package stl

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

type InitHello struct {
	Version      byte
	Epoch        uint32
	Random       [32]byte
	Suites       []Suite
	Key          []byte
	HostnameType HostnameType
	Hostname     []byte
	Extensions   []Extension
}

func (ch *InitHello) Unmarshal(d []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unmarshal invalid")
		}
	}()

	ch.Version = d[0]
	ch.Epoch = binary.BigEndian.Uint32(d[1:])
	copy(ch.Random[:], d[5:])

	offset := 38
	ch.Suites = make([]Suite, 0, int(d[37]))
	for i := 0; i < cap(ch.Suites); i++ {
		suite := Suite{
			Handshake:   HandshakeSuite(d[offset+(i*2)]),
			Application: ApplicationSuite(d[offset+1+(i*2)]),
		}
		ch.Suites = append(ch.Suites, suite)
	}

	offset += 2 * len(ch.Suites)
	keyLen := binary.BigEndian.Uint16(d[offset:])
	offset += 2
	ch.Key = d[offset : offset+int(keyLen)]

	offset += int(keyLen)

	ch.HostnameType = HostnameType(d[offset])

	offset += 1
	hostnameLen := binary.BigEndian.Uint16(d[offset:])
	offset += 2
	ch.Hostname = d[offset : offset+int(hostnameLen)]
	offset += int(hostnameLen)

	extCount := int(binary.BigEndian.Uint16(d[offset:]))
	offset += 2
	ch.Extensions = []Extension{}
	for i := 0; i < extCount; i++ {
		ext := Extension{}
		if err := ext.Unmarshal(d[offset:]); err != nil {
			return err
		}
		ch.Extensions = append(ch.Extensions, ext)
		offset += 3 + len(ext.Data)
	}

	return nil
}

func (ch *InitHello) Marshal() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 100))

	buf.WriteByte(ch.Version)
	binary.Write(buf, binary.BigEndian, ch.Epoch)
	buf.Write(ch.Random[:])

	buf.WriteByte(uint8(len(ch.Suites)))
	for _, suite := range ch.Suites {
		buf.WriteByte(byte(suite.Handshake))
		buf.WriteByte(byte(suite.Application))
	}

	binary.Write(buf, binary.BigEndian, uint16(len(ch.Key)))
	buf.Write(ch.Key)

	buf.WriteByte(byte(ch.HostnameType))
	binary.Write(buf, binary.BigEndian, uint16(len(ch.Hostname)))
	buf.Write(ch.Hostname)

	binary.Write(buf, binary.BigEndian, uint16(len(ch.Extensions)))

	for _, ext := range ch.Extensions {
		extBytes, err := ext.Marshal()
		if err != nil {
			return nil, err
		}

		buf.Write(extBytes)
	}

	return buf.Bytes(), nil
}

type InitHelloState struct {
	c                        *Conn
	ctx                      context.Context
	initial                  *InitHello
	response                 *ResponseHello
	params                   *handshakeParams
	requiredInfo             []Extension
	peerCertificates         []*Certificate
	deferedCertificateVerify bool
	handshakeCipher          cipher.AEAD
	masterSecret             []byte
	nextProto                string
}

func (c *Conn) makeInitHandshake() (*InitHello, *handshakeParams, error) {
	ih := &InitHello{
		Version: 1,
		Epoch:   uint32(c.config.time().Unix()),
	}

	_, err := c.config.rand().Read(ih.Random[:])
	if err != nil {
		return nil, nil, err
	}

	params, err := curveParams(c.config, c.config.PreferredCurve)
	if err != nil {
		return nil, nil, err
	}

	if hasAESGCMHardwareSupport {
		ih.Suites = []Suite{
			{params.curve, AES256gcm},
			{params.curve, Chacha20_poly1305},
		}
	} else {
		ih.Suites = []Suite{
			{params.curve, Chacha20_poly1305},
			{params.curve, AES256gcm},
		}
	}

	ih.Key = []byte(params.pub)

	switch c.config.HostnameMode {
	case HostnameType_DNS, HostnameType_IP:
		ih.Hostname = []byte(c.config.Hostname)
	case HostnameType_OnRequest:
		//keep it blank, responder will ask during handshake
	case HostnameType_PSK:
		//todo
	case HostnameType_unknown:
		fallthrough
	default:
		return nil, nil, fmt.Errorf("unknown hostname mode")
	}

	if c.config.NextProto != "" {
		ih.Extensions = append(ih.Extensions, Extension{
			ExtType: ExtensionType_NextProto,
			Data:    []byte(c.config.NextProto),
		})
	}

	return ih, params, nil
}

func (c *Conn) initHandshake(ctx context.Context) error {
	if c.config == nil {
		c.config = defaultConfig()
	}

	hello, params, err := c.makeInitHandshake()
	if err != nil {
		return err
	}

	helloBytes, _ := hello.Marshal()
	if _, err := c.writeFrame(FrameType_InitHello, helloBytes); err != nil {
		return err
	}

	atomic.StoreUint32(&c.state, connState_wait_handshake)

	hs := &InitHelloState{
		c:       c,
		ctx:     ctx,
		initial: hello,
		params:  params,
	}

	return hs.handshake()
}

func (hs *InitHelloState) handshake() error {
	if err := hs.readResponseFrame(); err != nil {
		return err
	}

	if err := hs.setCiphers(); err != nil {
		return err
	}

	if err := hs.processResponse(); err != nil {
		return err
	}

	if err := hs.sendExtraInfo(); err != nil {
		return err
	}

	if len(hs.requiredInfo) > 0 {
		if err := hs.processMoreInfo(); err != nil {
			return err
		}
	}

	if err := hs.sendFinish(); err != nil {
		return err
	}

	msg, err := hs.c.readHandshake()
	if err != nil {
		return err
	}

	if _, ok := msg.(*FinishFrame); !ok {
		hs.c.sendError(ErrorCode_UnexpectedFrame)
		return errors.New("unexpected frame, was expecting finish")
	}

	atomic.StoreUint32(&hs.c.state, connState_connected)

	return nil
}

func (hs *InitHelloState) readResponseFrame() error {
	c := hs.c

	for c.hand.Len() < frameHeaderLength {
		if err := c.readFrame(); err != nil {
			return err
		}
	}

	hdr := c.hand.Bytes()[:frameHeaderLength]
	n := int(binary.BigEndian.Uint16(hdr[1:]))
	if n > maxHandshakeSize {
		c.sendError(ErrorCode_BadParameters)
		return c.in.setError(fmt.Errorf("handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshakeSize))
	}

	for c.hand.Len() < frameHeaderLength+n {
		if err := c.readFrame(); err != nil {
			return err
		}
	}

	data := c.hand.Next(frameHeaderLength + n)

	hs.response = &ResponseHello{}
	if err := hs.response.UnmarshalPartial(data[frameHeaderLength:]); err != nil {
		return err
	}

	var err error
	hs.masterSecret, err = ecdh(hs.c.config, hs.response.Suite.Handshake, hs.response.Key, hs.params)
	if err != nil {
		return err
	}

	hc, err := makeCipher(hs.response.Suite.Application, hs.masterSecret, handshakeLabel)
	if err != nil {
		return err
	}
	hs.handshakeCipher = hc

	err = hs.response.UnmarshalEncrypted(data[frameHeaderLength:], hs.handshakeCipher)
	if err != nil {
		return err
	}

	return nil
}

func (hs *InitHelloState) processResponse() error {
	if hs.response.Version != hs.initial.Version {
		hs.c.sendError(ErrorCode_BadParameters)
		return errors.New("stl: responder responded with mismatching version")
	}
	hs.c.version = hs.response.Version

	if hs.c.config.AllowedTimeDiff != 0 {
		iTime := time.Unix(int64(hs.response.Epoch), 0)
		if hs.c.config.time().Sub(iTime) >= hs.c.config.AllowedTimeDiff {
			hs.c.sendError(ErrorCode_BadParameters)
			return errors.New("stl: client hello epoch too old")
		}
	}

	for _, ext := range hs.response.Extensions {
		if isInfoRequest(ext.ExtType) {
			hs.requiredInfo = append(hs.requiredInfo, ext)
			continue
		}

		if ext.ExtType == ExtensionType_Certificate {
			cert := &Certificate{}
			err := cert.Unmarshal(ext.Data)
			if err != nil {
				hs.c.sendError(ErrorCode_BadCertificate)
				return errors.New("stl: responder sent bad certificate extension")
			}
			hs.peerCertificates = append(hs.peerCertificates, cert)
		}

		if ext.ExtType == ExtensionType_NextProto {
			hs.nextProto = string(ext.Data)
		}
	}

	if err := hs.verifyResponseCertificates(); err != nil {
		return err
	}

	if hs.nextProto != "" && hs.c.config.NextProto != hs.nextProto {
		return errors.New("stl: mismatch next protocol")
	}
	hs.c.handshakeNextProto = hs.nextProto

	return nil
}

func (hs *InitHelloState) verifyResponseCertificates() error {
	if !hs.deferedCertificateVerify && hasInfoRequest(ExtensionType_NameRequest, hs.requiredInfo) {
		hs.deferedCertificateVerify = true
		return nil
	}

	var signed *Certificate
	var additional []*Certificate

	for _, cert := range hs.peerCertificates {
		if cert.Verify != nil && signed == nil {
			signed = cert
		} else {
			additional = append(additional, cert)
		}
	}

	if signed == nil {
		hs.c.sendError(ErrorCode_BadParameters)
		return errors.New("stl: responder sent no certificate signatures")
	}

	vd := append(hs.initial.Random[:], hs.response.Random[:]...)
	if err := verifyCertSignature(signed, vd); err != nil {
		hs.c.sendError(ErrorCode_BadCertificate)
		return errors.New("stl: responder sent bad certificate signature")
	}

	if err := verifyHostname(signed, hs.c.config.Hostname); err != nil {
		hs.c.sendError(ErrorCode_BadCertificate)
		return errors.New("stl: certificate hostname mismatch")
	}

	if !hs.c.config.SkipCertificateVerification {
		//ensure all certs are same as signed cert
		for _, a := range additional {
			if a.CertificateType != signed.CertificateType {
				hs.c.sendError(ErrorCode_BadCertificate)
				return errors.New("stl: inconsistent certificate types")
			}
		}

		var err error
		if signed.CertificateType == CertificateType_X509 {
			err = verifyX509Chain(hs.c.config, signed, additional)
		} else {
			err = verifyCKIChain(hs.c.config, signed, additional)
		}

		if err != nil {
			return err
		}
	}

	hs.c.peerCertificates = hs.peerCertificates

	return nil
}

func (hs *InitHelloState) processMoreInfo() error {
	msg, err := hs.c.readHandshake()
	if err != nil {
		return err
	}

	info, ok := msg.(*InfoFrame)
	if !ok {
		return hs.c.in.setError(hs.c.sendError(ErrorCode_UnexpectedFrame))
	}

	for _, ext := range info.Extensions {
		if isInfoRequest(ext.ExtType) {
			return hs.c.in.setError(hs.c.sendError(ErrorCode_BadParameters))
		}

		if ext.ExtType == ExtensionType_Certificate {
			cert := &Certificate{}
			err := cert.Unmarshal(ext.Data)
			if err != nil {
				hs.c.sendError(ErrorCode_BadCertificate)
				return errors.New("stl: responder sent bad certificate extension")
			}
			hs.peerCertificates = append(hs.peerCertificates, cert)
		}
	}

	if hs.deferedCertificateVerify {
		if err := hs.verifyResponseCertificates(); err != nil {
			return err
		}
	}
	return nil
}

func (hs *InitHelloState) setCiphers() error {
	inc, err := makeCipher(hs.response.Suite.Application, hs.masterSecret, trafficLabelInit)
	if err != nil {
		return err
	}

	outc, err := makeCipher(hs.response.Suite.Application, hs.masterSecret, trafficLabelResponse)
	if err != nil {
		return err
	}

	hs.c.in.cipher = inc
	hs.c.out.cipher = outc

	hs.c.suite = hs.response.Suite

	return nil
}

func (hs *InitHelloState) sendExtraInfo() error {
	if len(hs.requiredInfo) == 0 {
		return nil
	}

	info := []Extension{}

	for _, req := range hs.requiredInfo {
		switch req.ExtType {
		case ExtensionType_NameRequest:
			//TODO
			ext := Extension{
				ExtType: ExtensionType_Name,
				Data:    []byte(hs.c.config.Hostname),
			}
			info = append(info, ext)
		case ExtensionType_CertificateRequest:
			if len(hs.c.config.Certificates) == 0 {
				return errors.New("stl: responder requested a certificate but no certificates set")
			}

			//TODO
		}
	}

	if len(info) > 0 {
		infoFrame := &InfoFrame{
			Extensions: info,
		}

		b, err := infoFrame.Marshal()
		if err != nil {
			return err
		}

		_, err = hs.c.writeFrame(FrameType_Info, b)
		if err != nil {
			return err
		}
	}

	return nil
}

func (hs *InitHelloState) sendFinish() error {
	_, err := hs.c.writeFrame(FrameType_Finish, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err != nil {
		return err
	}

	atomic.StoreUint32(&hs.c.state, connState_wait_finish)

	return nil
}

func hasInfoRequest(t ExtensionType, e []Extension) bool {
	for _, i := range e {
		if i.ExtType == t {
			return true
		}
	}

	return false
}
