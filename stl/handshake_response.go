package stl

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

type ResponseHello struct {
	Version    byte
	Suite      Suite
	Key        []byte
	Epoch      uint32
	Random     [32]byte
	Extensions []Extension
}

func (ch *ResponseHello) Unmarshal(d []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unmarshal invalid")
		}
	}()

	ch.Version = d[0]
	ch.Suite.Handshake = HandshakeSuite(d[1])
	ch.Suite.Application = ApplicationSuite(d[2])

	keyLen := binary.BigEndian.Uint16(d[3:])
	ch.Key = d[5 : 5+keyLen]

	offset := int(5 + keyLen)
	ch.Epoch = binary.BigEndian.Uint32(d[offset:])
	offset += 4
	copy(ch.Random[:], d[offset:])
	offset += 32

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

func (ch *ResponseHello) UnmarshalPartial(d []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unmarshal invalid")
		}
	}()

	ch.Version = d[0]
	ch.Suite.Handshake = HandshakeSuite(d[1])
	ch.Suite.Application = ApplicationSuite(d[2])

	keyLen := binary.BigEndian.Uint16(d[3:])
	ch.Key = d[5 : 5+keyLen]

	return nil
}

func (ch *ResponseHello) UnmarshalEncrypted(d []byte, c cipher.AEAD) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unmarshal invalid")
		}
	}()

	ch.Version = d[0]
	ch.Suite.Handshake = HandshakeSuite(d[1])
	ch.Suite.Application = ApplicationSuite(d[2])

	keyLen := binary.BigEndian.Uint16(d[3:])
	ch.Key = d[5 : 5+keyLen]

	offset := int(5 + keyLen)

	nonce := d[offset : offset+c.NonceSize()]
	cipherText := d[offset+c.NonceSize():]
	add := d[:offset]

	plaintext, err := c.Open(cipherText[:0], nonce, cipherText, add)
	if err != nil {
		return err
	}

	offset = 0

	ch.Epoch = binary.BigEndian.Uint32(plaintext[offset:])
	offset += 4
	copy(ch.Random[:], plaintext[offset:])
	offset += 32

	extCount := int(binary.BigEndian.Uint16(plaintext[offset:]))
	offset += 2
	ch.Extensions = []Extension{}
	for i := 0; i < extCount; i++ {
		ext := Extension{}
		if err := ext.Unmarshal(plaintext[offset:]); err != nil {
			return err
		}
		ch.Extensions = append(ch.Extensions, ext)
		offset += 3 + len(ext.Data)
	}

	return nil
}

func (ch *ResponseHello) Marshal() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 100))

	buf.WriteByte(ch.Version)

	buf.WriteByte(byte(ch.Suite.Handshake))
	buf.WriteByte(byte(ch.Suite.Application))

	binary.Write(buf, binary.BigEndian, uint16(len(ch.Key)))
	buf.Write(ch.Key)

	binary.Write(buf, binary.BigEndian, ch.Epoch)

	buf.Write(ch.Random[:])

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

func (ch *ResponseHello) MarshalEncrypted(c cipher.AEAD, rand io.Reader) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 100))

	buf.WriteByte(ch.Version)

	buf.WriteByte(byte(ch.Suite.Handshake))
	buf.WriteByte(byte(ch.Suite.Application))

	binary.Write(buf, binary.BigEndian, uint16(len(ch.Key)))
	buf.Write(ch.Key)

	ptBuf := bytes.NewBuffer(make([]byte, 0, 100))

	binary.Write(ptBuf, binary.BigEndian, ch.Epoch)

	ptBuf.Write(ch.Random[:])

	binary.Write(ptBuf, binary.BigEndian, uint16(len(ch.Extensions)))

	for _, ext := range ch.Extensions {
		extBytes, err := ext.Marshal()
		if err != nil {
			return nil, err
		}
		ptBuf.Write(extBytes)
	}

	nonce := make([]byte, c.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ptBytes := ptBuf.Bytes()

	ptBytes = c.Seal(ptBytes[:0], nonce, ptBytes, buf.Bytes())

	buf.Write(nonce)
	buf.Write(ptBytes)

	return buf.Bytes(), nil
}

type ResponseHelloState struct {
	c                *Conn
	ctx              context.Context
	initial          *InitHello
	response         ResponseHello
	params           *handshakeParams
	peerCertificates []*Certificate
	hostname         []byte
	requiredInfo     []Extension
	moreInfo         *InfoFrame
	certificate      *CertificatePair
	validatedAuth    bool
	handshakeCipher  cipher.AEAD
	masterSecret     []byte
}

func (c *Conn) respondHandshake(ctx context.Context) error {
	atomic.StoreUint32(&c.state, connState_wait_handshake)

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	ih, ok := msg.(*InitHello)
	if !ok {
		return c.in.setError(c.sendError(ErrorCode_UnexpectedFrame))
	}

	state := &ResponseHelloState{
		c:       c,
		ctx:     ctx,
		initial: ih,
	}

	return state.handshake()
}

func (hs *ResponseHelloState) handshake() error {
	if err := hs.validateHello(); err != nil {
		return err
	}

	if err := hs.pickCertificate(); err != nil {
		return err
	}

	if err := hs.generateParams(); err != nil {
		return err
	}

	hs.c.buffering = true

	if err := hs.sendResponse(); err != nil {
		return err
	}

	if err := hs.setCiphers(); err != nil {
		return err
	}

	if len(hs.requiredInfo) > 0 {
		_, err := hs.c.flush()
		if err != nil {
			return err
		}

		atomic.StoreUint32(&hs.c.state, connState_wait_info)

		msg, err := hs.c.readHandshake()
		if err != nil {
			return err
		}

		info, ok := msg.(*InfoFrame)
		if !ok {
			hs.c.sendError(ErrorCode_UnexpectedFrame)
			return errors.New("was expecting an info frame")
		}
		hs.moreInfo = info
		if err := hs.processInfo(); err != nil {
			return err
		}
	}

	if err := hs.sendFinish(); err != nil {
		return err
	}

	_, err := hs.c.flush()
	if err != nil {
		return err
	}

	atomic.StoreUint32(&hs.c.state, connState_wait_finish)

	msg, err := hs.c.readHandshake()
	if err != nil {
		return err
	}

	_, ok := msg.(*FinishFrame)
	if !ok {
		hs.c.sendError(ErrorCode_UnexpectedFrame)
		return errors.New("was expecting an finish frame")
	}

	atomic.StoreUint32(&hs.c.state, connState_connected)

	return nil
}

func (hs *ResponseHelloState) validateHello() error {
	i := hs.initial

	if i.Version != 1 {
		hs.c.sendError(ErrorCode_BadParameters)
		return errors.New("stl: client used invalid version field")
	}

	hs.c.version = 1
	hs.response.Version = 1

	if len(i.Suites) == 0 {
		hs.c.sendError(ErrorCode_BadParameters)
		return errors.New("stl: client sent no available suites")
	}

	if hs.c.config.ClientAuth {
		for _, ext := range i.Extensions {
			if ext.ExtType == ExtensionType_Certificate {
				cert := &Certificate{}
				err := cert.Unmarshal(ext.Data)
				if err != nil {
					return err
				}

				hs.peerCertificates = append(hs.peerCertificates, cert)
				hs.c.peerCertificates = hs.peerCertificates
			}
		}

		if len(hs.peerCertificates) == 0 {
			hs.requiredInfo = append(hs.requiredInfo, Extension{ExtType: ExtensionType_CertificateRequest})
		} else {
			if err := hs.validateAuthCertificates(); err != nil {
				return err
			}
		}
	}

	if hs.c.config.AllowedTimeDiff != 0 {
		iTime := time.Unix(int64(i.Epoch), 0)
		if hs.c.config.time().Sub(iTime) >= hs.c.config.AllowedTimeDiff {
			hs.c.sendError(ErrorCode_BadParameters)
			return errors.New("stl: client hello epoch too old")
		}
	}

	return nil
}

func (hs *ResponseHelloState) validateAuthCertificates() error {
	// cert, err := cki.ParseCertificate(c.Certificate)
	// if err != nil {
	// 	hs.c.sendError(ErrorCode_BadCertificate)
	// 	return nil, fmt.Errorf("stl: client sent bad certificate: %s", err)
	// }

	// if err := cert.Verify(hs.c.config.ClientCAPool); err != nil {
	// 	hs.c.sendError(ErrorCode_BadCertificate)
	// 	return nil, fmt.Errorf("stl: client failed certificate verification: %s", err)
	// }

	// pk, err := cert.GetPublicKey()
	// if err != nil {
	// 	hs.c.sendError(ErrorCode_BadCertificate)
	// 	return nil, fmt.Errorf("stl: client sent bad certificate public key: %s", err)
	// }

	// if !pk.Verify(hs.initial.Random[:], c.Verify) {
	// 	hs.c.sendError(ErrorCode_BadCertificate)
	// 	return nil, errors.New("stl: client sent bad certificate verification")
	// }

	//TODO

	hs.validatedAuth = true

	return nil
}

func (hs *ResponseHelloState) pickCertificate() error {
	if hs.hostname == nil && hs.initial.Hostname != nil {
		hs.hostname = hs.initial.Hostname
	}

	if (hs.hostname == nil || hs.initial.HostnameType == HostnameType_OnRequest) && len(hs.c.config.Certificates) != 1 {
		hs.requiredInfo = append(hs.requiredInfo, Extension{ExtType: ExtensionType_NameRequest})
		return nil
	}

	cert, err := hs.c.config.getCertificate(hs)
	if err != nil {
		return err
	}
	hs.certificate = cert

	return nil
}

func (hs *ResponseHelloState) generateParams() error {
	suite, err := mutualSuite(hs.c.config, hs.initial.Suites)
	if err != nil {
		hs.c.sendError(ErrorCode_BadParameters)
		return errors.New("stl: unable to match against client suite")
	}

	hs.response.Suite = suite

	hs.params, err = curveParams(hs.c.config, hs.response.Suite.Handshake)
	if err != nil {
		return err
	}
	hs.response.Key = hs.params.pub

	hs.masterSecret, err = ecdh(hs.c.config, hs.response.Suite.Handshake, hs.initial.Key, hs.params)
	if err != nil {
		return err
	}

	hs.c.suite = suite

	return nil
}

func (hs *ResponseHelloState) setCiphers() (err error) {
	inc, err := makeCipher(hs.response.Suite.Application, hs.masterSecret, trafficLabelResponse)
	if err != nil {
		return err
	}

	outc, err := makeCipher(hs.response.Suite.Application, hs.masterSecret, trafficLabelInit)
	if err != nil {
		return err
	}

	hs.c.in.cipher = inc
	hs.c.out.cipher = outc

	return nil
}

func (hs *ResponseHelloState) sendResponse() error {
	_, err := hs.c.config.rand().Read(hs.response.Random[:])
	if err != nil {
		return err
	}

	hs.response.Epoch = uint32(hs.c.config.time().Unix())

	hs.response.Extensions = append(hs.response.Extensions, hs.requiredInfo...)

	if hs.certificate != nil {
		vd := append(hs.initial.Random[:], hs.response.Random[:]...)
		certExt, err := makeCertificateExtensions(*hs.certificate, vd, hs.c.config.rand())
		if err != nil {
			return err
		}

		hs.response.Extensions = append(hs.response.Extensions, certExt...)
	}

	hc, err := makeCipher(hs.response.Suite.Application, hs.masterSecret, handshakeLabel)
	if err != nil {
		return err
	}
	hs.handshakeCipher = hc

	frameData, err := hs.response.MarshalEncrypted(hc, hs.c.config.rand())
	if err != nil {
		return err
	}

	_, err = hs.c.writeFrame(FrameType_ResponseHello, frameData)
	return err
}

func (hs *ResponseHelloState) processInfo() error {
	info := []Extension{}

	for _, want := range hs.requiredInfo {
		var found *Extension
		for _, have := range hs.moreInfo.Extensions {
			if matchesRequest(want.ExtType, have.ExtType) {
				found = &have
			}
		}

		if found == nil {
			hs.c.sendError(ErrorCode_BadParameters)
			return errors.New("stl: missing requested info")
		}

		if found.ExtType == ExtensionType_Certificate {
			cert := &Certificate{}
			if err := cert.Unmarshal(found.Data); err != nil {
				return err
			}
			hs.peerCertificates = append(hs.peerCertificates, cert)
			hs.c.peerCertificates = hs.peerCertificates
		}

		if found.ExtType == ExtensionType_Name && hs.certificate == nil {
			//provide certificate if not already
			hs.hostname = found.Data
			if err := hs.pickCertificate(); err != nil {
				return err
			}

			certExt, err := makeCertificateExtensions(*hs.certificate, hs.initial.Random[:], hs.c.config.rand())
			if err != nil {
				return err
			}

			info = append(info, certExt...)
		}
	}

	if hs.c.config.ClientAuth && !hs.validatedAuth {
		if err := hs.validateAuthCertificates(); err != nil {
			return err
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
		return err
	}

	return nil
}

func (hs *ResponseHelloState) sendFinish() error {
	_, err := hs.c.writeFrame(FrameType_Finish, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err != nil {
		return err
	}

	atomic.StoreUint32(&hs.c.state, connState_wait_finish)

	return nil
}
