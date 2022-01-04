package stl

import (
	"bytes"
	"encoding/binary"
	"io"
)

type HostnameType byte

const (
	HostnameType_unknown HostnameType = iota
	HostnameType_IP
	HostnameType_DNS
	HostnameType_PSK
	HostnameType_OnRequest
)

type HostnamePSK struct {
	Suite     ApplicationSuite
	CertID    []byte
	PublicKey []byte
	Data      []byte
}

type FinishFrame struct{}

func (ff *FinishFrame) Unmarshal(d []byte) error {
	return nil
}

func (ff *FinishFrame) Marshal() ([]byte, error) {
	return []byte{}, nil
}

type InfoFrame struct {
	ExtLength  uint16
	Extensions []Extension
}

func (ifr *InfoFrame) Unmarshal(d []byte) error {
	if len(d) < 2 {
		return io.EOF
	}

	ifr.ExtLength = binary.BigEndian.Uint16(d)
	ifr.Extensions = make([]Extension, ifr.ExtLength)

	var n = 2
	for i := 0; i < int(ifr.ExtLength); i++ {
		err := ifr.Extensions[i].Unmarshal(d[n:])
		if err != nil {
			return err
		}

		n += int(len(ifr.Extensions[i].Data)) + 2 + 1
	}

	return nil
}

func (ifr *InfoFrame) Marshal() ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(ifr.Extensions)))
	buf.Write(extLen)

	for _, ext := range ifr.Extensions {
		b, err := ext.Marshal()
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}

	return buf.Bytes(), nil
}
