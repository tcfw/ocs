package stl

import (
	"bytes"
	"encoding/binary"
	"io"
)

type Extension struct {
	ExtType ExtensionType
	Data    []byte
}

func (ext *Extension) Unmarshal(d []byte) error {
	if len(d) < 3 {
		return io.EOF
	}

	ext.ExtType = ExtensionType(d[0])
	length := binary.BigEndian.Uint16(d[1:])
	ext.Data = d[3 : length+3]

	return nil
}

func (ext *Extension) Marshal() ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	buf.WriteByte(byte(ext.ExtType))
	binary.Write(buf, binary.BigEndian, uint16(len(ext.Data)))
	buf.Write(ext.Data)

	return buf.Bytes(), nil
}

type ExtensionType byte

const (
	ExtensionType_Certificate ExtensionType = iota + 1
	ExtensionType_CertificateRequest
	ExtensionType_Name
	ExtensionType_NameRequest
	ExtensionType_EarlyData
	ExtensionType_HostnameId
)

func matchesRequest(want, have ExtensionType) bool {
	switch want {
	case ExtensionType_CertificateRequest:
		return have == ExtensionType_Certificate
	case ExtensionType_NameRequest:
		return have == ExtensionType_Name
	default:
		return false
	}
}

func isInfoRequest(extType ExtensionType) bool {
	switch extType {
	case ExtensionType_CertificateRequest, ExtensionType_NameRequest:
		return true
	default:
		return false
	}
}

type Certificate struct {
	CertificateType CertificateType
	Length          uint16
	Certificate     []byte
	Verify          []byte
}

func (c *Certificate) Marshal() ([]byte, error) {
	return nil, nil

}

func (c *Certificate) Unmarshal(d []byte) error {
	return nil
}

type HostnameId struct {
	HostnameIdType HostnameIdType
	KeyIdLength    uint8
	KeyId          []byte
	Data           []byte
}

func (h *HostnameId) Marshal() ([]byte, error) {
	return nil, nil
}

type HostnameIdType uint8

const (
	HostnameIdType_UnknownType HostnameIdType = iota
	HostnameIdType_HMAC
	HostnameIdType_PSK
)
