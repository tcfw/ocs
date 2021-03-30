package eff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Magic = "OCSEFF"
)

//ParseEFF reads a EFF file and returns the header. The cipher text is not read
func ParseEFF(r io.Reader) (*Header, error) {
	version := make([]byte, 1)
	magic := make([]byte, len(Magic))
	var headerSize uint32

	_, err := r.Read(version)
	if err != nil {
		return nil, err
	}
	if bytes.Compare(version, []byte{1}) != 0 {
		return nil, fmt.Errorf("invalid version")
	}

	_, err = r.Read(magic)
	if err != nil {
		return nil, err
	}
	if bytes.Compare(magic, []byte(Magic)) != 0 {
		return nil, fmt.Errorf("invalid magic")
	}

	err = binary.Read(r, binary.LittleEndian, &headerSize)
	if err != nil {
		return nil, err
	}

	if headerSize > 10<<20 {
		return nil, fmt.Errorf("header too large")
	}

	headerData := make([]byte, headerSize)

	n, err := r.Read(headerData)
	if uint32(n) != headerSize || err != nil {
		return nil, fmt.Errorf("failed to read header")
	}

	return ParseHeader(headerData)
}

//MarshalEFF writes a EFF file given a Header and cipher text
func MarshalEFF(h *Header, ct []byte, w io.Writer) error {
	hBytes, err := h.Bytes()
	if err != nil {
		return err
	}

	//Version
	w.Write([]byte{1})

	//Magic
	w.Write([]byte(Magic))

	//Header size
	binary.Write(w, binary.LittleEndian, uint32(len(hBytes)))

	//Header
	w.Write(hBytes)

	//Rest
	w.Write(ct)

	return nil
}
