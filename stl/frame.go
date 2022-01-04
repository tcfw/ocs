package stl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	frameHeaderLength = 1 + 2
	maxHandshakeSize  = 65536
)

var (
	ErrorInvalidFrameType = errors.New("unknown frame type")
)

type Frame struct {
	FrameType FrameType
	Length    uint16
	data      []byte
}

type FrameType uint8

const (
	FrameType_Invalid FrameType = iota
	FrameType_InitHello
	FrameType_ResponseHello
	FrameType_Info
	FrameType_Finish
	FrameType_Error
	FrameType_Data
)

func (f *Frame) ReadFrom(r io.Reader) (int64, error) {
	var n int
	header := make([]byte, frameHeaderLength)

	np, err := io.ReadAtLeast(r, header, len(header))
	if err != nil {
		return int64(n), err
	}
	n += np

	f.FrameType = FrameType(header[0])
	f.Length = binary.BigEndian.Uint16(header[1:])

	f.data = make([]byte, f.Length)
	np, err = io.ReadAtLeast(r, f.data, int(f.Length))
	if err != nil {
		return int64(n), err
	}
	n += np

	return int64(n), nil
}

func (f *Frame) MarshalBinary() ([]byte, error) {
	d := make([]byte, frameHeaderLength+len(f.data))

	d[0] = byte(f.FrameType)
	binary.BigEndian.PutUint16(d[1:], uint16(len(f.data)))
	copy(d[frameHeaderLength:], f.data)

	return d, nil
}

func (f *Frame) Data() (interface{}, error) {
	switch f.FrameType {
	case FrameType_InitHello:
		var ch InitHello
		err := ch.Unmarshal(f.data)
		return ch, err

	case FrameType_ResponseHello:
		var ch ResponseHello
		err := ch.Unmarshal(f.data)
		return ch, err

	case FrameType_Info:
		var ifr InfoFrame
		err := ifr.Unmarshal(f.data)
		return ifr, err

	case FrameType_Finish:
		return nil, nil

	case FrameType_Error:
		var errf ErrorFrame
		err := errf.Unmarshal(f.data)
		return errf, err

	case FrameType_Data:
		return f.data[:f.Length], nil
	default:
		return nil, ErrorInvalidFrameType
	}
}

type Marshaller interface {
	Marshal() ([]byte, error)
}

func (f *Frame) Marshal(i Marshaller) ([]byte, error) {
	switch v := i.(type) {
	case *InitHello:
		f.FrameType = FrameType_InitHello
	case *ResponseHello:
		f.FrameType = FrameType_ResponseHello
	case *InfoFrame:
		f.FrameType = FrameType_Info
	case *ErrorFrame:
		f.FrameType = FrameType_Error
	default:
		return nil, fmt.Errorf("unsupported frame type %T", v)
	}

	d, err := i.Marshal()
	if err != nil {
		return nil, err
	}

	f.data = d

	return f.MarshalBinary()

}
