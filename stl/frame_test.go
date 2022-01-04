package stl

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadFrom(t *testing.T) {
	data := []byte{
		byte(FrameType_Data), //Frame Type
		0x0, 0x02,            //Length
		0xFF, 0x01, //Data
	}

	var f Frame
	n, err := f.ReadFrom(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if int(n) != len(data) {
		t.Fatal("mismatching data length")
	}

	if f.FrameType != FrameType_Data {
		t.Fatal("unexpected frame type")
	}

	marshalled, err := f.Data()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, data[3:], marshalled)
}

func TestMarshalBinary(t *testing.T) {
	data := []byte{
		byte(FrameType_Data), //Frame Type
		0x0, 0x02,            //Length
		0xFF, 0x01, //Data
	}

	var f Frame
	if _, err := f.ReadFrom(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	d, _ := f.MarshalBinary()

	assert.Equal(t, data, d)
}
