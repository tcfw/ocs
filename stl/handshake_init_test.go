package stl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMashalInitHello(t *testing.T) {
	ih := &InitHello{
		Version: 1,
		Epoch:   1234567890,
		Random:  [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
		Suites: []Suite{
			{ECDHE_x25519, AES256gcm},
			{ECDHE_x25519, Chacha20_poly1305},
		},
		Key:          []byte{1, 2, 3, 4},
		HostnameType: HostnameType_DNS,
		Hostname:     []byte("example.com"),
		Extensions: []Extension{
			{
				ExtType: ExtensionType_HostnameId,
				Data:    []byte{1, 2, 3, 4, 5, 6},
			},
			{
				ExtType: ExtensionType_Certificate,
				Data:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
			},
		},
	}

	ihb, err := ih.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		0x01,                   //version
		0x49, 0x96, 0x02, 0xd2, //epoch
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, //random
		0x02,       //suite count
		0x01, 0x02, //suite 1
		0x01, 0x03, //suite 2
		0x00, 0x04, //key len
		0x01, 0x02, 0x03, 0x04, //key
		0x02,       //hostname type
		0x00, 0x0b, //hostname len
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, //hostname
		0x00, 0x02, //extension count
		0x06,       //extension 1 type
		0x00, 0x06, //extension 1 len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, //extension 1 data
		0x01,       //extension 2 type
		0x00, 0x0a, //extension 2 len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, //extension 2 data
	}

	assert.Equal(t, expected, ihb)
}

func TestUnmashalInitHello(t *testing.T) {
	raw := []byte{
		0x01,                   //version
		0x49, 0x96, 0x02, 0xd2, //epoch
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, //random
		0x02,       //suite count
		0x01, 0x02, //suite 1
		0x01, 0x03, //suite 2
		0x00, 0x04, //key len
		0x01, 0x02, 0x03, 0x04, //key
		0x02,       //hostname type
		0x00, 0x0b, //hostname len
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, //hostname
		0x00, 0x02, //extension count
		0x06,       //extension 1 type
		0x00, 0x06, //extension 1 len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, //extension 1 data
		0x01,       //extension 2 type
		0x00, 0x0a, //extension 2 len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, //extension 2 data
	}

	expected := &InitHello{
		Version: 1,
		Epoch:   1234567890,
		Random:  [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
		Suites: []Suite{
			{ECDHE_x25519, AES256gcm},
			{ECDHE_x25519, Chacha20_poly1305},
		},
		Key:          []byte{1, 2, 3, 4},
		HostnameType: HostnameType_DNS,
		Hostname:     []byte("example.com"),
		Extensions: []Extension{
			{
				ExtType: ExtensionType_HostnameId,
				Data:    []byte{1, 2, 3, 4, 5, 6},
			},
			{
				ExtType: ExtensionType_Certificate,
				Data:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
			},
		},
	}

	ih := &InitHello{}

	err := ih.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, ih)
}

func TestUnmarshalRecover(t *testing.T) {
	raw := []byte{
		0x01,                   //version
		0x49, 0x96, 0x02, 0xd2, //epoch
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, //random
		0xFF, //suite count
	}

	ih := &InitHello{}

	err := ih.Unmarshal(raw)
	assert.Error(t, err)
	assert.EqualError(t, err, "unmarshal invalid")
}

func TestMakeInitHello(t *testing.T) {
	config := defaultConfig()
	config.Hostname = "example.com"

	c := &Conn{
		config: config,
	}
	ih, params, err := c.makeInitHandshake()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, uint8(1), ih.Version)
	assert.Equal(t, params.pub, ih.Key)
	assert.NotEmpty(t, ih.Epoch)
	assert.Equal(t, []byte(config.Hostname), ih.Hostname)
}
