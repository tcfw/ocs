package stl

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestMarshalResponseHello(t *testing.T) {
	rh := &ResponseHello{
		Version: 1,
		Suite: Suite{
			ECDHE_x25519, AES256gcm,
		},
		Key:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
		Epoch:  1234567890,
		Random: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
		Extensions: []Extension{
			{
				ExtType: ExtensionType_CertificateRequest,
			},
			{
				ExtType: ExtensionType_NameRequest,
			},
		},
	}

	rhb, err := rh.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		0x01,       //version
		0x01, 0x02, //suite
		0x00, 0x0a, //key len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, //key
		0x49, 0x96, 0x02, 0xd2, //epoch
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, //random
		0x00, 0x02, //extension count
		0x02,       //extension 1 type
		0x00, 0x00, //extension 1 len
		0x04,       //extension 2 type
		0x00, 0x00, //extension 2 len
	}

	assert.Equal(t, rhb, expected)
}

func TestUnmarshalResponseHello(t *testing.T) {
	raw := []byte{
		0x01,       //version
		0x01, 0x02, //suite
		0x00, 0x0a, //key len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, //key
		0x49, 0x96, 0x02, 0xd2, //epoch
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, //random
		0x00, 0x02, //extension count
		0x02,       //extension 1 type
		0x00, 0x00, //extension 1 len
		0x04,       //extension 2 type
		0x00, 0x00, //extension 2 len
	}

	expected := &ResponseHello{
		Version: 1,
		Suite: Suite{
			ECDHE_x25519, AES256gcm,
		},
		Key:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
		Epoch:  1234567890,
		Random: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
		Extensions: []Extension{
			{
				ExtType: ExtensionType_CertificateRequest,
				Data:    []byte{},
			},
			{
				ExtType: ExtensionType_NameRequest,
				Data:    []byte{},
			},
		},
	}

	rh := &ResponseHello{}

	err := rh.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, rh)
}

func TestUnmarshalResponseHelloInvalid(t *testing.T) {
	raw := []byte{
		0x01,       //version
		0x01, 0x02, //suite
		0xFF, 0xFF, //key len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, //key
	}

	rh := &ResponseHello{}

	err := rh.Unmarshal(raw)
	assert.EqualError(t, err, "unmarshal invalid")
}

func TestMarshalEncryptedResponseHello(t *testing.T) {
	rh := &ResponseHello{
		Version: 1,
		Suite: Suite{
			ECDHE_x25519, AES256gcm,
		},
		Key:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
		Epoch:  1234567890,
		Random: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2},
		Extensions: []Extension{
			{
				ExtType: ExtensionType_CertificateRequest,
				Data:    []byte{},
			},
			{
				ExtType: ExtensionType_NameRequest,
				Data:    []byte{},
			},
		},
	}

	c, err := chacha20poly1305.New([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}

	erhb, err := rh.MarshalEncrypted(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rhb := &ResponseHello{}

	err = rhb.UnmarshalEncrypted(erhb, c)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, rh, rhb)
}

func TestResponseBasicParams(t *testing.T) {
	certPem, privPEM := generateTestCert(t, "example.com")

	cp, err := CKIKeyPair(certPem, privPEM)
	if err != nil {
		t.Fatal(err)
	}

	config := testDefaultConfig()
	config.Certificates = []CertificatePair{cp}
	config.NextProto = "h2"

	cState, scState, err := testHandshake(t, config, config)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, cState.HandshakeComplete)
	assert.True(t, scState.HandshakeComplete)

	assert.Equal(t, cState.Version, scState.Version)
	assert.Equal(t, cState.Suite, scState.Suite)
	assert.Equal(t, cState.NextProto, scState.NextProto)
	assert.Equal(t, config.NextProto, cState.NextProto)
}
