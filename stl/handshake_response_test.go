package stl

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open local listener: %v", err)
		os.Exit(1)
	}
	localListener.ch = make(chan net.Conn)
	localListener.addr = l.Addr()
	defer l.Close()
	go localServer(l)

	config := defaultConfig()
	config.Time = func() time.Time { return time.Unix(0, 0) }
	config.Rand = zeroSource{}
	config.Hostname = "example.com"
	config.SkipCertificateVerification = true
	config.NextProto = "h2"

	certPem, privPEM := generateTestCert(t, "example.com")

	cp, err := CKIKeyPair(certPem, privPEM)
	if err != nil {
		t.Fatal(err)
	}

	config.Certificates = []CertificatePair{cp}

	r, w := localPipe(t) //net.Pipe()

	c := &Conn{
		conn:   w,
		config: config,
	}

	sc := &Conn{
		conn:   r,
		config: config,
	}

	hello, initParams, err := c.makeInitHandshake()
	if err != nil {
		t.Fatal(err)
	}

	errs := make(chan error)

	ih := &InitHelloState{
		c:       sc,
		ctx:     context.Background(),
		initial: hello,
		params:  initParams,
	}

	rh := &ResponseHelloState{
		c:       c,
		ctx:     context.Background(),
		initial: hello,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		err := ih.handshake()
		if err != nil {
			errs <- fmt.Errorf("err on inter: %s", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err = rh.handshake()
		if err != nil {
			errs <- fmt.Errorf("err on responder: %s", err)
		}
	}()

	go func() {
		wg.Wait()
		close(errs)
	}()

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	cState := c.State()
	scState := sc.State()

	assert.True(t, cState.HandshakeComplete)
	assert.True(t, scState.HandshakeComplete)

	assert.Equal(t, cState.Version, scState.Version)
	assert.Equal(t, cState.Suite, scState.Suite)
	assert.Equal(t, cState.NextProto, scState.NextProto)
	assert.Equal(t, config.NextProto, cState.NextProto)
}

// func testHandshake(t *testing.T, clientConfig, serverConfig *Config) (clientState, serverState *State, err error) {

// 	return
// }
