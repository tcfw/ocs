package stl

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestSeal(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	payload := []byte("abc123")

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	hc := &halfConn{
		cipher: aead,
	}

	frame := make([]byte, frameHeaderLength) //simulate unallocated pool
	frame[0] = byte(FrameType_Info)

	frame, err = hc.encrypt(frame, payload, defaultConfig().rand())
	if err != nil {
		t.Fatal(err)
	}

	//ensure original frame type is encrypted
	assert.Equal(t, byte(FrameType_Data), frame[0])

	expectedFrameLen := len(payload) + 1 + frameHeaderLength + aead.NonceSize() + aead.Overhead()

	if len(frame) != expectedFrameLen {
		t.Fatalf("unexpected frame length, got %d expected %d", len(frame), expectedFrameLen)
	}

	if hc.seq != 1 {
		t.Fatal("seq did not increment")
	}

	t.Logf("data %+v", frame)
}

func TestOpen(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	payload := []byte("abc123")

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	hc := &halfConn{
		cipher: aead,
	}

	frame := make([]byte, frameHeaderLength) //simulate unallocated pool
	frame[0] = byte(FrameType_Finish)

	frame, err = hc.encrypt(frame, payload, defaultConfig().rand())
	if err != nil {
		t.Fatal(err)
	}

	//ensure original frame type is encrypted
	assert.Equal(t, byte(FrameType_Data), frame[0])

	plaintext, _, err := hc.decrypt(frame)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, payload) {
		t.Fatalf("unexpected byes, got %v expected %v", plaintext, payload)
	}

	//ensure original frame type is recovered
	assert.Equal(t, byte(FrameType_Finish), frame[0])
}

func TestSendError(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	r, w := net.Pipe()

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		buf.ReadFrom(&atLeastReader{r, frameHeaderLength + 1})
		wg.Done()
	}()

	c := &Conn{
		conn:   w,
		config: defaultConfig(),
	}

	err := c.sendError(ErrorCode_Closed)
	assert.Equal(t, err, &ErrorFrame{ErrorCode_Closed})

	errFrameReadBack := make([]byte, frameHeaderLength+1)

	wg.Wait()

	_, err = buf.Read(errFrameReadBack)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, []byte{byte(FrameType_Error), 0, 1, byte(ErrorCode_Closed)}, errFrameReadBack)

	go func() {
		r.Write(errFrameReadBack)
	}()

	err = c.readFrame()

	assert.ErrorIs(t, err, io.EOF)
}
