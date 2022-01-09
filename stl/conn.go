package stl

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Conn struct {
	conn   net.Conn
	state  uint32
	active uint32

	handshakeFn       func(context.Context) error
	handshakeMutex    sync.Mutex
	handshakeError    error
	handshakeAttempts int
	version           uint8
	peerCertificates  []*Certificate

	config *Config
	suite  Suite

	in, out             halfConn
	input, output, hand bytes.Buffer
	rawInput            bytes.Buffer

	buffer    []byte
	buffering bool

	bytesSent   int64
	packetsSent int64
}

const (
	connState_start uint32 = iota
	connState_wait_handshake
	connState_wait_info
	connState_wait_finish
	connState_connected
)

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) Handshake() error {
	return c.handshake(context.Background())
}

func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.handshake(ctx)
}

func (c *Conn) handshake(ctx context.Context) error {
	handshakeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	state := atomic.LoadUint32(&c.state)
	if state == connState_connected {
		return nil
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeError; err != nil {
		return err
	}

	c.in.Lock()
	defer c.in.Unlock()

	atomic.StoreUint32(&c.state, connState_start)

	c.handshakeError = c.handshakeFn(handshakeCtx)
	if c.handshakeError != nil {
		c.handshakeAttempts++
	} else {
		c.flush()
	}

	return c.handshakeError
}

func (c *Conn) Write(d []byte) (int, error) {
	// interlock with Close below
	for {
		x := atomic.LoadUint32(&c.active)
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if atomic.CompareAndSwapUint32(&c.active, x, x+2) {
			break
		}
	}
	defer atomic.AddUint32(&c.active, ^uint32(2-1))

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	return c.writeFrame(FrameType_Data, d)
}

func (c *Conn) write(data []byte) (int, error) {
	if c.buffering {
		c.buffer = append(c.buffer, data...)
		return len(data), nil
	}

	n, err := c.conn.Write(data)
	atomic.AddInt64(&c.bytesSent, int64(n))
	atomic.AddInt64(&c.packetsSent, 1)
	return n, err
}

func (c *Conn) flush() (int, error) {
	c.buffering = false

	if len(c.buffer) == 0 {
		return 0, nil
	}

	n, err := c.write(c.buffer)
	c.buffer = []byte{}

	return n, err
}

var outBufPool = sync.Pool{
	New: func() interface{} {
		return new([]byte)
	},
}

func (c *Conn) writeFrame(frametype FrameType, data []byte) (int, error) {
	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		// You might be tempted to simplify this by just passing &outBuf to Put,
		// but that would make the local copy of the outBuf slice header escape
		// to the heap, causing an allocation. Instead, we keep around the
		// pointer to the slice header returned by Get, which is already on the
		// heap, and overwrite and return that.
		*outBufPtr = outBuf
		outBufPool.Put(outBufPtr)
	}()

	var n int
	for len(data) > 0 {
		m := len(data)
		if maxPayload := c.maxPayloadSizeForWrite(); m > maxPayload {
			m = maxPayload
		}

		_, outBuf = sliceForAppend(outBuf[:0], frameHeaderLength)
		outBuf[0] = byte(frametype)

		outBuf, err := c.out.encrypt(outBuf, data[:m], c.config.rand())
		if err != nil {
			return n, err
		}

		binary.BigEndian.PutUint16(outBuf[1:], uint16(len(outBuf)-frameHeaderLength))

		if _, err := c.write(outBuf); err != nil {
			return n, err
		}
		n += m
		data = data[m:]
	}

	return n, nil
}

func (c *Conn) maxPayloadSizeForWrite() int {
	return 16384
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	if len(b) == 0 {
		return 0, nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	for c.input.Len() == 0 {
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}

	n, _ := c.input.Read(b)

	return n, nil
}

func (c *Conn) Close() error {
	// Interlock with Conn.Write above.
	var x uint32
	for {
		x = atomic.LoadUint32(&c.active)
		if x&1 != 0 {
			return net.ErrClosed
		}
		if atomic.CompareAndSwapUint32(&c.active, x, x|1) {
			break
		}
	}

	if x == 0 {
		c.sendError(ErrorCode_Closed)
	}

	return c.conn.Close()
}

func (c *Conn) readFrame() error {
	if c.in.err != nil {
		return c.in.err
	}

	if c.input.Len() != 0 {
		return c.in.setError(fmt.Errorf("attempted to read frame with pending application data"))
	}

	c.input.Reset()

	if err := c.readFromUntil(c.conn, frameHeaderLength); err != nil {
		if err == io.ErrUnexpectedEOF && c.rawInput.Len() == 0 {
			err = io.EOF
		}
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setError(err)
		}
		return err
	}

	hdr := c.rawInput.Bytes()[:frameHeaderLength]
	n := int(binary.BigEndian.Uint16(hdr[1:]))

	if err := c.readFromUntil(c.conn, frameHeaderLength+n); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setError(err)
		}
		return err
	}

	frame := c.rawInput.Next(frameHeaderLength + n)
	data, typ, err := c.in.decrypt(frame)
	if err != nil {
		return c.in.setError(c.sendError(ErrorCode_Unknown))
	}

	// Application Data messages are always protected.
	if c.in.cipher == nil && typ == FrameType_Data {
		return c.in.setError(c.sendError(ErrorCode_UnexpectedFrame))
	}

	switch typ {
	default:
		return c.in.setError(c.sendError(ErrorCode_UnexpectedFrame))
	case FrameType_Error:
		err := &ErrorFrame{}
		err.Unmarshal(data)
		switch err.Code {
		case ErrorCode_Closed:
			return c.in.setError(io.EOF)
		default:
			return c.in.setError(c.sendError(ErrorCode_UnexpectedFrame))
		}
	case FrameType_Data:
		c.input.Write(data)
	case FrameType_InitHello, FrameType_ResponseHello, FrameType_Info, FrameType_Finish:
		if len(data) == 0 {
			return c.in.setError(c.sendError(ErrorCode_UnexpectedFrame))
		}
		c.hand.WriteByte(byte(typ))
		binary.Write(&c.hand, binary.BigEndian, uint16(len(data)))
		c.hand.Write(data)
	}

	return nil
}

func (c *Conn) sendError(ec ErrorCode) error {
	err := &ErrorFrame{ec}

	c.out.Lock()
	defer c.out.Unlock()

	c.output.Reset()
	c.output.Grow(1)

	err.WriteTo(&c.output)

	c.writeFrame(FrameType_Error, c.output.Bytes())

	return err
}

type halfConn struct {
	sync.Mutex
	cipher cipher.AEAD
	seq    uint64
	err    error
}

func (hc *halfConn) setError(err error) error {
	hc.err = err
	return err
}

func (hc *halfConn) encrypt(frame, payload []byte, rand io.Reader) ([]byte, error) {
	atomic.AddUint64(&hc.seq, 1)

	if hc.cipher == nil {
		return append(frame, payload...), nil
	}

	payload = append(payload, frame[0])
	frame[0] = byte(FrameType_Data)

	frame, nonce := sliceForAppend(frame, hc.cipher.NonceSize())

	_, err := io.ReadFull(rand, nonce)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(frame[1:], uint16(len(payload)+len(nonce)+hc.cipher.Overhead()))

	frame, enc := sliceForAppend(frame, len(payload)+hc.cipher.Overhead())

	hc.cipher.Seal(enc[:0], nonce, payload, frame[:frameHeaderLength])

	return frame, nil
}

type Unmarshaller interface {
	Unmarshal(d []byte) error
}

func (hc *halfConn) decrypt(frame []byte) ([]byte, FrameType, error) {
	var plaintext []byte

	payload := frame[frameHeaderLength:]

	if hc.cipher == nil {
		plaintext = payload
		return plaintext, FrameType(frame[0]), nil
	}

	nonceSize := hc.cipher.NonceSize()
	nonce := payload[:nonceSize]
	payload = payload[nonceSize:]
	additionalData := frame[:frameHeaderLength]

	var err error
	plaintext, err = hc.cipher.Open(payload[:0], nonce, payload, additionalData)
	if err != nil {
		return nil, FrameType(frame[0]), err
	}

	frame[0] = plaintext[len(plaintext)-1]
	plaintext = plaintext[:len(plaintext)-1]

	return plaintext, FrameType(frame[0]), nil
}

func (c *Conn) readHandshake() (interface{}, error) {
	for c.hand.Len() < frameHeaderLength {
		if err := c.readFrame(); err != nil {
			return nil, err
		}
	}

	hdr := c.hand.Bytes()[:frameHeaderLength]
	n := int(binary.BigEndian.Uint16(hdr[1:]))
	if n > maxHandshakeSize {
		c.sendError(ErrorCode_BadParameters)
		return nil, c.in.setError(fmt.Errorf("handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshakeSize))
	}

	for c.hand.Len() < frameHeaderLength+n {
		if err := c.readFrame(); err != nil {
			return nil, err
		}
	}

	data := c.hand.Next(frameHeaderLength + n)

	var m Unmarshaller

	switch data[0] {
	case byte(FrameType_InitHello):
		m = new(InitHello)
	case byte(FrameType_Info):
		m = new(InfoFrame)
	case byte(FrameType_Finish):
		m = new(FinishFrame)
	default:
		return nil, c.in.setError(c.sendError(ErrorCode_UnexpectedFrame))
	}

	if err := m.Unmarshal(data[frameHeaderLength:]); err != nil {
		return nil, c.in.setError(c.sendError(ErrorCode_UnexpectedFrame))
	}

	return m, nil
}

// readFromUntil reads from r into c.rawInput until c.rawInput contains
// at least n bytes or else returns an error.
func (c *Conn) readFromUntil(r io.Reader, n int) error {
	if c.rawInput.Len() >= n {
		return nil
	}
	needs := n - c.rawInput.Len()
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	c.rawInput.Grow(needs + bytes.MinRead)
	_, err := c.rawInput.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}

func (c *Conn) isHandshakeComplete() bool {
	return atomic.LoadUint32(&c.state) == connState_connected
}

type State struct {
	Version           uint8
	HandshakeComplete bool
	Suite             Suite
	PeerName          string
	PeerCertificates  []*Certificate
}

func (c *Conn) State() (state State) {
	state.Version = c.version
	state.Suite = c.suite
	state.HandshakeComplete = c.isHandshakeComplete()
	state.PeerCertificates = c.peerCertificates
	state.PeerName = c.config.Hostname

	return
}

// atLeastReader reads from R, stopping with EOF once at least N bytes have been
// read. It is different from an io.LimitedReader in that it doesn't cut short
// the last Read call, and in that it considers an early EOF an error.
type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n) // won't underflow unless len(p) >= n > 9223372036854775809
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
