# Protocol

## Handshake Overview

Hello ->
      <- Hello
Info (opt) ->
  <- Err (opt)
     <- Finish
Finish ->
<- App Data ->

### Best case

Hello -> 
      <- Hello
     <- Finish
Finish ->
<- App Data ->

### Worst case

Hello ->
        <- Err
-> TCP FIN <--

---

# Frame Protocol

## Frame wrapper

struct {
	frameType FrameType
	length uint16
	data [:length]byte
} frame

type FrameType uint8

const (
	invalid FrameType = iota
	clientHello
	serverHello
	info
	finish
	error
	data
)

## Error frame

struct {
	code ErrorCode
} error

type ErrorCode uint8

const (
	errorUnknown ErrorCode = iota
	errorUnauthorised
	errorUnexpectedFrame
	errorBadCertificate
	errorBadParameters
)

## Info frame

struct {
	extlength uint16
	ext [:extlength] extension
} info

## Init Hello Frame

struct {
	version byte
	epoch uint32
	random [32]byte
	suitesCount uint8
	suites [:suitesCount]suite
	keylength uint16
	key [:keylength]byte
	hostnameType hostnameType
	hostnamelength uint16
	hostname [:namelength]byte
	extlength uint16
	ext [:extlength] extension
} InitHello

## Hostname

type hostnameType byte

const (
	unknown hostnameType = iota
	ip 
	dns
	psk
	onRequest
)

struct {
	suite applicationSuite
	certID []byte
	publicKey []byte
	data []byte
} hostnamePSK

## Suite

struct {
	handshake handshakeSuite
	application applicationSuite
} suite

type handshakeSuite byte
type applicationSuite byte

const (
	hsSuiteNotSet handshakeSuite = iota
	ecdhe_x25519
	ecdhe_p386
	ecdhe_p256
	dbvf_pn14qp438

	appSuiteNotSet applicationSuite = iota
	aes128gcm
	aes256gcm
	chacha20_poly1305
)

## Extension

struct {
	extType extensionType
	length uint16
	data [:length]byte
} extension

type extensionType byte

const (
	certificate extensionType = iota 0x01
	certificateRequest
	name 
	nameRequest
	earlyData
	hostnameId
)

### Certificate

struct {
	type certificateType
	length uint16
	certificate [:length]byte
	verify [48]byte
} certificate

type certificateType uint8

const (
	cki certificateType = iota
	x509
)

### Hostname Identification

struct {
	hostnameIdType hostnameIdType
	keyIdLength uint8
	keyId [:keyIdLength]byte
	data []byte
} hostnameId

type hostnameIdType uint8

const (
	unknownType hostnameIdType = iota
	hmac
	psk
)

struct {
	emphemalKeyLength uint16
	emphemalKey [:emphemalKeyLength]byte
	pkidLength uint16
	publicKeyIDUsed [:pkidLength]byte
	data []byte
} 

## Response Hello Frame

struct {
	version byte
	suite suite
	keyLen uint16
	key [:keyLen]byte
	epoch uint32
	random [32]byte
	// This point down is encrypted using handshake key share
	extLen uint16
	ext [:extLen] extension
} ResponseHello

# State Machines

## Initer

START
-> WAIT_HANDSHAKE
-> WAIT_FINISH
CONNECTED

## Responder

START
-> WAIT_HANDSHAKE
-> WAIT_INFO
-> WAIT_FINISH
CONNECTED