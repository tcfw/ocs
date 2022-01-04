package stl

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"errors"
	"io"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sys/cpu"
)

var (
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	// Keep in sync with crypto/aes/cipher_s390x.go.
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR &&
		(cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasAESGCMHardwareSupport = runtime.GOARCH == "amd64" && hasGCMAsmAMD64 ||
		runtime.GOARCH == "arm64" && hasGCMAsmARM64 ||
		runtime.GOARCH == "s390x" && hasGCMAsmS390X

	defaultCipherSuites = []ApplicationSuite{
		AES256gcm,
		Chacha20_poly1305,
		AES128gcm,
	}

	defaultCipherSuitesNoAES = []ApplicationSuite{
		Chacha20_poly1305,
		AES256gcm,
		AES128gcm,
	}

	trafficLabelInit     = []byte("traffic initer")
	trafficLabelResponse = []byte("traffic response")
	handshakeLabel       = []byte("hs reponse hello")
)

type Suite struct {
	Handshake   HandshakeSuite
	Application ApplicationSuite
}

type HandshakeSuite uint8
type ApplicationSuite uint8

const (
	HsSuiteNotSet HandshakeSuite = iota
	ECDHE_x25519
	ECDHE_p386
	ECDHE_p256
	DBVF6_pn14qp438
)

const (
	AppSuiteNotSet ApplicationSuite = iota
	AES128gcm
	AES256gcm
	Chacha20_poly1305
)

type handshakeParams struct {
	priv crypto.PrivateKey
	pub  []byte
}

func curveParams(c *Config, s HandshakeSuite) (*handshakeParams, error) {
	switch s {
	case ECDHE_p256, ECDHE_p386:
		return curveGenericParams(c, s)
	case ECDHE_x25519:
		fallthrough
	default:
		return curve25519params(c)
	}
}

func curve25519params(c *Config) (*handshakeParams, error) {
	var priv, pub [32]byte
	_, err := io.ReadFull(c.rand(), priv[:])
	if err != nil {
		return nil, err
	}

	curve25519.ScalarBaseMult(&pub, &priv)

	return &handshakeParams{
		priv: priv,
		pub:  pub[:],
	}, nil
}

func curveGenericParams(c *Config, curve HandshakeSuite) (*handshakeParams, error) {
	var g elliptic.Curve

	switch curve {
	case ECDHE_p256:
		g = elliptic.P256()
	case ECDHE_p386:
		g = elliptic.P384()
	default:
		return nil, errors.New("unknown curve")
	}

	private, x, y, err := elliptic.GenerateKey(g, c.rand())
	if err != nil {
		private = nil
		return nil, err
	}

	public := elliptic.MarshalCompressed(g, x, y)

	return &handshakeParams{
		pub:  public,
		priv: private,
	}, nil
}

func ecdh(c *Config, curve HandshakeSuite, peerKey []byte, params *handshakeParams) ([]byte, error) {
	switch curve {
	case ECDHE_p386, ECDHE_p256:
		return genericECDH(c, curve, peerKey, params)
	case ECDHE_x25519:
		return x25519ECDH(c, peerKey, params)
	}

	return nil, errors.New("unknown curve")
}

func genericECDH(c *Config, curve HandshakeSuite, peerKey []byte, params *handshakeParams) ([]byte, error) {
	var g elliptic.Curve

	switch curve {
	case ECDHE_p256:
		g = elliptic.P256()
	case ECDHE_p386:
		g = elliptic.P384()
	default:
		return nil, errors.New("unknown curve")
	}

	x, y := elliptic.UnmarshalCompressed(g, peerKey)

	sX, _ := g.ScalarMult(x, y, params.priv.([]byte))

	return sX.Bytes(), nil
}

func x25519ECDH(c *Config, peerKey []byte, params *handshakeParams) ([]byte, error) {
	priv := params.priv.([32]byte)

	sec, err := curve25519.X25519(priv[:], peerKey)
	if err != nil {
		return nil, err
	}

	return sec[:], nil
}

func mutualSuite(c *Config, inital []Suite) (Suite, error) {
	suite := Suite{
		Handshake:   inital[0].Handshake,
		Application: AppSuiteNotSet,
	}

	preferenceList := defaultCipherSuites

	if !hasAESGCMHardwareSupport {
		preferenceList = defaultCipherSuitesNoAES
	}

	for _, want := range preferenceList {
		for _, have := range inital {
			if have.Application == want {
				suite.Application = want
				break
			}
		}
	}

	if suite.Application == AppSuiteNotSet {
		return suite, errors.New("stl: no cipher suite supported by both parties")
	}

	return suite, nil
}

func makeCipher(suite ApplicationSuite, baseKey []byte, label []byte) (c cipher.AEAD, err error) {
	k := make([]byte, 32)

	_, err = hkdf.New(sha3.New384, baseKey, nil, label).Read(k)
	if err != nil {
		return nil, err
	}

	switch suite {
	case Chacha20_poly1305:
		c, err = chacha20poly1305.New(k[:32])
	case AES128gcm:
		bc, err := aes.NewCipher(k[:16])
		if err != nil {
			return nil, err
		}
		c, err = cipher.NewGCM(bc)
	case AES256gcm:
		bc, err := aes.NewCipher(k[:32])
		if err != nil {
			return nil, err
		}
		c, err = cipher.NewGCM(bc)
	}

	if err != nil {
		return nil, err
	}

	return c, nil
}
