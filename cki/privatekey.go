package cki

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/argon2"
)

var (
	//ErrUnknownKeyAlgorithm unknown key algorithm
	ErrUnknownKeyAlgorithm = errors.New("unknown key algorithm")
)

const (
	argon2Times   = 2
	argon2Mem     = 64 * 1024
	argon2Threads = 2
	saltLen       = 32
)

//PrivateKey to create signatures
type PrivateKey interface {
	Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
	Bytes() ([]byte, error)
	Public() PublicKey
}

func castSigner(p PrivateKey) crypto.Signer {
	return &cryptoSigner{p}
}

type cryptoSigner struct {
	p PrivateKey
}

func (cs *cryptoSigner) Public() crypto.PublicKey {
	pk := cs.p.Public()

	switch pk.(type) {
	case *SecpPublicKey:
		return &pk.(*SecpPublicKey).PublicKey
	case *Ed25519Public:
		return pk.(*Ed25519Public)
	case *RSAPublicKey:
		return &pk.(*RSAPublicKey).PublicKey
	default:
		return pk
	}
}
func (cs *cryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return cs.p.Sign(rand, digest, opts)
}

//MarshalPrivateKey encodes a private key into msgpack encoding
func MarshalPrivateKey(pk PrivateKey) ([]byte, error) {
	var err error
	k := &ocsPrivateKey{}

	k.Algo = privKeyAlgo(pk)
	k.Key, err = pk.Bytes()
	if err != nil {
		return nil, err
	}

	return msgpack.Marshal(k)
}

//ocsPrivateKey represntation of a generic private key
type ocsPrivateKey struct {
	Algo Algorithm `msgpack:"a"`
	Key  []byte    `msgpack:"k"`
}

//Bytes encodes the private key to msgpack encoding
func (privk *ocsPrivateKey) Bytes() ([]byte, error) {
	return msgpack.Marshal(privk)
}

//ParsePrivateKey unmarshals the private key raw data
func ParsePrivateKey(d []byte) (PrivateKey, error) {
	k := &ocsPrivateKey{}

	err := msgpack.Unmarshal(d, k)
	if err != nil {
		return nil, err
	}

	if len(k.Key) == 0 {
		return nil, errors.New("key is empty")
	}

	switch k.Algo {
	case ED25519:
		return parseED25519PrivateKey(k)
	case ECDSAsecp256r1, ECDSAsecp384r1:
		return parseECPrivateKey(k)
	case RSA2048, RSA4096:
		return ParseRSAPrivateKey(k)
	default:
		return nil, ErrUnknownKeyAlgorithm
	}
}

//MarshalEncryptedPrivateKey encodes and encryps a private key with AES-256-GCM
func MarshalEncryptedPrivateKey(pk PrivateKey, key []byte) ([]byte, error) {
	if len(key) < 8 {
		return nil, errors.New("key length should be at least 8 character")
	}

	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	encKey := argon2.IDKey(key, salt, argon2Times, argon2Mem, argon2Threads, 32)

	d, err := MarshalPrivateKey(pk)
	if err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()

	encDst := make([]byte, nonceSize+len(d)+aead.Overhead())

	n, err := rand.Read(encDst[:nonceSize])
	if err != nil {
		return nil, err
	}
	if n != nonceSize {
		return nil, errors.New("nonce read mismatch")
	}

	aead.Seal(encDst[:nonceSize], encDst[:nonceSize], d, salt)

	salt = append(salt, encDst...)

	return salt, nil
}

//ParseEncryptedPrivateKey decrypts and decodes a private key using AES256-GCM
func ParseEncryptedPrivateKey(d []byte, key []byte) (PrivateKey, error) {
	if len(key) != 32 {
		return nil, errors.New("key length should be 32 bytes")
	}

	salt := d[:saltLen]
	d = d[saltLen:]

	encKey := argon2.IDKey(key, salt, argon2Times, argon2Mem, argon2Threads, 32)

	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()

	dst := make([]byte, len(d)-nonceSize)

	_, err = aead.Open(dst[:0], d[:nonceSize], d[nonceSize:], salt)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKey(dst)
}

//MarshalPEMRawPrivateKey encodes a marshalled private key to PEM format
func MarshalPEMRawPrivateKey(d []byte, w io.Writer, encrypted bool) error {
	bType := PEMPrivKeyHeader

	if encrypted {
		bType = PEMEncPrivKeyHeader
	}

	b := &pem.Block{Type: bType, Bytes: d}
	return pem.Encode(w, b)
}

//MarshalPEMPrivateKey encodes a private key to PEM format
func MarshalPEMPrivateKey(d []byte) []byte {
	b := &pem.Block{Type: PEMPrivKeyHeader, Bytes: d}
	return pem.EncodeToMemory(b)
}

//ParsePEMPrivateKey parses a non-encrypted PEM encoded file
func ParsePEMPrivateKey(d []byte) ([]byte, error) {
	b, _ := pem.Decode(d)

	if b.Type != PEMPrivKeyHeader {
		return nil, ErrUnknownPEMType
	}

	return b.Bytes, nil
}
