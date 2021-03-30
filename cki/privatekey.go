package cki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/vmihailenco/msgpack"
)

var (
	//ErrUnknownKeyAlgorithm unknown key algorithm
	ErrUnknownKeyAlgorithm = errors.New("unknown key algorithm")
)

//PrivateKey to create signatures
type PrivateKey interface {
	Sign([]byte) ([]byte, error)
	Bytes() ([]byte, error)
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
	if len(key) != 32 {
		return nil, errors.New("key length should be 32 bytes")
	}

	d, err := MarshalPrivateKey(pk)
	if err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()

	dst := make([]byte, nonceSize+len(d)+aead.Overhead())

	n, err := rand.Read(dst[:nonceSize])
	if err != nil {
		return nil, err
	}
	if n != nonceSize {
		return nil, errors.New("nonce read mismatch")
	}

	aead.Seal(dst[:nonceSize], dst[:nonceSize], d, nil)

	return dst, nil
}

//ParseEncryptedPrivateKey decrypts and decodes a private key using AES256-GCM
func ParseEncryptedPrivateKey(d []byte, key []byte) (PrivateKey, error) {
	if len(key) != 32 {
		return nil, errors.New("key length should be 32 bytes")
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()

	dst := make([]byte, len(d)-nonceSize)

	_, err = aead.Open(dst[:0], d[:nonceSize], d[nonceSize:], nil)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKey(dst)
}
