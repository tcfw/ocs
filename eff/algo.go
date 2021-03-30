package eff

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	//ErrInvalidAlgo invalid algorithm
	ErrInvalidAlgo = errors.New("invalid algorithm")
)

//Algorithm EFF AEAD encryption algorithm
type Algorithm uint8

const (
	//UnknownAlgo unknown or not set
	UnknownAlgo Algorithm = iota
	//AES256GCM AES 256 bit GCM mode
	AES256GCM
	//ChaCha20Poly1305 ChaCha20 with Poly1305 MAC
	ChaCha20Poly1305

	maxAlgo
)

//algoToAEAD provides an AEAD consturct on a given algorithm and shared key
func algoToAEAD(a Algorithm, k []byte) (cipher.AEAD, error) {
	switch a {
	case ChaCha20Poly1305:
		return chacha20poly1305.New(k)
	case AES256GCM:
		return newAESCipher(k)
	default:
		return nil, ErrInvalidAlgo
	}
}
