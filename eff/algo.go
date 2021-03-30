package eff

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidAlgo = errors.New("invalid algorithm")
)

type Algorithm uint8

const (
	//UnknownAlgo unknown or not set
	UnknownAlgo Algorithm = iota
	//AES256_GCM AES 256 bit GCM mode
	AES256_GCM
	//ChaCha20_Poly1305 ChaCha20 with Poly1305 MAC
	ChaCha20_Poly1305

	maxAlgo
)

//algoToAEAD provides an AEAD consturct on a given algorithm and shared key
func algoToAEAD(a Algorithm, k []byte) (cipher.AEAD, error) {
	switch a {
	case ChaCha20_Poly1305:
		return chacha20poly1305.New(k)
	case AES256_GCM:
		return newAESCipher(k)
	default:
		return nil, ErrInvalidAlgo
	}
}
