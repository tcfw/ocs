package eff

import (
	"crypto/aes"
	"crypto/cipher"
)

//newAESCipher creates a new GCM based AES 256 bit cipher
func newAESCipher(k []byte) (cipher.AEAD, error) {
	if len(k) != 32 {
		return nil, ErrInvalidAlgo
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
