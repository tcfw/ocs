package eff

import (
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAESCipher(t *testing.T) {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	if err != nil {
		t.Fatal(err)
	}

	c, err := newAESCipher(k)
	if err != nil {
		t.Fatal(err)
	}

	assert.Implements(t, (*cipher.AEAD)(nil), c)
}
