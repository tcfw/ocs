package cki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECPublicKeyMarshal(t *testing.T) {
	a := ECDSAsecp256r1
	pub, _, err := GenerateECKey(a)
	if err != nil {
		t.Fatal(err)
	}

	b, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	pubrb, err := parsePublicKey(a, b)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, pub, pubrb)
}

func TestEd25519PublicKeyMarshal(t *testing.T) {
	pub, _, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	b, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	pubrb, err := parsePublicKey(ED25519, b)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, pub, pubrb)
}

func TestRSAPublicKeyMarshal(t *testing.T) {
	pub, _, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	b, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	pubrb, err := parsePublicKey(RSA2048SHA384, b)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, pub, pubrb)
}

func TestUnknownPublicKeyParse(t *testing.T) {
	pubrb, err := parsePublicKey(UnknownAlgo, []byte(`abc`))
	assert.Error(t, err, "empty public key")
	assert.Nil(t, pubrb)
}

func TestEmptyPublicKeyMarshal(t *testing.T) {
	pubrb, err := parsePublicKey(RSA2048SHA384, []byte{})
	assert.Error(t, err, "empty public key")
	assert.Nil(t, pubrb)
}
