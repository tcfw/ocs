package cki

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack"
)

func TestECPrivateKeyMarshal(t *testing.T) {
	_, priv, err := GenerateECKey(ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	d, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	privrb, err := ParsePrivateKey(d)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, priv, privrb)
}

func TestEd25519PrivateKeyMarshal(t *testing.T) {
	_, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	d, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	privrb, err := ParsePrivateKey(d)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, priv, privrb)
}

func TestRSAPrivateKeyMarshal(t *testing.T) {
	_, priv, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	d, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	privrb, err := ParsePrivateKey(d)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, priv, privrb)
}

func TestUnknownKeyParse(t *testing.T) {
	incorrectKey := &ocsPrivateKey{
		Algo: UnknownAlgo,
		Key:  []byte(`not a key`),
	}

	b, err := msgpack.Marshal(incorrectKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParsePrivateKey(b)
	assert.NotEmpty(t, err)
	assert.ErrorIs(t, err, ErrUnknownKeyAlgorithm)
}

func TestEmptyPrivateKeyMarshal(t *testing.T) {
	incorrectKey := &ocsPrivateKey{
		Algo: ED25519,
		Key:  []byte(``),
	}

	b, err := msgpack.Marshal(incorrectKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParsePrivateKey(b)
	assert.NotEmpty(t, err)
	assert.Equal(t, err.Error(), "key is empty")
}

func TestMarshalEncryptedPrivateKey(t *testing.T) {
	_, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	key := []byte(`abcdefghijklmnopqrstuvwxyz123456`)

	encK, err := MarshalEncryptedPrivateKey(priv, key)
	if err != nil {
		t.Fatal(err)
	}

	privrb, err := ParseEncryptedPrivateKey(encK, key)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, priv, privrb)
}
