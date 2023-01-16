package cki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCRYSTALSDilithiumSignature(t *testing.T) {
	pk, sk, err := GenerateCRYSTALSDilithiumKey(2)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte(`test`)

	sig, err := sk.Sign(nil, msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	ok := pk.Verify(msg, sig)
	if !ok {
		t.Fatal("exected verify to be true")
	}
}

func TestCRYSTALSDilithiumMarshal(t *testing.T) {
	pk, sk, err := GenerateCRYSTALSDilithiumKey(2)
	if err != nil {
		t.Fatal(err)
	}

	ppk, err := pk.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	psk, err := sk.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	rbpk, err := parseCRYSTALSDilithiumPublicKey(CRYSTALSDilithium2, ppk)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, pk, rbpk)

	rbsk, err := parseCRYSTALSDilithiumPrivateKey(&ocsPrivateKey{CRYSTALSDilithium2, psk})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, sk, rbsk)
}
