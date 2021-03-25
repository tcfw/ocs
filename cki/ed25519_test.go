package cki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCertFromEd25519(t *testing.T) {
	pub, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	template := Certificate{
		Subject: "*.tcfw.com.au",
		Entity: &Entity{
			Name:     "Thomas Worrall",
			Locality: "Sydney",
			State:    "NSW",
			Country:  "AU",
			Email:    "hello@tcfw.com.au",
		},
	}

	cert, err := NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, cert.Algo, ED25519)
	assert.Equal(t, cert.Version, uint8(1))

	//Check self sign
	err = cert.verifySignatureOnly(cert.ID, pub)
	if err != nil {
		t.Fatal(err)
	}

	//Test non-matching pub cert
	pub2, priv2, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	template2 := Certificate{}

	cert2, err := NewCertificate(template2, pub2, cert, priv)
	if err != nil {
		t.Fatal(err)
	}

	err = cert.verifySignatureMatching(cert2.ID, pub2)
	if err == nil {
		t.Fatalf("Should have not matched any signatures")
	}
	assert.Same(t, err, ErrNoMatchingSignatures)

	err = cert.AddSignature(cert2, priv2, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = cert.verifySignatureMatching(cert2.ID, pub2)
	if err != nil {
		t.Fatal(err)
	}
}
