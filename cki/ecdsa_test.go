package cki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCertFromECDSA(t *testing.T) {
	pub, priv, err := GenerateECKey(ECDSAsecp256r1)
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

	assert.Equal(t, cert.Algo, ECDSAsecp256r1)
	assert.Equal(t, cert.Version, uint8(1))

	err = cert.verifySignatureMatching(cert.ID, pub)
	if err != nil {
		t.Fatal(err)
	}
}
