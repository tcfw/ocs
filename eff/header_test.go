package eff

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tcfw/ocs/cki"
)

func TestEncrypt(t *testing.T) {
	pub1, priv1, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	template := cki.Certificate{
		Subject: "c1",
	}
	template2 := cki.Certificate{
		Subject: "c2",
	}

	cert1, err := cki.NewCertificate(template, pub1, nil, priv1)
	if err != nil {
		t.Fatal(err)
	}

	cert2, err := cki.NewCertificate(template2, pub2, nil, priv2)
	if err != nil {
		t.Fatal(err)
	}

	h, _, err := NewHeader(cert1, cert2)
	if err != nil {
		t.Fatal(err)
	}

	testData := make([]byte, 10<<20)
	rand.Read(testData)

	cipherData, err := h.Encrypt(nil, priv1, testData)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, cipherData)

	plainData, err := h.Decrypt(nil, priv2, cipherData, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, testData, plainData)
}

func TestParseHeader(t *testing.T) {
	pub1, priv1, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	template := cki.Certificate{
		Subject: "c1",
	}
	template2 := cki.Certificate{
		Subject: "c2",
	}

	cert1, err := cki.NewCertificate(template, pub1, nil, priv1)
	if err != nil {
		t.Fatal(err)
	}

	cert2, err := cki.NewCertificate(template2, pub2, nil, priv2)
	if err != nil {
		t.Fatal(err)
	}

	h, _, err := NewHeader(cert1, cert2)
	if err != nil {
		t.Fatal(err)
	}

	testData := make([]byte, 10<<20)
	rand.Read(testData)

	cipherData, err := h.Encrypt(nil, priv1, testData)
	if err != nil {
		t.Fatal(err)
	}

	headerBytes, err := h.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	parsedHeader, err := ParseHeader(headerBytes)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, h.Version, parsedHeader.Version)
	assert.Equal(t, h.Algo, parsedHeader.Algo)
	assert.Equal(t, h.CertificateID, parsedHeader.CertificateID)
	assert.Equal(t, h.Signature, parsedHeader.Signature)
	assert.Equal(t, h.IntendedCertificateID, parsedHeader.IntendedCertificateID)
	assert.Equal(t, h.EphemeralAlgo, parsedHeader.EphemeralAlgo)
	assert.Equal(t, h.EphemeralPublicKey, parsedHeader.EphemeralPublicKey)
	assert.Equal(t, h.EphemeralKDFSalt, parsedHeader.EphemeralKDFSalt)
	assert.Equal(t, h.Certificates, parsedHeader.Certificates)

	cp := cki.NewInMemCertPool()
	cp.AddCert(cert1, cki.Trusted)
	cp.AddCert(cert2, cki.Trusted)

	plainData, err := parsedHeader.Decrypt(cp, priv2, cipherData, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, testData, plainData)
}

func TestEmbeddedCertificate(t *testing.T) {
	pub1, priv1, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	template := cki.Certificate{
		Subject: "c1",
	}
	template2 := cki.Certificate{
		Subject: "c2",
	}

	cert1, err := cki.NewCertificate(template, pub1, nil, priv1)
	if err != nil {
		t.Fatal(err)
	}

	cert2, err := cki.NewCertificate(template2, pub2, nil, priv2)
	if err != nil {
		t.Fatal(err)
	}

	_, hdopt, err := WithEphemeral(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	h, err := NewHeaderWithOptions(cert1, cert2, hdopt, WithEmbeddedCerts(cert1)) //enable embedding
	if err != nil {
		t.Fatal(err)
	}

	testData := make([]byte, 10<<20)
	rand.Read(testData)

	cipherData, err := h.Encrypt(nil, priv1, testData)
	if err != nil {
		t.Fatal(err)
	}

	headerBytes, err := h.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	parsedHeader, err := ParseHeader(headerBytes)
	if err != nil {
		t.Fatal(err)
	}

	cp := cki.NewInMemCertPool()
	cp.AddCert(cert2, cki.Trusted)

	plainData, err := parsedHeader.Decrypt(cp, priv2, cipherData, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, testData, plainData)
}
