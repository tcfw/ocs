package eff

import (
	"bytes"
	"io/ioutil"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tcfw/ocs/cki"
)

func TestMarshalEFF(t *testing.T) {
	pub1, priv1, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	template := cki.Certificate{Subject: "c1"}
	template2 := cki.Certificate{Subject: "c2"}

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

	testData := make([]byte, 1<<20)
	rand.Read(testData)

	ct, err := h.Encrypt(nil, priv1, testData)
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)

	err = MarshalEFF(h, ct, buf)
	if err != nil {
		t.Fatal(err)
	}

	hBytes, err := h.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	//version + magic + headerSize + header + nonce + cipherText + aeadOverhead
	expectedLen := 1 + len(`OCSEFF`) + 4 + len(hBytes) + 12 + len(testData) + 16

	assert.Len(t, buf.Bytes(), expectedLen, "unexpected output length")
}

func TestParseEFF(t *testing.T) {
	pub1, priv1, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	template := cki.Certificate{Subject: "c1"}
	template2 := cki.Certificate{Subject: "c2"}

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

	testData := make([]byte, 1<<20)
	rand.Read(testData)

	ct, err := h.Encrypt(nil, priv1, testData)
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)

	err = MarshalEFF(h, ct, buf)
	if err != nil {
		t.Fatal(err)
	}

	rbH, err := ParseEFF(buf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, h.Version, rbH.Version)
	assert.Equal(t, h.Algo, rbH.Algo)
	assert.Equal(t, h.CertificateID, rbH.CertificateID)
	assert.Equal(t, h.Signature, rbH.Signature)
	assert.Equal(t, h.IntendedCertificateID, rbH.IntendedCertificateID)
	assert.Equal(t, h.EphemeralAlgo, rbH.EphemeralAlgo)
	assert.Equal(t, h.EphemeralPublicKey, rbH.EphemeralPublicKey)
	assert.Equal(t, h.EphemeralKDFSalt, rbH.EphemeralKDFSalt)
	assert.Equal(t, h.Certificates, rbH.Certificates)

	rbCt, _ := ioutil.ReadAll(buf)

	pt, err := h.Decrypt(nil, priv2, rbCt, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, testData, pt)

}
