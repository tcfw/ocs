package cki

import (
	"regexp"
	"strings"
	"testing"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"
)

func TestCertFuzz(t *testing.T) {
	f := fuzz.New()

	//Remove fuzzing signatures otherwise NewCertificate will always fail
	skipList := regexp.MustCompile(`^(Signatures)$`)
	f.SkipFieldsWithPattern(skipList)

	template := Certificate{
		Entity: &Entity{},
	}

	f.Fuzz(&template)

	pub, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	template.CertType = PKI

	//TODO(tcfw): test err response for invalid date ranges
	if template.NotAfter.After(time.Now().Add(10 * 365 * 24 * time.Hour)) {
		template.NotAfter = time.Now().Add(5 * 365 * 24 * time.Hour)
	}
	if template.NotBefore.After(time.Now()) {
		template.NotBefore = time.Now().Add(-1 * 24 * time.Hour)
	}

	cert, err := NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	//Check self sign
	err = cert.verifySignatureOnly(cert.ID, pub)
	if err != nil {
		t.Fatal(err)
	}

	b, err := cert.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	readback, err := ParseCertificate(b)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, cert.NotBefore.Equal(readback.NotBefore))
	assert.True(t, cert.NotAfter.Equal(readback.NotAfter))

	//Match up ts between readback and original
	//caused by time being equal, but different values
	//being used to create value in wall and/or ext
	readback.NotAfter = cert.NotAfter
	readback.NotBefore = cert.NotBefore

	assert.Equal(t, cert, readback)
}

func TestCertPEM(t *testing.T) {
	template := Certificate{
		Entity: &Entity{},
	}

	pub, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	pem, err := cert.PEM()
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, strings.HasPrefix(string(pem), "-----BEGIN OCS CERTIFICATE"))

	additional := []byte(`ADDITIONAL data`)
	pem = append(pem, additional...)

	readback, rest, err := ParsePEMCertificate(pem)
	if err != nil {
		t.Fatal(err)
	}

	//Match up ts between readback and original
	//caused by time being equal, but different values
	//being used to create value in wall and/or ext
	//
	// Tested above for equality
	readback.NotAfter = cert.NotAfter
	readback.NotBefore = cert.NotBefore

	assert.Equal(t, additional, rest)
	assert.Equal(t, cert, readback)
}

func TestCertValidity(t *testing.T) {
	template := Certificate{
		Entity: &Entity{},
	}

	pub, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	//Version
	cert.Version = 3
	err = cert.validate()
	assert.EqualError(t, err, "invalid version")

	//NotBefore
	cert.Version = 1
	cert.NotBefore = time.Now().Add(1 * time.Second)
	err = cert.validate()
	assert.EqualError(t, err, "invalid notBefore: must be before now")

	//NotAfter
	cert.NotBefore = time.Now().Add(-1 * time.Second)
	cert.NotAfter = cert.NotBefore
	err = cert.validate()
	assert.EqualError(t, err, "invalid notAfter: must be after now")

	//CertType
	cert.NotAfter = time.Now().Add(10 * time.Minute)
	cert.CertType = certTypeMax
	err = cert.validate()
	assert.EqualError(t, err, "invalid certType: 4")

	//PKI signature count
	cert.CertType = PKI
	cert.Signatures = append(cert.Signatures, Signature{Algo: UnknownAlgo})
	err = cert.validate()
	assert.EqualError(t, err, "too many signatures")

	//Switch to WOT mode for more sigs
	cert.CertType = WOT

	//Zero public key
	origPK := make([]byte, len(cert.PublicKey))
	copy(origPK, cert.PublicKey)
	cert.PublicKey = []byte{}
	err = cert.validate()
	assert.EqualError(t, err, "no public key")

	//Invalid algo on sig
	cert.PublicKey = origPK
	err = cert.validate()
	assert.EqualError(t, err, "invalid algo 0 in signature 1")

	//Missing cert ID
	cert.Signatures[1].Algo = ED25519
	err = cert.validate()
	assert.EqualError(t, err, "invalid cert ID in signature 1")

	//Missing signature value
	cert.Signatures[1].ID = []byte(`abcdefghijklmnopqrstuvwxyz123456`)
	err = cert.validate()
	assert.EqualError(t, err, "invalid signature value in signature 1")

	//Zero signatures
	cert.Signatures = []Signature{}
	err = cert.validate()
	assert.EqualError(t, err, "no signatures")
}
