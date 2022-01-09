package cki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyPKI(t *testing.T) {
	cp := NewInMemCertPool()

	pubRoot, privRoot, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	pubInterm, privInterm, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	pubEdge, _, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	//Create self-signed root CA
	rootTemplate := Certificate{
		CertType: PKI,
		IsCA:     true,
		Subject:  "Digital Verify Root",
		Entity: &Entity{
			Name:     "Digital Verify Inc",
			Unit:     "Digital",
			Locality: "Sydney",
			State:    "NSW",
			Country:  "AU",
			Email:    "certificates@tcfw.com.au",
		},
	}
	root, err := NewCertificate(rootTemplate, pubRoot, nil, privRoot)
	if err != nil {
		t.Fatal(err)
	}

	//Intermediate cert
	intermTemplate := Certificate{
		CertType: PKI,
		IsCA:     true,
		Subject:  "Digital Verify Intermediate",
		Entity: &Entity{
			Name:     "Digital Verify Inc",
			Unit:     "Digital",
			Locality: "Sydney",
			State:    "NSW",
			Country:  "AU",
			Email:    "certificates@tcfw.com.au",
		},
	}
	intermediate, err := NewCertificate(intermTemplate, pubInterm, root, privRoot)
	if err != nil {
		t.Fatal(err)
	}

	//Edge cert
	edgeTemplate := Certificate{
		CertType: PKI,
		Subject:  "mysite.com",
		Entity: &Entity{
			Name:     "TCFW",
			Unit:     "Engineering",
			Locality: "Sydney",
			State:    "NSW",
			Country:  "AU",
		},
	}
	edge, err := NewCertificate(edgeTemplate, pubEdge, intermediate, privInterm)
	if err != nil {
		t.Fatal(err)
	}

	//Root CA trusted
	cp.AddCert(root, Trusted)
	cp.AddCert(intermediate, UnknownTrust)

	err = edge.Verify(cp)
	assert.Nil(t, err)

	cp.Reset()

	//No one trusted
	cp.AddCert(root, UnknownTrust)
	cp.AddCert(intermediate, UnknownTrust)

	err = edge.Verify(cp)
	assert.ErrorIs(t, err, ErrUntrustedCertificate)

	cp.Reset()

	//Intermediate Trusted
	cp.AddCert(root, UnknownTrust)
	cp.AddCert(intermediate, Trusted)

	err = edge.Verify(cp)
	assert.Nil(t, err)

	//Edge ultimately trusted
	cp.AddCert(root, UnknownTrust)
	cp.AddCert(intermediate, UnknownTrust)
	cp.AddCert(edge, UltimatelyTrusted)

	err = edge.Verify(cp)
	assert.Nil(t, err)

	//Root not trusted
	cp.AddCert(root, NotTrusted)
	cp.AddCert(intermediate, UnknownTrust)
	cp.AddCert(edge, UnknownTrust)

	err = edge.Verify(cp)
	assert.ErrorIs(t, err, ErrUntrustedCertificate)
}

func TestPatternMatch(t *testing.T) {
	assert.True(t, matchesPattern("*.test", "a.test"))
	assert.True(t, matchesPattern("b.test", "b.test"))
	assert.True(t, matchesPattern("*.test", "*.test"))
	assert.True(t, matchesPattern("*.b.c", "a.b.c"))
	assert.True(t, matchesPattern("a.b.c", "a.b.c"))
	assert.False(t, matchesPattern("d.b.c", "a.b.c"))
	assert.False(t, matchesPattern("*.test.com", "a.test"))
	assert.False(t, matchesPattern("*.test", "a.b.test"))
	assert.False(t, matchesPattern("b.test", "a.test"))
	assert.False(t, matchesPattern("a.*.test", "a.b.test"))
	assert.False(t, matchesPattern("a.test", "*.test"))
}
