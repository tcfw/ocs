package cki

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type inmemCertPool struct {
	certStore  map[string]*Certificate
	trustStore map[string]TrustLevel
	revoked    map[string]bool
}

func newInMemCertPool() *inmemCertPool {
	return &inmemCertPool{
		certStore:  make(map[string]*Certificate),
		trustStore: make(map[string]TrustLevel),
		revoked:    make(map[string]bool),
	}
}

func (incp *inmemCertPool) Reset() {
	incp.certStore = make(map[string]*Certificate)
	incp.trustStore = make(map[string]TrustLevel)
	incp.revoked = make(map[string]bool)
}

func (incp *inmemCertPool) AddCert(c *Certificate, t TrustLevel) {
	incp.certStore[string(c.ID)] = c
	incp.trustStore[string(c.ID)] = t
}

func (incp *inmemCertPool) FindCertificate(id, _ []byte) (*Certificate, error) {
	cert, ok := incp.certStore[string(id)]
	if !ok {
		return nil, errors.New("not found")
	}

	return cert, nil
}

func (incp *inmemCertPool) TrustLevel(id []byte) (TrustLevel, error) {
	tl, ok := incp.trustStore[string(id)]
	if !ok {
		return UnknownTrust, nil
	}

	return tl, nil
}

func (incp *inmemCertPool) IsRevoke(id []byte) error {
	revoked, ok := incp.revoked[string(id)]
	if !ok {
		return nil
	}

	if revoked {
		return ErrRevoked
	}

	return nil
}

func TestVerifyPKI(t *testing.T) {
	cp := newInMemCertPool()

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
	interm, err := NewCertificate(intermTemplate, pubInterm, root, privRoot)
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
	edge, err := NewCertificate(edgeTemplate, pubEdge, interm, privInterm)
	if err != nil {
		t.Fatal(err)
	}

	//Root CA trusted
	cp.AddCert(root, Trusted)
	cp.AddCert(interm, UnknownTrust)
	cp.AddCert(edge, UnknownTrust)

	err = edge.Verify(cp)
	assert.Nil(t, err)

	cp.Reset()

	//No one trusted
	cp.AddCert(root, UnknownTrust)
	cp.AddCert(interm, UnknownTrust)
	cp.AddCert(edge, UnknownTrust)

	err = edge.Verify(cp)
	assert.ErrorIs(t, err, ErrUntrustedCertificate)

	cp.Reset()

	//Intermediate Trusted
	cp.AddCert(root, UnknownTrust)
	cp.AddCert(interm, Trusted)
	cp.AddCert(edge, UnknownTrust)

	err = edge.Verify(cp)
	assert.Nil(t, err)

	//Edge ultimately trusted
	cp.AddCert(root, UnknownTrust)
	cp.AddCert(interm, UnknownTrust)
	cp.AddCert(edge, UltimatelyTrusted)

	err = edge.Verify(cp)
	assert.Nil(t, err)

	//Root not trusted
	cp.AddCert(root, NotTrusted)
	cp.AddCert(interm, UnknownTrust)
	cp.AddCert(edge, UnknownTrust)

	err = edge.Verify(cp)
	assert.ErrorIs(t, err, ErrUntrustedCertificate)
}
