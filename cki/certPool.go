package cki

import "errors"

type TrustLevel uint8

const (
	UnknownTrust = iota
	NotTrusted
	IndirectlyTrusted
	Trusted
	UltimatelyTrusted
)

type CertFinder interface {
	FindCertificate(id, ref []byte) (*Certificate, error)
}

type CertTrustStore interface {
	TrustLevel(id []byte) (TrustLevel, error)
}

type CertRevokeChecker interface {
	IsRevoke(id []byte) error
}

type CertPool interface {
	CertFinder
	CertTrustStore
	CertRevokeChecker
}

type InMemCertPool struct {
	certStore  map[string]*Certificate
	trustStore map[string]TrustLevel
	revoked    map[string]bool
}

func NewInMemCertPool() *InMemCertPool {
	return &InMemCertPool{
		certStore:  make(map[string]*Certificate),
		trustStore: make(map[string]TrustLevel),
		revoked:    make(map[string]bool),
	}
}

func (incp *InMemCertPool) Reset() {
	incp.certStore = make(map[string]*Certificate)
	incp.trustStore = make(map[string]TrustLevel)
	incp.revoked = make(map[string]bool)
}

func (incp *InMemCertPool) AddCert(c *Certificate, t TrustLevel) {
	incp.certStore[string(c.ID)] = c
	incp.trustStore[string(c.ID)] = t
}

func (incp *InMemCertPool) Revoke(c *Certificate) {
	incp.revoked[string(c.ID)] = true
}

func (incp *InMemCertPool) FindCertificate(id, _ []byte) (*Certificate, error) {
	cert, ok := incp.certStore[string(id)]
	if !ok {
		return nil, errors.New("not found")
	}

	return cert, nil
}

func (incp *InMemCertPool) TrustLevel(id []byte) (TrustLevel, error) {
	tl, ok := incp.trustStore[string(id)]
	if !ok {
		return UnknownTrust, nil
	}

	return tl, nil
}

func (incp *InMemCertPool) IsRevoke(id []byte) error {
	revoked, ok := incp.revoked[string(id)]
	if !ok {
		return nil
	}

	if revoked {
		return ErrRevoked
	}

	return nil
}
