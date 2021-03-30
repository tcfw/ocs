package cki

import "errors"

//TrustLevel represents a user specified or system level of trust on a certificste
type TrustLevel uint8

const (
	//UnknownTrust represents an unknown or incomplete state of trust
	UnknownTrust = iota
	//NotTrusted represents a explicity untrusted certificate
	NotTrusted
	//IndirectlyTrusted represents a certificate which is not immediate trusted, but is trusted by another certificate the system trusts (WOT)
	IndirectlyTrusted
	//Trusted represents a certificate the system trusts, but not a certificate the immediate system created
	Trusted
	//UltimatelyTrusted represents a certificate the system that the local system has created
	UltimatelyTrusted
)

//CertFinder finds certificates from IDs
type CertFinder interface {
	FindCertificate(id, ref []byte) (*Certificate, error)
}

//CertTrustStore provides system trust levels on a given certificate by ID
type CertTrustStore interface {
	TrustLevel(id []byte) (TrustLevel, error)
}

//CertRevokeChecker checks if a certificate is revoked by ID
type CertRevokeChecker interface {
	IsRevoked(id []byte) error
}

//CertPool provides a means of validating certificates
type CertPool interface {
	CertFinder
	CertTrustStore
	CertRevokeChecker
}

//InMemCertPool an in-memory certificate pool useful for tests
type InMemCertPool struct {
	certStore  map[string]*Certificate
	trustStore map[string]TrustLevel
	revoked    map[string]bool
}

//NewInMemCertPool inits a new in-memory cert pool
func NewInMemCertPool() *InMemCertPool {
	return &InMemCertPool{
		certStore:  make(map[string]*Certificate),
		trustStore: make(map[string]TrustLevel),
		revoked:    make(map[string]bool),
	}
}

//Reset clears all stored certificates, revokes and trust levels
func (incp *InMemCertPool) Reset() {
	incp.certStore = make(map[string]*Certificate)
	incp.trustStore = make(map[string]TrustLevel)
	incp.revoked = make(map[string]bool)
}

//AddCert adds a certificate to the pool with an associated trust level
func (incp *InMemCertPool) AddCert(c *Certificate, t TrustLevel) {
	incp.certStore[string(c.ID)] = c
	incp.trustStore[string(c.ID)] = t
}

//Revoke adds a certificate to the revoked list
func (incp *InMemCertPool) Revoke(c *Certificate) {
	incp.revoked[string(c.ID)] = true
}

//FindCertificate provides the certificate for an ID in the pool
func (incp *InMemCertPool) FindCertificate(id, _ []byte) (*Certificate, error) {
	cert, ok := incp.certStore[string(id)]
	if !ok {
		return nil, errors.New("not found")
	}

	return cert, nil
}

//TrustLevel provides the trust level of a stored certificate. If the certificate is
//not in the pool, it will have an unknown trust level
func (incp *InMemCertPool) TrustLevel(id []byte) (TrustLevel, error) {
	tl, ok := incp.trustStore[string(id)]
	if !ok {
		return UnknownTrust, nil
	}

	return tl, nil
}

//IsRevoked checks if a certificate has been revoked
func (incp *InMemCertPool) IsRevoked(id []byte) error {
	revoked, ok := incp.revoked[string(id)]
	if !ok {
		return nil
	}

	if revoked {
		return ErrRevoked
	}

	return nil
}
