package cki

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
