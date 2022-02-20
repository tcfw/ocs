package cki

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	certDirEnv = "SSL_CERT_DIR"
)

//TrustLevel represents a user specified or system level of trust on a certificste
type TrustLevel uint8

const (
	//UnknownTrust represents an unknown or incomplete state of trust
	UnknownTrust = iota
	//NotTrusted represents a explicitly untrusted certificate
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

var (
	once           sync.Once
	systemRoots    CertPool
	systemRootsErr error
)

func SystemRootsPool() CertPool {
	once.Do(initSystemRoots)
	return systemRoots
}

func initSystemRoots() {
	systemRoots, systemRootsErr = newSystemCertPool()
	if systemRootsErr != nil {
		systemRoots = nil
	}
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

// readUniqueDirectoryEntries is like os.ReadDir but omits
// symlinks that point within the directory.
func readUniqueDirectoryEntries(dir string) ([]fs.DirEntry, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	uniq := files[:0]
	for _, f := range files {
		if !isSameDirSymlink(f, dir) {
			uniq = append(uniq, f)
		}
	}
	return uniq, nil
}

// isSameDirSymlink reports whether fi in dir is a symlink with a
// target not containing a slash.
func isSameDirSymlink(f fs.DirEntry, dir string) bool {
	if f.Type()&fs.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(filepath.Join(dir, f.Name()))
	return err == nil && !strings.Contains(target, "/")
}

func NewIntermCertPool(parent CertPool, certs map[string]*Certificate) *IntermCertPool {
	if certs == nil {
		certs = make(map[string]*Certificate)
	}

	return &IntermCertPool{
		parentPool: parent,
		interms:    certs,
	}
}

type IntermCertPool struct {
	parentPool CertPool
	interms    map[string]*Certificate
}

func (escp *IntermCertPool) FindCertificate(id, ref []byte) (*Certificate, error) {
	interm, ok := escp.interms[string(id)]
	if ok {
		return interm, nil
	}

	return escp.parentPool.FindCertificate(id, ref)
}

func (escp *IntermCertPool) TrustLevel(id []byte) (TrustLevel, error) {
	cert, err := escp.parentPool.FindCertificate(id, nil)
	if err == nil && cert != nil {
		return escp.TrustLevel(id)
	}

	return UnknownTrust, nil
}

func (escp *IntermCertPool) IsRevoked(id []byte) error {
	return escp.parentPool.IsRevoked(id)
}

func (escp *IntermCertPool) AddCert(c *Certificate) {
	escp.interms[string(c.ID)] = c
}
