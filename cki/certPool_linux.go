// +build linux

package cki

import (
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

var certificateDirectories = []string{
	"/etc/ocs/roots",
}

type SystemCertPool struct {
	certs map[string]*Certificate
}

var _ CertPool = (*SystemCertPool)(nil)

func newSystemCertPool() (*SystemCertPool, error) {
	scp := &SystemCertPool{}

	dirs := certificateDirectories
	if d := os.Getenv(certDirEnv); d != "" {
		dirs = strings.Split(d, ":")
	}

	for _, directory := range dirs {
		fis, err := readUniqueDirectoryEntries(directory)
		if err != nil {
			continue
		}
		for _, fi := range fis {
			data, err := os.ReadFile(directory + "/" + fi.Name())
			if err == nil {
				scp.AppendCertsFromPEM(data)
			}
		}
	}

	return scp, nil
}

func (scp *SystemCertPool) FindCertificate(id, _ []byte) (*Certificate, error) {
	cert, ok := scp.certs[string(id)]
	if !ok {
		return nil, errors.New("not found")
	}

	return cert, nil
}

//TrustLevel returns the level of trust associated with a certificate. Since these are read from the system,
//we assume that all certificates are at least trusted
func (scp *SystemCertPool) TrustLevel(id []byte) (TrustLevel, error) {
	return Trusted, nil
}

//IsRevoked checks if a certificate is revoked or not and returns an error if it is. Since these are read from
//the system, it is assumed no certificates are inherently revoked
func (scp *SystemCertPool) IsRevoked(id []byte) error {
	return nil
}

func (scp *SystemCertPool) AppendCertsFromPEM(pemCerts []byte) bool {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}

		if block.Type != PEMCertHeader || len(block.Headers) != 0 {
			continue
		}
		certBytes := block.Bytes
		cert, err := ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		scp.certs[string(cert.ID)] = cert
	}

	return true
}
