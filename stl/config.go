package stl

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"time"

	"github.com/tcfw/ocs/cki"
)

var (
	errNoCertificate = errors.New("stl: no certificate provided")
)

type Config struct {
	Hostname       string
	HostnameMode   HostnameType
	PreferredCurve HandshakeSuite
	NextProto      string

	Certificates   []CertificatePair
	ClientAuth     bool
	ClientCAPool   cki.CertPool
	GetCertificate func(*InitHello) (*CertificatePair, error)

	AllowedTimeDiff time.Duration

	Rand io.Reader
	Time func() time.Time

	SkipCertificateVerification bool
	RootCertificates            []*Certificate
}

func defaultConfig() *Config {
	return &Config{
		PreferredCurve:  ECDHE_x25519,
		HostnameMode:    HostnameType_DNS,
		AllowedTimeDiff: 5 * time.Second,
	}
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	if c.Time == nil {
		return time.Now()
	}
	return c.Time()
}

func (c *Config) getCertificate(ih *ResponseHelloState) (*CertificatePair, error) {
	if c.GetCertificate != nil && len(c.Certificates) == 0 {
		cert, err := c.GetCertificate(ih.initial)
		if err != nil && cert != nil {
			return cert, nil
		}
	}

	if len(c.Certificates) == 0 {
		return nil, errNoCertificate
	}

	if len(c.Certificates) == 1 {
		return &c.Certificates[0], nil
	}

	for _, cert := range c.Certificates {
		switch cert.CertType {
		case CertificateType_X509:
			cx, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, err
			}
			err = cx.VerifyHostname(string(ih.hostname))
			if err == nil {
				return &cert, nil
			}
		case CertificateType_CKI:
			cx, err := cki.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, err
			}

			err = cki.MatchesSubject(cx, string(ih.hostname))
			if err == nil {
				return &cert, nil
			}
		}
	}

	return &c.Certificates[0], nil
}
