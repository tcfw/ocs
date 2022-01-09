package stl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tcfw/ocs/cki"
)

type CertificateType uint8

const (
	CertificateType_CKI CertificateType = iota
	CertificateType_X509
)

type CertificatePair struct {
	CertType    CertificateType
	Certificate [][]byte
	PrivateKey  crypto.PrivateKey
}

func LoadX509KeyPair(certFile, keyFile string) (CertificatePair, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return CertificatePair{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return CertificatePair{}, err
	}

	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (CertificatePair, error) {
	var cert CertificatePair

	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		return CertificatePair{}, errors.New("stl: failed to find any PEM data in certificate input")
	}

	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			return CertificatePair{}, errors.New("stl: failed to find PEM block with type ending in \"PRIVATE KEY\" in input")
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return CertificatePair{}, err
	}

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return CertificatePair{}, err
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return CertificatePair{}, errors.New("stl: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return CertificatePair{}, errors.New("stl: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return CertificatePair{}, errors.New("stl: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return CertificatePair{}, errors.New("stl: private key does not match public key")
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return CertificatePair{}, errors.New("stl: private key type does not match public key type")
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return CertificatePair{}, errors.New("stl: private key does not match public key")
		}
	default:
		return CertificatePair{}, errors.New("stl: unknown public key algorithm")
	}

	return cert, nil

}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("stl: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("stl: failed to parse private key")
}

func LoadCKIKeyPair(certFile, keyFile string) (CertificatePair, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return CertificatePair{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return CertificatePair{}, err
	}

	return CKIKeyPair(certPEMBlock, keyPEMBlock)
}

func CKIKeyPair(certPEMBlock, keyPEMBlock []byte) (CertificatePair, error) {
	var cert CertificatePair

	for {
		var certBlock *pem.Block
		certBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certBlock == nil {
			break
		}
		if certBlock.Type == cki.PEMCertHeader {
			cert.Certificate = append(cert.Certificate, certBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		return CertificatePair{}, errors.New("stl: failed to find any PEM data in certificate input")
	}

	var keyBlock *pem.Block
	for {
		keyBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyBlock == nil {
			return CertificatePair{}, errors.New("stl: failed to find PEM block with type ending in \"PRIVATE KEY\" in input")
		}
		if keyBlock.Type == cki.PEMPrivKeyHeader {
			break
		}
	}

	ckiCert, err := cki.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return CertificatePair{}, err
	}

	ckiKey, err := cki.ParsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return CertificatePair{}, err
	}

	cert.PrivateKey = ckiKey

	pubk, _ := ckiCert.GetPublicKey()
	publicKeyBytes, err := pubk.Bytes()
	if err != nil {
		return CertificatePair{}, err
	}

	privPubKeyBytes, err := ckiKey.Public().Bytes()
	if err != nil {
		return CertificatePair{}, err
	}

	if !bytes.Equal(privPubKeyBytes, publicKeyBytes) {
		return CertificatePair{}, errors.New("stl: private key does not match public key")
	}

	return cert, nil
}

func makeCertificateExtensions(c CertificatePair, verifyData []byte, rand io.Reader) ([]Extension, error) {
	exts := make([]Extension, 0, len(c.Certificate))

	for i, cert := range c.Certificate {

		ext := Extension{
			ExtType: ExtensionType_Certificate,
		}

		cert := &Certificate{
			CertificateType: c.CertType,
			Certificate:     cert,
		}

		if i == 0 {
			vd, err := makeCertVerifySig(c.PrivateKey, verifyData, rand)
			if err != nil {
				return nil, err
			}
			cert.Verify = vd
		}

		b, err := cert.Marshal()
		if err != nil {
			return nil, err
		}

		ext.Data = b

		exts = append(exts, ext)
	}

	return exts, nil
}

func makeCertVerifySig(p crypto.PrivateKey, data []byte, rand io.Reader) ([]byte, error) {
	h := sha512.Sum384(data)

	switch t := p.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand, p.(*rsa.PrivateKey), crypto.SHA384, h[:])
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand, p.(*ecdsa.PrivateKey), h[:])
	case ed25519.PrivateKey:
		sig := ed25519.Sign(p.(ed25519.PrivateKey), h[:])
		return sig, nil
	case cki.PrivateKey:
		return p.(cki.PrivateKey).Sign(rand, h[:], nil)
	default:
		return nil, fmt.Errorf("unsupported private key type %T", t)
	}
}

func verifyHostname(c *Certificate, h string) error {
	switch c.CertificateType {
	case CertificateType_X509:
		return verifyX509Hostname(c, h)
	case CertificateType_CKI:
		return verifyCKIHostname(c, h)
	default:
		return errors.New("unknown certificate type")
	}
}

func verifyX509Hostname(c *Certificate, h string) error {
	cert, err := x509.ParseCertificate(c.Certificate)
	if err != nil {
		return err
	}

	return cert.VerifyHostname(h)
}

func verifyCKIHostname(c *Certificate, h string) error {
	cert, err := cki.ParseCertificate(c.Certificate)
	if err != nil {
		return err
	}

	return cki.MatchesSubject(cert, h)
}

func verifyCertSignature(c *Certificate, data []byte) error {
	switch c.CertificateType {
	case CertificateType_X509:
		return verifyX509Signature(c, data)
	case CertificateType_CKI:
		return verifyCKISignature(c, data)
	default:
		return errors.New("unknown certificate type")
	}
}

func verifyCKISignature(c *Certificate, data []byte) error {
	cert, err := cki.ParseCertificate(c.Certificate)
	if err != nil {
		return err
	}

	pk, err := cert.GetPublicKey()
	if err != nil {
		return err
	}

	h := sha512.Sum384(data)

	if ok := pk.Verify(h[:], c.Verify); !ok {
		return errors.New("stl: invalid cki certificate signature")
	}

	return nil
}

func verifyX509Signature(c *Certificate, data []byte) error {
	cert, err := x509.ParseCertificate(c.Certificate)
	if err != nil {
		return err
	}

	h := sha512.Sum384(data)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA384, h[:], c.Verify)
	case *ecdsa.PublicKey:
		ok := ecdsa.VerifyASN1(pub, h[:], c.Verify)
		if !ok {
			return errors.New("stl: invalid ecdsa signature")
		}
	case ed25519.PublicKey:
		ok := ed25519.Verify(pub, h[:], c.Verify)
		if !ok {
			return errors.New("stl: invalid ed25519 signature")
		}
	default:
		return fmt.Errorf("stl: unknown public key algorithm %T", pub)
	}

	return nil
}

func verifyCKIChain(c *Config, s *Certificate, a []*Certificate) error {
	escp := &extendedSystemCertPool{
		systemPool: cki.SystemRootsPool(),
		interms:    make(map[string]*cki.Certificate, len(a)),
	}

	cert, err := cki.ParseCertificate(s.Certificate)
	if err != nil {
		return err
	}

	for _, ic := range a {
		c, err := cki.ParseCertificate(ic.Certificate)
		if err != nil {
			return err
		}
		escp.interms[string(c.ID)] = c
	}

	return cert.Verify(escp)
}

type extendedSystemCertPool struct {
	systemPool cki.CertPool
	interms    map[string]*cki.Certificate
}

func (escp *extendedSystemCertPool) FindCertificate(id, ref []byte) (*cki.Certificate, error) {
	interm, ok := escp.interms[string(id)]
	if ok {
		return interm, nil
	}

	return escp.systemPool.FindCertificate(id, ref)
}

func (escp *extendedSystemCertPool) TrustLevel(id []byte) (cki.TrustLevel, error) {
	cert, err := escp.systemPool.FindCertificate(id, nil)
	if err == nil && cert != nil {
		return escp.TrustLevel(id)
	}

	return cki.UnknownTrust, nil
}

func (escp *extendedSystemCertPool) IsRevoked(id []byte) error {
	return nil
}

func verifyX509Chain(c *Config, s *Certificate, a []*Certificate) error {
	cert, err := x509.ParseCertificate(s.Certificate)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{}

	for _, ap := range a {
		ac, err := x509.ParseCertificate(ap.Certificate)
		if err != nil {
			return err
		}
		opts.Intermediates.AddCert(ac)
	}

	for _, r := range c.RootCertificates {
		rc, err := x509.ParseCertificate(r.Certificate)
		if err != nil {
			return err
		}
		opts.Roots.AddCert(rc)
	}

	_, err = cert.Verify(opts)

	return err
}
