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
	exts := make([]Extension, len(c.Certificate))

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
		return p.(cki.PrivateKey).Sign(rand, data, nil)
	default:
		return nil, fmt.Errorf("unsupported private key type %T", t)
	}
}
