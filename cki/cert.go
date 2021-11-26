package cki

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/sha3"
)

var (
	//ErrAlreadySigned already signed by this key
	ErrAlreadySigned = errors.New("already signed by this key")
	//ErrNoMatchingSignatures no matching signatures
	ErrNoMatchingSignatures = errors.New("no matching signatures")
	//ErrTooManySignatures too many signatures
	ErrTooManySignatures = errors.New("too many signatures")
	//ErrUnknownPEMType unknown PEM block header type
	ErrUnknownPEMType = errors.New("unknown PEM block header type")
)

const (
	//PEMCertHeader PEM block header for certificates
	PEMCertHeader = "OCS CERTIFICATE"
	//PEMPrivKeyHeader PEM block header for private keys
	PEMPrivKeyHeader = "OCS PRIVATE KEY"
	//PEMEncPrivKeyHeader PEM block header for encrypted private keys
	PEMEncPrivKeyHeader = "OCS ENCRYPTED PRIVATE KEY"
)

//CertificateType the type of certificate chain verifying/signing infrastructure
type CertificateType uint8

const (
	//UnknownCertType unknown or not set
	UnknownCertType CertificateType = iota
	//PKI general single CA
	PKI
	//WOT Web of trust
	WOT
	//MultiPKI multiple CAs
	MultiPKI

	certTypeMax
)

//Entity provides personal or businses information in
//the certificate
type Entity struct {
	Name     string `msgpack:"o,omitempty"`
	Unit     string `msgpack:"ou,omitempty"`
	Locality string `msgpack:"l,omitempty"`
	State    string `msgpack:"st,omitempty"`
	Country  string `msgpack:"c,omitempty"`
	Email    string `msgpack:"e,omitempty"`
}

//Signature signatures provided by peers or CAs
type Signature struct {
	ID        []byte    `msgpack:"c"`
	Algo      Algorithm `msgpack:"a"`
	Signature []byte    `msgpack:"s"`
	PublicRef []byte    `msgpack:"p,omitempty"`
}

//Certificate an OCS certificate representation
type Certificate struct {
	Raw        []byte          `msgpack:"-"`
	Version    uint8           `msgpack:"v"`
	CertType   CertificateType `msgpack:"t"`
	Algo       Algorithm       `msgpack:"a"`
	ID         []byte          `msgpack:"c"`
	IsCA       bool            `msgpack:"ca,omitempty"`
	PublicKey  []byte          `msgpack:"pk"`
	NotBefore  time.Time       `msgpack:"nb"`
	NotAfter   time.Time       `msgpack:"na"`
	Revoke     bool            `msgpack:"r,omitempty"`
	Subject    string          `msgpack:"sb"`
	Entity     *Entity         `msgpack:"e,omitempty"`
	Signatures []Signature     `msgpack:"s"`
	Extensions []Extension     `msgpack:"x,omitempty"`

	publicKey PublicKey
}

//NewCertificate generates a new OCS certificate based on a template, a public certificate and a signing private certificate
//
//The following template fields are preserved:
//
//  - Subject
//  - Entity and all child values
//  - Revoked
//  - NotAfter if is not zero and is not over 365 days in the future from the current time
func NewCertificate(template Certificate, pub PublicKey, issuer *Certificate, priv PrivateKey) (*Certificate, error) {
	template.Raw = nil

	template.Version = 1
	if template.NotBefore.Before(time.Now()) {
		template.NotBefore = time.Now()
	}

	if len(template.Signatures) != 0 {
		return nil, ErrAlreadySigned
	}

	if template.NotAfter.After(time.Now().Add(10 * 365 * 24 * time.Hour)) {
		return nil, fmt.Errorf("not-after too far in the future")
	}

	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}

	if template.NotBefore.After(template.NotAfter) {
		return nil, fmt.Errorf("not-before cannot be after not-after")
	}

	if template.CertType == 0 {
		template.CertType = MultiPKI
	}

	template.publicKey = pub

	pubCert, err := pub.Bytes()
	if err != nil {
		return nil, err
	}

	template.PublicKey = pubCert
	template.Algo = pubAlgo(pub)

	template.ID = make([]byte, 32)
	n, err := rand.Read(template.ID)
	if err != nil || n != 32 {
		return nil, errors.New("failed to generate certificate ID")
	}

	if issuer == nil {
		issuer = &template
	}

	err = template.AddSignature(issuer, priv, nil)
	if err != nil {
		return nil, err
	}

	if err := template.finalise(); err != nil {
		return nil, err
	}

	return &template, nil
}

//ParseCertificate decodes a msgpack encoded certificate
func ParseCertificate(d []byte) (*Certificate, error) {
	cert := &Certificate{}

	err := msgpack.Unmarshal(d, cert)
	if err != nil {
		return nil, err
	}

	pk, err := ParsePublicKey(cert.Algo, cert.PublicKey)
	if err != nil {
		return nil, err
	}

	if err := cert.finalise(); err != nil {
		return nil, err
	}

	cert.publicKey = pk

	err = cert.validate()
	if err != nil {
		return nil, err
	}

	return cert, nil
}

//ParsePEMCertificate parses a certificate from a PEM block format
func ParsePEMCertificate(d []byte) (*Certificate, []byte, error) {
	block, rest := pem.Decode(d)
	if block.Type != PEMCertHeader {
		return nil, nil, ErrUnknownPEMType
	}

	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, rest, nil
}

//Bytes provides a raw msgpack encoded certificate
func (cert *Certificate) Bytes() ([]byte, error) {
	if len(cert.Raw) == 0 {
		_, err := cert.Marshal()
		if err != nil {
			return nil, err
		}
	}

	return cert.Raw, nil
}

//validate checks required properties of the certificate
func (cert *Certificate) validate() error {
	if cert.Version != 1 {
		return errors.New("invalid version")
	}

	if cert.NotBefore.After(time.Now()) {
		return errors.New("invalid notBefore: must be before now")
	}

	if cert.NotAfter.Before(time.Now()) {
		return errors.New("invalid notAfter: must be after now")
	}

	if cert.CertType == 0 || cert.CertType >= certTypeMax {
		return fmt.Errorf("invalid certType: %d", cert.CertType)
	}

	if cert.CertType == PKI && len(cert.Signatures) != 1 {
		return ErrTooManySignatures
	}

	if len(cert.PublicKey) == 0 {
		return errors.New("no public key")
	}

	if len(cert.Signatures) == 0 {
		return errors.New("no signatures")
	}

	for i, sig := range cert.Signatures {
		if sig.Algo == 0 || sig.Algo >= algoMax {
			return fmt.Errorf("invalid algo %d in signature %d", sig.Algo, i)
		}

		if len(sig.ID) == 0 {
			return fmt.Errorf("invalid cert ID in signature %d", i)
		}

		if len(sig.Signature) == 0 {
			return fmt.Errorf("invalid signature value in signature %d", i)
		}
	}

	return nil
}

func (cert *Certificate) finalise() error {
	raw, err := cert.Bytes()
	if err != nil {
		return err
	}

	cert.Raw = raw
	return nil
}

//AddSignature adds a new signature to the certificate
func (cert *Certificate) AddSignature(issuer *Certificate, privk PrivateKey, pubRef []byte) error {
	issuerID := issuer.ID

	for _, prevSig := range cert.Signatures {
		if bytes.Equal(prevSig.ID, issuerID) {
			return ErrAlreadySigned
		}
	}

	//Sign specific parts of the certificate - i.e. other signatures should not be part of the signature
	sigInfo, err := cert.marshalForSignature(issuer.ID)
	if err != nil {
		return fmt.Errorf("failed to prepare signature data: %s", err)
	}

	signature, err := privk.Sign(rand.Reader, sigInfo, nil)
	if err != nil {
		return fmt.Errorf("failed to sign certificate: %s", err)
	}

	sigType := privKeyAlgo(privk)

	cert.Signatures = append(cert.Signatures, Signature{
		ID:        issuerID,
		Algo:      sigType,
		Signature: signature,
	})

	if err := cert.finalise(); err != nil {
		return err
	}

	return nil
}

//Marshal returns the certificate in msgpack encoding
func (cert *Certificate) Marshal() ([]byte, error) {
	raw, err := msgpack.Marshal(cert)
	if err != nil {
		return nil, err
	}

	cert.Raw = raw

	return cert.Raw, nil
}

//PEM encodes the certificate and the returned slice in a PEM block encoding
func (cert *Certificate) PEM() ([]byte, error) {
	data, err := cert.Marshal()
	if err != nil {
		return nil, err
	}

	b := &pem.Block{
		Type:  PEMCertHeader,
		Bytes: data,
	}

	return pem.EncodeToMemory(b), nil
}

//marshalForSignature creates a digest of the required fields of the certificate to be used
//when creating signatures
func (cert *Certificate) marshalForSignature(pkID []byte) ([]byte, error) {
	d, err := msgpack.Marshal(
		Certificate{
			ID:         cert.ID,
			Version:    cert.Version,
			Revoke:     cert.Revoke,
			Algo:       cert.Algo,
			PublicKey:  cert.PublicKey,
			Subject:    cert.Subject,
			NotBefore:  cert.NotBefore,
			NotAfter:   cert.NotAfter,
			CertType:   cert.CertType,
			Entity:     cert.Entity,
			Extensions: cert.Extensions,
		})
	if err != nil {
		return nil, err
	}

	//Append signing key id
	d = append(d, pkID...)

	digest := sha3.Sum384(d)

	return digest[:], nil
}

//verifySignatureMatching checks if any of the signatures in the certficiate match the given
//public key - returning on the first match
func (cert *Certificate) verifySignatureMatching(pkID []byte, pubk PublicKey) error {
	sigInfo, err := cert.marshalForSignature(pkID)
	if err != nil {
		return err
	}

	for _, sig := range cert.Signatures {
		if pubk.Verify(sigInfo, sig.Signature) {
			return nil
		}
	}

	return ErrNoMatchingSignatures
}

//verifySignatureOnly verifies the only 1 signature exists and that that signature matches
//the given public key
func (cert *Certificate) verifySignatureOnly(pkID []byte, pubk PublicKey) error {
	sigCount := len(cert.Signatures)
	if sigCount > 1 || sigCount == 0 {
		return ErrTooManySignatures
	}

	sigInfo, err := cert.marshalForSignature(pkID)
	if err != nil {
		return err
	}

	if pubk.Verify(sigInfo, cert.Signatures[0].Signature) {
		return nil
	}

	return ErrNoMatchingSignatures
}

//pubAlgo provides the algorithm used for the given public key
func pubAlgo(pub PublicKey) Algorithm {
	switch pubType := pub.(type) {
	case Ed25519Public:
		return ED25519
	case *SecpPublicKey:
		return pub.(*SecpPublicKey).algo
	case *RSAPublicKey:
		bits := pub.(*RSAPublicKey).PublicKey.Size() * 8
		if bits == 2048 {
			return RSA2048
		} else if bits == 4096 {
			return RSA4096
		} else {
			panic("unsupported RSA bit size")
		}
	default:
		panic(fmt.Sprintf("unknown public key algo: %s", pubType))
	}
}

//GetPublicKey provides a parsed version of the certificates public key
func (cert *Certificate) GetPublicKey() (PublicKey, error) {
	return cert.publicKey, nil
}

//privKeyAlgo provides the algorithm used for the private key
func privKeyAlgo(priv PrivateKey) Algorithm {
	switch privType := priv.(type) {
	case *Ed25519Private:
		return ED25519
	case *SecpPrivateKey:
		return priv.(*SecpPrivateKey).algo
	case *RSAPrivateKey:
		bits := priv.(*RSAPrivateKey).Size() * 8
		if bits == 2048 {
			return RSA2048
		} else if bits == 4096 {
			return RSA4096
		} else {
			panic("unsupported RSA bit size")
		}
	default:
		panic(fmt.Sprintf("unknown private key algo: %s", privType))
	}
}
