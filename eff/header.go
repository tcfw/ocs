package eff

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/tcfw/ocs/cki"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/sha3"
)

var (
	ErrInvalidHeader          = errors.New("invalid header")
	ErrInvalidPublicKey       = errors.New("invalid public key")
	ErrBadSignature           = errors.New("bad signature")
	ErrBadCertificate         = errors.New("bad certificiate")
	ErrNoMatchingCertificates = errors.New("no matching certificates")
)

//Header representation of a OCS EPF Header
type Header struct {
	Version               uint8         `msgpack:"v"`
	Algo                  Algorithm     `msgpack:"a"`
	CertificateID         []byte        `msgpack:"c"`
	Signature             []byte        `msgpack:"s"`
	IntendedCertificateID []byte        `msgpack:"i"`
	EphemeralAlgo         cki.Algorithm `msgpack:"ea"`
	EphemeralPublicKey    []byte        `msgpack:"ek"`
	EphemeralKDFSalt      []byte        `msgpack:"es"`
	Certificates          [][]byte      `msgpack:"ac,omitempty"`
	// PasswordProtected     bool          `msgpack:"p"`
	// PasswordAlgo          Algorithm     `msgpack:"pa"`

	sigCert   *cki.Certificate
	intCert   *cki.Certificate
	publicKey cki.PublicKey
	empPriv   *cki.SecpPrivateKey
}

//ParseHeader unmarshals in a msgpack encoded header
func ParseHeader(d []byte) (*Header, error) {
	h := &Header{}
	err := msgpack.Unmarshal(d, h)
	if err != nil {
		return nil, err
	}

	err = h.validate()
	if err != nil {
		return nil, err
	}

	return h, nil
}

//validate header validity over individual properties
func (h *Header) validate() (err error) {
	if h.Version != 1 {
		return ErrInvalidHeader
	}

	if h.Algo == UnknownAlgo || h.Algo > maxAlgo {
		return ErrInvalidHeader
	}

	if len(h.CertificateID) != 32 {
		return ErrInvalidHeader
	}

	if len(h.Signature) == 0 {
		return ErrInvalidHeader
	}

	if h.EphemeralAlgo != cki.UnknownAlgo && len(h.EphemeralPublicKey) == 0 {
		return ErrInvalidHeader
	}

	h.publicKey, err = cki.ParsePublicKey(h.EphemeralAlgo, h.EphemeralPublicKey)
	if err != nil {
		return ErrInvalidPublicKey
	}

	for _, cert := range h.Certificates {
		_, err := cki.ParseCertificate(cert)
		if err != nil {
			return ErrInvalidHeader
		}
	}

	// if h.PasswordProtected && h.PasswordAlgo == UnknownAlgo {
	// 	return ErrInvalidHeader
	// }

	return nil
}

//NewHeader creates a new header and ephemeral key using a designated signing key (from) and
//an intended recipient key (to)
func NewHeader(sigCert, intendedCert *cki.Certificate) (*Header, cki.PrivateKey, error) {
	if intendedCert.Algo == cki.RSA2048 || intendedCert.Algo == cki.RSA4096 {
		return nil, nil, ErrInvalidAlgo
	}

	pk, hdopt, err := WithEphemeral(intendedCert.Algo)

	h, err := NewHeaderWithOptions(sigCert, intendedCert, hdopt)
	if err != nil {
		return nil, nil, err
	}

	return h, pk, nil
}

//NewHeaderWithOptions creates a new header with a specific set of options applied using a
//designated signing key (from) and an intended recipient key (to)
func NewHeaderWithOptions(sigCert, intendedCert *cki.Certificate, options ...HeaderOption) (*Header, error) {
	h := &Header{
		Version:               1,
		Algo:                  ChaCha20_Poly1305,
		CertificateID:         sigCert.ID,
		IntendedCertificateID: intendedCert.ID,

		sigCert: sigCert,
		intCert: intendedCert,
	}

	for _, opt := range options {
		if err := opt(h); err != nil {
			return nil, err
		}
	}

	if h.empPriv == nil || h.publicKey == nil || len(h.EphemeralPublicKey) == 0 {
		if intendedCert.Algo == cki.RSA2048 || intendedCert.Algo == cki.RSA4096 {
			return nil, ErrInvalidAlgo
		}

		empAlgo := intendedCert.Algo

		empPub, empPriv, err := cki.GenerateECKey(empAlgo)
		if err != nil {
			return nil, err
		}

		empPubBytes, err := empPub.Bytes()
		if err != nil {
			return nil, err
		}
		h.EphemeralAlgo = empAlgo
		h.EphemeralPublicKey = empPubBytes
		h.publicKey = empPub
		h.empPriv = empPriv
	}

	return h, nil
}

//Bytes encodes the header to msgpack
func (h *Header) Bytes() ([]byte, error) {
	return msgpack.Marshal(h)
}

//Encrypt creates cipher text based on the signing private key and plain text
func (h *Header) Encrypt(cp cki.CertPool, pk cki.PrivateKey, d []byte) ([]byte, error) {
	if err := h.sign(pk, d); err != nil {
		return nil, err
	}

	//Create shared key
	sk, err := h.sharedKey(cp, h.empPriv, true)
	if err != nil {
		return nil, err
	}

	aead, err := algoToAEAD(h.Algo, sk)
	if err != nil {
		return nil, err
	}

	nonceLen := aead.NonceSize()

	ct := make([]byte, nonceLen+len(d)+aead.Overhead())

	n, err := rand.Read(ct[:nonceLen])
	if err != nil || n != nonceLen {
		return nil, fmt.Errorf("failed to create nonce: %s", err)
	}

	aad, err := h.Bytes()
	if err != nil {
		return nil, err
	}

	ct = aead.Seal(ct[:nonceLen], ct[:nonceLen], d, aad)

	return ct, nil
}

//sign creates a digest of the plain text and signs it with a given CKI private key
func (h *Header) sign(pk cki.PrivateKey, d []byte) error {
	digest := sha3.Sum384(d)

	s, err := pk.Sign(digest[:])
	if err != nil {
		return err
	}
	h.Signature = s

	return nil
}

//Decrypt deciphers the given data using the private key of the intended certificate. sending is available
//if the sender wants to decypher their own message
func (h *Header) Decrypt(cp cki.CertPool, priv cki.PrivateKey, d []byte, sending bool) ([]byte, error) {
	sk, err := h.sharedKey(cp, priv, sending)
	if err != nil {
		return nil, err
	}

	aead, err := algoToAEAD(h.Algo, sk)
	if err != nil {
		return nil, err
	}

	nonceLen := aead.NonceSize()

	aad, err := h.Bytes()
	if err != nil {
		return nil, err
	}

	pt, err := aead.Open(d[:nonceLen], d[:nonceLen], d[nonceLen:], aad)
	if err != nil {
		return nil, err
	}

	plainText := pt[nonceLen:]

	err = h.verifySignature(cp, plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

//verifySignature validates the signature of a header against the signing certificate
func (h *Header) verifySignature(cp cki.CertPool, d []byte) error {
	digest := sha3.Sum384(d)

	if h.sigCert == nil {
		c, err := h.findCert(cp, h.IntendedCertificateID)
		if err != nil {
			return err
		}
		h.sigCert = c
	}

	pk, err := h.sigCert.GetPublicKey()
	if err != nil {
		return err
	}

	if !pk.Verify(digest[:], h.Signature) {
		return ErrBadSignature
	}

	return nil
}

//sharedKey creates a new shared key based off the private key of either party
//TODO(tcfw): check that priv matches h.IntentedCertificate(ID) - will be picked up by sk+aead
func (h *Header) sharedKey(cp cki.CertPool, priv cki.PrivateKey, sending bool) ([]byte, error) {
	ecpriv, ok := priv.(*cki.SecpPrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type")
	}

	//Get signing certificate
	if h.sigCert == nil {
		cert, err := h.findCert(cp, h.CertificateID)
		if err != nil {
			return nil, err
		}
		h.sigCert = cert
	}

	if h.intCert == nil {
		cert, err := h.findCert(cp, h.IntendedCertificateID)
		if err != nil {
			return nil, err
		}
		h.intCert = cert
	}

	if h.sigCert == nil || h.intCert == nil { //shouldnt happen
		return nil, ErrNoMatchingCertificates
	}

	skpk := h.EphemeralPublicKey

	if sending {
		skpk = h.intCert.PublicKey
	}

	//Recover shared key
	pk, err := cki.ParsePublicKey(h.EphemeralAlgo, skpk)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	if _, ok := pk.(*cki.RSAPublicKey); ok {
		//Randomly generate key and encrypt with public key
		return nil, ErrInvalidPublicKey
	}

	if h.EphemeralAlgo == cki.ED25519 {
		//TODO(tcfw): convert to X25519 curve
		return nil, fmt.Errorf("unsupported ephemeral key")
	}

	ecpk, ok := pk.(*cki.SecpPublicKey)
	if !ok {
		return nil, ErrInvalidPublicKey
	}

	sk, salt, err := ecdheSharedKey(ecpk, ecpriv, h.EphemeralKDFSalt, 32)
	if err != nil {
		return nil, err
	}

	h.EphemeralKDFSalt = salt

	return sk, nil
}

//findCert attempts to find a certificate given an idea either embedded in the header, or in the given
//CKI cert pool
func (h *Header) findCert(cp cki.CertPool, id []byte) (*cki.Certificate, error) {
	var wanted *cki.Certificate

	//Check embedded first
	for _, c := range h.Certificates {
		cert, err := cki.ParseCertificate(c)
		if err != nil {
			return nil, ErrBadCertificate
		}
		if bytes.Compare(cert.ID, id) == 0 {
			wanted = cert
		}
	}

	//Check cert pool
	if wanted == nil {
		cert, err := cp.FindCertificate(id, nil)
		if err != nil {
			return nil, err
		}
		if bytes.Compare(id, cert.ID) == 0 {
			wanted = cert
		}
	}

	if wanted == nil {
		return nil, ErrNoMatchingCertificates
	}

	return wanted, nil
}
