package cki

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"
)

// Ed25519Private wrapper of a Ed25519 pub/priv key
type Ed25519Private struct {
	pub, priv []byte
}

// Ed25519Public wrapper of Ed25519 public key
type Ed25519Public []byte

// GenerateEd25519Key generates a new Ed25519 based public/private key
func GenerateEd25519Key() (Ed25519Public, *Ed25519Private, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	privk := &Ed25519Private{
		pub:  pub,
		priv: priv,
	}

	return Ed25519Public(pub), privk, nil
}

// Bytes raw public key bytes
func (ed Ed25519Public) Bytes() ([]byte, error) {
	return ed, nil
}

// ParseED25519PublicKey decodes an ED25519 public key
func ParseED25519PublicKey(a Algorithm, d []byte) (Ed25519Public, error) {
	return Ed25519Public(d), nil
}

// Verify a signature using Ed25519 given the message and signature
func (ed Ed25519Public) Verify(msg, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(ed), msg, sig)
}

// parseED25519PrivateKey decodes an exported Ed25519 private key
func parseED25519PrivateKey(k *ocsPrivateKey) (*Ed25519Private, error) {
	priv := ed25519.PrivateKey(k.Key)
	pub := priv.Public().(ed25519.PublicKey)

	if len(priv) < ed25519.PrivateKeySize {
		return nil, errors.New("incorrect key size")
	}

	if len(pub) < ed25519.PublicKeySize {
		return nil, errors.New("incorrect public key size")
	}

	return &Ed25519Private{
		priv: priv,
		pub:  pub,
	}, nil
}

// Bytes raw private key bytes
func (ed *Ed25519Private) Bytes() ([]byte, error) {
	return ed.priv, nil
}

// Public provides the Ed25519 public key
func (ed *Ed25519Private) Public() PublicKey {
	return Ed25519Public(ed.pub)
}

// Sign a msg using the Ed25519 private key
func (ed *Ed25519Private) Sign(_ io.Reader, d []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig := ed25519.Sign(ed.priv, d)

	return sig, nil
}
