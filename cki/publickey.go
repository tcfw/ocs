package cki

import (
	"crypto"
	"errors"
)

// PublicKey an OCS compatible public key
type PublicKey interface {
	crypto.PublicKey

	Verify(msg []byte, sig []byte) bool
	Bytes() ([]byte, error)
}

// ParsePublicKey unmarshals a public key
func ParsePublicKey(a Algorithm, d []byte) (PublicKey, error) {
	if len(d) == 0 {
		return nil, errors.New("empty public key")
	}

	switch a {
	case ED25519:
		return ParseED25519PublicKey(a, d)
	case ECDSAsecp256r1, ECDSAsecp384r1:
		return ParseECPublicKey(a, d)
	case RSA2048, RSA4096:
		return ParseRSAPublicKey(a, d)
	case CRYSTALSDilithium2, CRYSTALSDilithium3, CRYSTALSDilithium5:
		return parseCRYSTALSDilithiumPublicKey(a, d)
	default:
		return nil, ErrUnknownKeyAlgorithm
	}
}
