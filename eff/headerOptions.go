package eff

import "github.com/tcfw/ocs/cki"

//HeaderOption header creation option
type HeaderOption func(*Header) error

//WithEncryptionAlgo specifies which encryption (AEAD) algorithm to use
func WithEncryptionAlgo(a Algorithm) HeaderOption {
	return func(h *Header) error {
		h.Algo = a
		return nil
	}
}

//WithEphemeral creates a new ephemeral key pair based off the given algorithm
func WithEphemeral(a cki.Algorithm) (cki.PrivateKey, HeaderOption, error) {
	var pub cki.PublicKey
	var priv *cki.SecpPrivateKey
	var err error

	switch a {
	case cki.RSA2048, cki.RSA4096:
		return nil, nil, ErrInvalidAlgo
	case cki.ED25519:
		return nil, nil, ErrInvalidAlgo
	default:
		pub, priv, err = cki.GenerateECKey(a)
		if err != nil {
			return nil, nil, err
		}
	}

	pubBytes, err := pub.Bytes()
	if err != nil {
		return nil, nil, err
	}

	fn := func(h *Header) error {
		h.EphemeralAlgo = a
		h.EphemeralPublicKey = pubBytes
		h.empPriv = priv
		h.publicKey = pub

		return nil
	}

	return priv, fn, nil
}

//WithEmbeddedCerts specifies which certificates to include in the header
//certificates are parsed to ensure validity
func WithEmbeddedCerts(c ...*cki.Certificate) HeaderOption {
	return func(h *Header) error {
		if h.Certificates == nil {
			h.Certificates = [][]byte{}
		}

		for _, cert := range c {
			sigCertBytes, err := cert.Bytes()
			if err != nil {
				return err
			}

			h.Certificates = append(h.Certificates, sigCertBytes)
		}

		return nil
	}
}
