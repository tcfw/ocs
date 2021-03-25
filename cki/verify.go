package cki

import (
	"bytes"
	"errors"
)

var (
	ErrUntrustedCertificate = errors.New("certificate is not trusted")
	ErrRevoked              = errors.New("certificate has been marked as revoked")
)

func (c *Certificate) Verify(p CertPool) error {
	switch c.CertType {
	case PKI, MultiPKI:
		isMulti := c.CertType == MultiPKI
		return verifyPKI(c, p, isMulti)
	case WOT:
		return verifyWOT(c, p)
	default:
		return errors.New("unknown certType")
	}
}

func verifyPKI(c *Certificate, p CertPool, multi bool) error {
	if !multi && len(c.Signatures) != 1 {
		return ErrTooManySignatures
	}

	if err := p.IsRevoke(c.ID); err != nil {
		return ErrRevoked
	}

	tl, err := p.TrustLevel(c.ID)
	if err != nil {
		return err
	}
	if tl == NotTrusted {
		return ErrUntrustedCertificate
	}

	var hasTrustedChain bool

	for _, sig := range c.Signatures {
		//Skip self signed
		if bytes.Compare(sig.ID, c.ID) == 0 {
			err = c.verifySignatureOnly(sig.ID, c.publicKey)
			if err != nil {
				return err
			}

			//Assumed root
			tl, err = p.TrustLevel(c.ID)
			if err != nil {
				return err
			}
			if tl < Trusted {
				return ErrUntrustedCertificate
			}

			continue
		}

		parent, err := p.FindCertificate(sig.ID, sig.PublicRef)
		if err != nil {
			return err
		}

		err = c.verifySignatureOnly(parent.ID, parent.publicKey)
		if err != nil {
			return err
		}

		if err := p.IsRevoke(parent.ID); err != nil {
			return ErrRevoked
		}

		if !parent.IsCA {
			return errors.New("parent certificate is not a CA")
		}

		err = verifyPKI(parent, p, multi)
		if err != nil {
			if err == ErrUntrustedCertificate {
				tl, err := p.TrustLevel(c.ID)
				if err != nil {
					return err
				}
				if tl > IndirectlyTrusted || multi {
					continue
				}
			}
			return err
		}

		if multi {
			hasTrustedChain = true
		}
	}

	if multi && !hasTrustedChain {
		return ErrUntrustedCertificate
	}

	return nil
}

func verifyWOT(c *Certificate, p CertPool) error {
	return nil
}
