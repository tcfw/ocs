package cki

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

var (
	//ErrUntrustedCertificate when a certificate is untrusted explicitly
	ErrUntrustedCertificate = errors.New("certificate is not trusted")
	//ErrRevoked when a certificate either immediately or in the chain is revoked
	ErrRevoked = errors.New("certificate has been marked as revoked")
)

//Verify verifies the certificates signators over a given cert pool
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

//verifyPKI verifies both Multi-PKI and single PKI requiring the signator to have a trust
//level of a least Trusted. Revoked certificates are rejected
func verifyPKI(c *Certificate, p CertPool, multi bool) error {
	if !multi && len(c.Signatures) != 1 {
		return ErrTooManySignatures
	}

	if err := p.IsRevoked(c.ID); err != nil {
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
		if bytes.Equal(sig.ID, c.ID) {
			err = c.VerifySignatureOnly(sig.ID, c.publicKey)
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

		err = c.VerifySignatureOnly(parent.ID, parent.publicKey)
		if err != nil {
			return err
		}

		if err := p.IsRevoked(parent.ID); err != nil {
			return ErrRevoked
		}

		if !parent.IsCA {
			return errors.New("cki: parent certificate is not a CA")
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

//verifyWOT TODO(tcfw)
func verifyWOT(c *Certificate, p CertPool) error {
	return fmt.Errorf("cki: WOT verification currently not implemented")
}

func MatchesSubject(c *Certificate, s string) error {
	subjects := []string{c.Subject}

	for _, ext := range c.Extensions {
		if ext.Type == AdditionalSubject {
			subjects = append(subjects, string(ext.Data))
		}
	}

	matchHost := validHostname(s, false)

	for _, subject := range subjects {
		if matchHost && validHostname(subject, true) && matchesPattern(subject, s) {
			return nil
		} else {
			if s == subject {
				return nil
			}
		}
	}

	return fmt.Errorf("cki: no match found for hostname %s", s)
}

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
func validHostname(host string, isPattern bool) bool {
	if !isPattern {
		host = strings.TrimSuffix(host, ".")
	}
	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if isPattern && i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behaviour.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' {
				// Not a valid character in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

func matchesPattern(pattern, subject string) bool {
	patternP := strings.Split(pattern, ".")
	subjectP := strings.Split(subject, ".")

	if len(patternP) != len(subjectP) {
		return false
	}

	for i, l := range patternP {
		if i == 0 && l == "*" {
			continue
		}

		if l != subjectP[i] {
			return false
		}
	}

	return true
}
