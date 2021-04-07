package cdi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tcfw/ocs/cki"
)

func TestCertScore(t *testing.T) {
	validator := &ocsValidator{}

	cert := &cki.Certificate{
		NotBefore: time.Now().Add(-1 * 24 * time.Hour),
		NotAfter:  time.Now().Add(1 * 24 * time.Hour),
		Signatures: []cki.Signature{
			{
				ID: []byte(`invalid`),
			},
		},
	}

	score := validator.certScore(cert)
	assert.Equal(t, 0, score)

	cert.NotAfter = time.Now().Add(24*time.Hour + time.Second)

	score = validator.certScore(cert)
	assert.Equal(t, 1, score)
}
