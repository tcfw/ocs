package stl

import (
	"testing"

	"github.com/tcfw/ocs/cki"
)

func generateTestCert(t *testing.T, subject string) ([]byte, []byte) {
	pub, priv, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	template := cki.Certificate{
		Subject: subject,
		Entity: &cki.Entity{
			Name:     "OCS",
			Locality: "Sydney",
			State:    "NSW",
			Country:  "AU",
		},
	}

	cert, err := cki.NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, _ := cert.PEM()

	privBytes, err := cki.MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	privPEM := cki.MarshalPEMPrivateKey(privBytes)

	return certPEM, privPEM
}
