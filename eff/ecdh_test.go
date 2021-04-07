package eff

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tcfw/ocs/cki"
)

func TestSharedKeyECDH(t *testing.T) {
	pub1, priv1, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	pub2, priv2, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		t.Fatal(err)
	}

	sk1, salt, err := ecdheSharedKey(pub2.Curve, pub2, priv1, nil, 56)
	if err != nil {
		t.Fatal(err)
	}

	sk2, _, err := ecdheSharedKey(pub1.Curve, pub1, priv2, salt, 56)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, sk1, sk2)
}
