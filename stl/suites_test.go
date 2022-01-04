package stl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECDHX25519(t *testing.T) {
	c := defaultConfig()
	hss := ECDHE_x25519

	param1, err := curveParams(c, hss)
	if err != nil {
		t.Fatal(err)
	}

	param2, err := curveParams(c, hss)
	if err != nil {
		t.Fatal(err)
	}

	ms1, err := ecdh(c, hss, param2.pub, param1)
	if err != nil {
		t.Fatal(err)
	}

	ms2, err := ecdh(c, hss, param1.pub, param2)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ms1, ms2)
}

func TestECDHGeneric(t *testing.T) {
	c := defaultConfig()
	hss := ECDHE_p256

	param1, err := curveParams(c, hss)
	if err != nil {
		t.Fatal(err)
	}

	param2, err := curveParams(c, hss)
	if err != nil {
		t.Fatal(err)
	}

	ms1, err := ecdh(c, hss, param2.pub, param1)
	if err != nil {
		t.Fatal(err)
	}

	ms2, err := ecdh(c, hss, param1.pub, param2)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ms1, ms2)
}
