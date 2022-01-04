package cki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicExtensionMarshal(t *testing.T) {
	template := Certificate{
		Extensions: []Extension{
			{Type: ExtensionType(1), Data: []byte("test extension")},
			{Type: AdditionalSubject, Data: []byte("test extension 2")},
		},
	}

	pub, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	b, err := cert.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	certR, err := ParseCertificate(b)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, cert.NotBefore.Equal(certR.NotBefore))
	assert.True(t, cert.NotAfter.Equal(certR.NotAfter))

	//Match up ts between certR and original
	//caused by time being equal, but different values
	//being used to create value in wall and/or ext
	certR.NotAfter = cert.NotAfter
	certR.NotBefore = cert.NotBefore

	assert.Equal(t, cert, certR)
}

func TestExtensionSignatureInclusion(t *testing.T) {
	template := Certificate{
		Extensions: []Extension{
			{Type: ExtensionType(1), Data: []byte("test extension")},
			{Type: AdditionalSubject, Data: []byte("test extension 2")},
		},
	}

	pub, priv, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	template.Extensions = nil

	cert2, err := NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert2.ID = cert.ID
	cert2.finalise()

	assert.NotEqual(t, cert.Signatures[0], cert2.Signatures[0])
}
