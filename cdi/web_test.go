package cdi

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tcfw/ocs/cki"
	"github.com/vmihailenco/msgpack"
)

type nullCertStore struct{}

func (ncs *nullCertStore) Lookup(context.Context, *Lookup) (io.Reader, error) {
	return bytes.NewReader([]byte("abc")), nil
}

func (ncs *nullCertStore) Publish(context.Context, *cki.Certificate, *PublishRequest) (string, error) {
	return "abc", nil
}

func TestPublish(t *testing.T) {
	//Create self signed cert
	pub, priv, err := cki.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	template := cki.Certificate{
		CertType: cki.PKI,
		Subject:  "Self signed",
		Entity: &cki.Entity{
			Name:     "Self signed Co",
			Locality: "Sydney",
			State:    "NSW",
			Country:  "AU",
			Email:    "ocs@tcfw.com.au",
		},
	}
	cert, err := cki.NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := cert.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	sigData := append(certBytes, nonce...)

	sig, err := priv.Sign(sigData)
	if err != nil {
		t.Fatal(err)
	}

	req := &PublishRequest{
		Cert:      certBytes,
		Signature: sig,
		Nonce:     nonce,
	}

	reqBytes, err := msgpack.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	//Setup server
	s := &Server{}
	s.certificates = &nullCertStore{}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/publish", bytes.NewReader(reqBytes))

	s.webPublish(w, r)

	body, _ := ioutil.ReadAll(w.Result().Body)
	assert.Equal(t, 200, w.Result().StatusCode)
	assert.True(t, strings.HasPrefix(string(body), "OK abc"))
}

func TestBadSignature(t *testing.T) {
	//Create self signed cert
	pub, priv, err := cki.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	template := cki.Certificate{
		CertType: cki.PKI,
		Subject:  "Self signed",
		Entity: &cki.Entity{
			Name:     "Self signed Co",
			Locality: "Sydney",
			State:    "NSW",
			Country:  "AU",
		},
	}
	cert, err := cki.NewCertificate(template, pub, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := cert.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	req := &PublishRequest{
		Cert:      certBytes,
		Signature: []byte(`badsignature`),
		Nonce:     nonce,
	}

	reqBytes, err := msgpack.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	//Setup server
	s := &Server{}
	s.certificates = &nullCertStore{}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/publish", bytes.NewReader(reqBytes))

	s.webPublish(w, r)

	body, _ := ioutil.ReadAll(w.Result().Body)
	assert.Equal(t, "bad signature\n", string(body))
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}
