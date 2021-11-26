package cki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"io"
)

//GenerateRSAKey generates a new RSA public/private key
func GenerateRSAKey(bits int) (*RSAPublicKey, *RSAPrivateKey, error) {
	if bits != 2048 && bits != 4096 && bits != 8192 {
		panic("unsupported bit size")
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	priv := &RSAPrivateKey{rsaPriv}
	pub := &RSAPublicKey{rsaPriv.PublicKey}

	return pub, priv, nil
}

//RSAPublicKey representation of an RSA public key
type RSAPublicKey struct {
	rsa.PublicKey
}

//Bytes encodes the RSA public key to...
//TODO(tcfw) - encode using msgpack intead of ANSI.1
func (pubk *RSAPublicKey) Bytes() ([]byte, error) {
	return x509.MarshalPKCS1PublicKey(&pubk.PublicKey), nil
}

//Verify validates an RSA PKCS1v15 signature based on SHA2-384
func (pubk *RSAPublicKey) Verify(msg []byte, sig []byte) bool {
	h := sha512.Sum384(msg)

	err := rsa.VerifyPKCS1v15(&pubk.PublicKey, crypto.SHA384, h[:], sig)
	return err == nil
}

//parseRSAPublicKey decodes a RSA public key
//TODO(tcfw) - decode using msgpack intead of ANSI.1
func parseRSAPublicKey(a Algorithm, d []byte) (*RSAPublicKey, error) {
	pubk, err := x509.ParsePKCS1PublicKey(d)
	if err != nil {
		return nil, err
	}

	return &RSAPublicKey{*pubk}, nil
}

//ParseRSAPrivateKey decodes an exported RSA private key
func ParseRSAPrivateKey(k *ocsPrivateKey) (*RSAPrivateKey, error) {
	privk, err := x509.ParsePKCS1PrivateKey(k.Key)
	if err != nil {
		return nil, err
	}

	return &RSAPrivateKey{privk}, nil
}

//RSAPrivateKey representation of a RSA pivatekey
type RSAPrivateKey struct {
	*rsa.PrivateKey
}

//Sign creates a PKCS1v15 RSA signature of the given byte slice over a SHA2-384 hash
func (privk *RSAPrivateKey) Sign(_ io.Reader, d []byte, _ crypto.SignerOpts) ([]byte, error) {
	h := sha512.Sum384(d)

	return rsa.SignPKCS1v15(rand.Reader, privk.PrivateKey, crypto.SHA384, h[:])
}

//Bytes encodes the private key into ANSI.1
func (privk *RSAPrivateKey) Bytes() ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(privk.PrivateKey), nil
}

//Public provides the RSA public key
func (privk *RSAPrivateKey) Public() PublicKey {
	return &RSAPublicKey{privk.PrivateKey.PublicKey}
}
