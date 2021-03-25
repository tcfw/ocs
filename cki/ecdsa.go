package cki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/sha3"
)

//GenerateECKey generates a new private/public key from a given accepted OCS curve based algorithm
func GenerateECKey(a Algorithm) (*SecpPublicKey, *SecpPrivateKey, error) {
	curve := algoToCurve(a)

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privk := &SecpPrivateKey{PrivateKey: *priv, algo: a}
	pubk := &SecpPublicKey{PublicKey: priv.PublicKey, algo: a}

	return pubk, privk, nil
}

func algoToCurve(a Algorithm) elliptic.Curve {
	switch a {
	case ECDSAsecp256r1:
		return elliptic.P256()
	case ECDSAsecp384r1:
		return elliptic.P384()
	default:
		panic("unsupported elliptic algo params")
	}
}

//ECDSASignature representation of a unpacked ECDSA siganture
type ECDSASignature struct {
	Algo Algorithm `msgpack:"a"`
	R    []byte    `msgpack:"r"`
	S    []byte    `msgpack:"s"`
}

//Marshal encode the signature into msgpack encoding
func (sig *ECDSASignature) Marshal() ([]byte, error) {
	return msgpack.Marshal(sig)
}

//Unmarshal deecode the signature from msgpack encoding
func (sig *ECDSASignature) Unmarshal(d []byte) error {
	return msgpack.Unmarshal(d, sig)
}

type ecPrivateKey struct {
	D   []byte `msgpack:"d"`
	Pub []byte `msgpack:"p"`
}

//parseECPrivateKey decodes an exported EC private key
func parseECPrivateKey(k *ocsPrivateKey) (*SecpPrivateKey, error) {
	ec := &ecPrivateKey{}
	err := msgpack.Unmarshal(k.Key, ec)
	if err != nil {
		return nil, err
	}

	c := algoToCurve(k.Algo)
	x, y := elliptic.UnmarshalCompressed(c, ec.Pub)

	if !c.IsOnCurve(x, y) {
		return nil, errors.New("public key not on curve")
	}

	d := big.NewInt(0)
	d.SetBytes(ec.D)

	ecPriv := &SecpPrivateKey{
		PrivateKey: ecdsa.PrivateKey{
			D: d,
			PublicKey: ecdsa.PublicKey{
				Curve: c,
				X:     x,
				Y:     y,
			},
		},
		algo: k.Algo,
	}

	return ecPriv, nil
}

//SecpPrivateKey wrapper for ECDSA private keys
type SecpPrivateKey struct {
	ecdsa.PrivateKey
	algo Algorithm
}

//Sign a msg using ECDSA using the key
func (secpk *SecpPrivateKey) Sign(d []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, &secpk.PrivateKey, d)
	if err != nil {
		return nil, err
	}

	sig := &ECDSASignature{
		Algo: secpk.algo,
		R:    r.Bytes(),
		S:    s.Bytes(),
	}

	return sig.Marshal()
}

//Bytes marshals the private key into a compressed ANSI x9.62 encoding
func (secpk *SecpPrivateKey) Bytes() ([]byte, error) {
	pk := secpk.PrivateKey

	ec := &ecPrivateKey{
		Pub: elliptic.MarshalCompressed(pk.Curve, pk.X, pk.Y),
		D:   pk.D.Bytes(),
	}

	return msgpack.Marshal(ec)
}

//SecpPublicKey wrapper for a ECDSA public key
type SecpPublicKey struct {
	ecdsa.PublicKey
	algo Algorithm
}

//parseECPublicKey decodes an elliptical curve based public key
func parseECPublicKey(a Algorithm, d []byte) (*SecpPublicKey, error) {
	c := algoToCurve(a)
	x, y := elliptic.UnmarshalCompressed(c, d)

	if !c.IsOnCurve(x, y) {
		return nil, errors.New("public key not on curve")
	}

	pubk := &SecpPublicKey{
		ecdsa.PublicKey{Curve: c, X: x, Y: y},
		a,
	}

	return pubk, nil
}

//ID public ID matching the private key PublicID - SHA3-384
func (secppk *SecpPublicKey) ID() []byte {
	b, _ := secppk.Bytes()
	ha := sha3.Sum384(b)
	return ha[:]
}

//Verify a signature against a given message using the public key
//the signature must be in the ECDSASignature msgpack encoding
func (secppk *SecpPublicKey) Verify(msg []byte, sig []byte) bool {
	ecdsaSig := &ECDSASignature{}
	err := ecdsaSig.Unmarshal(sig)
	if err != nil {
		return false
	}

	r := big.NewInt(0)
	s := big.NewInt(0)
	r.SetBytes(ecdsaSig.R)
	s.SetBytes(ecdsaSig.S)

	return ecdsa.Verify(&secppk.PublicKey, msg, r, s)
}

//Bytes encodes the public key into ANSI X9.62 encoding
func (secppk *SecpPublicKey) Bytes() ([]byte, error) {
	pk := secppk.PublicKey
	return elliptic.MarshalCompressed(pk.Curve, pk.X, pk.Y), nil
}
