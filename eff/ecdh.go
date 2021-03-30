package eff

import (
	"crypto/rand"

	"github.com/tcfw/ocs/cki"
	"golang.org/x/crypto/argon2"
)

const (
	argon2Times   = 2
	argon2Mem     = 64 * 1024
	argon2Threads = 2
)

//ecdheSharedKey creates a shared key given a public key of the receiver, the private key of the sender, a salt and key length.
//The final key is derrived from Argon2id
func ecdheSharedKey(pub *cki.SecpPublicKey, priv *cki.SecpPrivateKey, salt []byte, keyLen uint32) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, nil, err
		}
	}

	a, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())

	sk := argon2.IDKey(a.Bytes(), salt, argon2Times, argon2Mem, argon2Threads, keyLen)

	return sk[:], salt, nil
}
