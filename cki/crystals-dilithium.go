package cki

import (
	"crypto"
	"io"

	"github.com/pkg/errors"

	dilithium "github.com/kudelskisecurity/crystals-go/crystals-dilithium"
)

// CRYSTALSDilithiumPrivate CRYSTALS Dilithium Private Key
type CRYSTALSDilithiumPrivate struct {
	dilithium.PrivateKey

	algo Algorithm
	data []byte
}

// CRYSTALSDilithiumPublic CRYSTALS Dilithium Public Key
type CRYSTALSDilithiumPublic struct {
	dilithium.PublicKey

	algo Algorithm
	data []byte
}

// GenerateCRYSTALSDilithiumKey generates a CRYSTALS Dilithium key pair at the given
// security of 2, 3 or 5
func GenerateCRYSTALSDilithiumKey(level int) (*CRYSTALSDilithiumPublic, *CRYSTALSDilithiumPrivate, error) {
	var di *dilithium.Dilithium
	var a Algorithm

	switch level {
	case 2:
		di = dilithium.NewDilithium2()
		a = CRYSTALSDilithium2
	case 3:
		di = dilithium.NewDilithium3()
		a = CRYSTALSDilithium3
	case 5:
		di = dilithium.NewDilithium5()
		a = CRYSTALSDilithium5
	default:
		return nil, nil, errors.New("unsupported security level")
	}

	ppk, psk := di.KeyGen(nil)

	pk, err := parseCRYSTALSDilithiumPublicKey(a, ppk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing generated packed public key")
	}

	sk, err := parseCRYSTALSDilithiumPrivateKey(&ocsPrivateKey{a, psk})
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing generated packed private key")
	}

	return pk, sk, nil
}

// Sign signs then give message with the private key
func (sk *CRYSTALSDilithiumPrivate) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	var di *dilithium.Dilithium

	switch sk.algo {
	case CRYSTALSDilithium2:
		di = dilithium.NewDilithium2()
	case CRYSTALSDilithium3:
		di = dilithium.NewDilithium3()
	case CRYSTALSDilithium5:
		di = dilithium.NewDilithium5()
	default:
		return nil, errors.New("unsupported security level")
	}

	return di.Sign(sk.data, msg), nil
}

// Bytes return the packed CRYSTALS Dilithium private key
func (sk *CRYSTALSDilithiumPrivate) Bytes() ([]byte, error) {
	return sk.data, nil
}

func (sk *CRYSTALSDilithiumPrivate) Public() PublicKey {
	return nil
}

// parseCRYSTALSDilithiumPrivateKey unpacks a CRYSTALS Dilithium private key
func parseCRYSTALSDilithiumPrivateKey(k *ocsPrivateKey) (*CRYSTALSDilithiumPrivate, error) {
	var di *dilithium.Dilithium

	switch k.Algo {
	case CRYSTALSDilithium2:
		di = dilithium.NewDilithium2()
	case CRYSTALSDilithium3:
		di = dilithium.NewDilithium3()
	case CRYSTALSDilithium5:
		di = dilithium.NewDilithium5()
	default:
		return nil, errors.New("unsupported security level")
	}

	sk := di.UnpackSK(k.Key)

	return &CRYSTALSDilithiumPrivate{sk, k.Algo, k.Key}, nil
}

// Verify verifies the given CRYSTALS Dilithium Signature using the public key
// and original message
func (pk *CRYSTALSDilithiumPublic) Verify(msg []byte, sig []byte) bool {
	var di *dilithium.Dilithium

	switch pk.algo {
	case CRYSTALSDilithium2:
		di = dilithium.NewDilithium2()
	case CRYSTALSDilithium3:
		di = dilithium.NewDilithium3()
	case CRYSTALSDilithium5:
		di = dilithium.NewDilithium5()
	default:
		panic("unsupported security level")
	}

	return di.Verify(pk.data, msg, sig)
}

// Bytes return the packed publick key bytes
func (pk *CRYSTALSDilithiumPublic) Bytes() ([]byte, error) {
	return pk.data, nil
}

// parseCRYSTALSDilithiumPublicKey parses a packed CRYTALS Dilithium public key
// given the security level algorithm
func parseCRYSTALSDilithiumPublicKey(a Algorithm, d []byte) (*CRYSTALSDilithiumPublic, error) {
	var di *dilithium.Dilithium

	switch a {
	case CRYSTALSDilithium2:
		di = dilithium.NewDilithium2()
	case CRYSTALSDilithium3:
		di = dilithium.NewDilithium3()
	case CRYSTALSDilithium5:
		di = dilithium.NewDilithium5()
	default:
		return nil, errors.New("unsupported security level")
	}

	pk := di.UnpackPK(d)

	return &CRYSTALSDilithiumPublic{pk, a, d}, nil
}
