package cki

// Algorithm available cryptographic algorithms
type Algorithm uint16

const (
	//UnknownAlgo unknown or not set
	UnknownAlgo Algorithm = iota
	//ED25519 Ed25519/curve25519
	ED25519
	//ECDSAsecp256r1 secp256k1 or NIST P-256
	ECDSAsecp256r1
	//ECDSAsecp384r1 secp384r1 or NIST P-384
	ECDSAsecp384r1
	//RSA2048 RSA 2048 bits
	RSA2048
	//RSA4096 RSA 4096 bits
	RSA4096
	//CRYSTALS-DILITHIUM-2
	CRYSTALSDilithium2
	//CRYSTALS-DILITHIUM-3
	CRYSTALSDilithium3
	//CRYSTALS-DILITHIUM-5
	CRYSTALSDilithium5

	algoMax
)

func (a Algorithm) String() string {
	switch a {
	case ED25519:
		return "ED25519"
	case ECDSAsecp256r1:
		return "ECDSA Secp256r1 (P-256)"
	case ECDSAsecp384r1:
		return "ECDSA Secp384r1 (P-384)"
	case RSA2048:
		return "RSA 2048"
	case RSA4096:
		return "RSA 4096"
	case CRYSTALSDilithium2:
		return "CRYSTALS-Dilithium2"
	case CRYSTALSDilithium3:
		return "CRYSTALS-Dilithium3"
	case CRYSTALSDilithium5:
		return "CRYSTALS-Dilithium5"
	default:
		return "unknown"
	}
}
