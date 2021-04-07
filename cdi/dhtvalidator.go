package cdi

import (
	"errors"
	"fmt"
	"strings"
	"time"

	icore "github.com/ipfs/interface-go-ipfs-core"
	records "github.com/libp2p/go-libp2p-record"
	"github.com/tcfw/ocs/cki"
	"github.com/vmihailenco/msgpack"
)

const (
	validatorNS = `ocs`
	refEmailNS  = `emailRef`
	refCertIDNS = `idRef`
)

//setupDHTValidator adds the ocs namespace into the IPFS DHT validators
func (s *Server) setupDHTValidator() {
	validator := &ocsValidator{s.ipfs}

	wanValidator := s.rNode.DHT.WAN.Validator.(records.NamespacedValidator)
	lanValidator := s.rNode.DHT.LAN.Validator.(records.NamespacedValidator)
	wanValidator[validatorNS] = validator
	lanValidator[validatorNS] = validator
}

//ocsValidator the main OCS DHT entry validator
type ocsValidator struct {
	ipfs icore.CoreAPI
}

//Validate ensures keys attempted to be added to the DHT in the OCS namespace are correctly formatted
//and verifies the associated signatures
func (ocsv *ocsValidator) Validate(key string, value []byte) error {
	parts := strings.Split(key, "/")
	parts = parts[1:]

	if parts[0] != validatorNS {
		return errors.New("not OCS namespace")
	}

	if len(parts) != 3 {
		return errors.New("invalid number of ns")
	}

	if parts[1] != refCertIDNS && parts[1] != refEmailNS {
		return errors.New("unknown NS")
	}

	ref := &CertRef{}
	err := msgpack.Unmarshal(value, ref)
	if err != nil {
		return fmt.Errorf("failed to parse value: %s", err)
	}

	cert, err := ref.getCertificate(ocsv.ipfs)
	if err != nil {
		return fmt.Errorf("failed to parse cert: %s", err)
	}

	certBytes, err := cert.Bytes()
	if err != nil {
		return err
	}

	pk, err := cert.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to parse pubcert: %s", err)
	}

	sigData := make([]byte, 0, len(certBytes)+len(ref.Nonce))
	sigData = append(sigData, certBytes...)
	sigData = append(sigData, ref.Nonce...)

	if !pk.Verify(sigData, ref.Signature) {
		return errors.New("bad signature")
	}

	return nil
}

//Select chooses which value to provide as they get updated in the DHT
//Currently just returns the first available
func (ocsv *ocsValidator) Select(key string, values [][]byte) (int, error) {
	scores := make(map[int]int, len(values))

	for i, value := range values {
		ref := &CertRef{}
		err := msgpack.Unmarshal(value, ref)
		if err != nil {
			return 0, err
		}

		cert, err := ref.getCertificate(ocsv.ipfs)
		if err != nil {
			return 0, fmt.Errorf("failed to parse cert: %s", err)
		}

		scores[i] = ocsv.certScore(cert)
	}

	ith := 0
	hScore := ^int(0)

	for i, score := range scores {
		if score > hScore {
			ith = i
			hScore = score
		}
	}

	return ith, nil
}

func (ocsv *ocsValidator) certScore(cert *cki.Certificate) int {
	score := 0

	score -= int(time.Since(cert.NotBefore) / time.Second)
	score += int(time.Until(cert.NotAfter) / time.Second)

	//TODO(tcfw) count verified signatures
	score += len(cert.Signatures)

	return score
}
