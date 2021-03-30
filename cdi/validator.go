package cdi

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	icore "github.com/ipfs/interface-go-ipfs-core"
	"github.com/ipfs/interface-go-ipfs-core/path"
	records "github.com/libp2p/go-libp2p-record"
	"github.com/tcfw/ocs/cki"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/net/context"
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

	b, err := ocsv.ipfs.Block().Get(context.Background(), path.New(ref.Ref))
	if err != nil {
		return fmt.Errorf("failed to fetch cert block: %s", err)
	}

	d, err := ioutil.ReadAll(io.LimitReader(b, 10<<20))
	if err != nil {
		return err
	}

	cert, err := cki.ParseCertificate(d)
	if err != nil {
		return fmt.Errorf("failed to parse cert: %s", err)
	}

	pk, err := cert.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to parse pubcert: %s", err)
	}

	if !pk.Verify(ref.SignatureData, ref.Signature) {
		return errors.New("bad signature")
	}

	return nil
}

//Select chooses which value to provide as they get updated in the DHT
//Currently just returns the first available
func (ocsv *ocsValidator) Select(key string, values [][]byte) (int, error) {
	//TODO(tcfw) select against a timestamp in certificate nbf/nat
	fmt.Printf("TO SELECT: %+v %+v\n", key, values)
	return 0, nil
}
