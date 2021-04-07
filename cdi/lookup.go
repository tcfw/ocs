package cdi

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"

	blocks "github.com/ipfs/go-block-format"
	icore "github.com/ipfs/interface-go-ipfs-core"
	"github.com/ipfs/interface-go-ipfs-core/path"
	"github.com/tcfw/ocs/cki"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/sha3"
)

//LookupType represents the mode of lookup
type LookupType string

const (
	//RefLookup represents a public reference of an certificate (IPFS block addr)
	RefLookup = "ref"
	//CertIDLookup represents a lookup against the certificates ID
	CertIDLookup = "id"
	//EmailLookup represents a lookup against any stored email in a certificate
	EmailLookup = "email"
)

//CertRef represents a certificate reference structure
type CertRef struct {
	Ref           string `msgpack:"r"`
	Signature     []byte `msgpack:"s"`
	SignatureData []byte `msgpack:"sd"`
}

func (cr *CertRef) getCertificate(ipfs icore.CoreAPI) (*cki.Certificate, error) {
	b, err := ipfs.Block().Get(context.Background(), path.New(cr.Ref))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cert block: %s", err)
	}

	d, err := ioutil.ReadAll(io.LimitReader(b, 10<<20))
	if err != nil {
		return nil, err
	}

	cert, err := cki.ParseCertificate(d)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %s", err)
	}

	return cert, nil
}

//Lookup represents a lookup request data
type Lookup struct {
	LookupType LookupType `json:"t" msgpack:"t"`
	Data       []byte     `json:"d" msgpack:"d"`
}

//CertStore provides a means of finding certificates
type CertStore interface {
	Lookup(context.Context, *Lookup) (io.Reader, error)
	Publish(context.Context, *cki.Certificate, *PublishRequest) (string, error)
}

//IPFSCertStore uses IPFS to create a certificate store
type IPFSCertStore struct {
	s *Server
}

//Publish publishes a certificate based on a signed public request
func (scs *IPFSCertStore) Publish(ctx context.Context, c *cki.Certificate, r *PublishRequest) (string, error) {
	d, err := c.Bytes()
	if err != nil {
		return "", err
	}

	block := blocks.NewBlock(d)

	err = scs.s.rNode.Blocks.AddBlock(block)
	if err != nil {
		return "", err
	}

	path := block.Cid().String()

	refs := &CertRef{Ref: path, Signature: r.Signature, SignatureData: r.SignatureData}
	refData, err := msgpack.Marshal(refs)
	if err != nil {
		return "", err
	}

	var email string
	if (c.CertType == cki.MultiPKI || c.CertType == cki.PKI) && c.Entity.Email != "" {
		email = c.Entity.Email
	} else if c.CertType == cki.WOT && c.Subject != "" {
		email = c.Subject
	}
	if email != "" {
		emailRefKey := fmt.Sprintf("/%s/%s/%x", validatorNS, refEmailNS, sha3.Sum256([]byte(email)))
		fmt.Printf("Publishing DHT key %s\n", emailRefKey)
		err := scs.s.rNode.DHT.PutValue(ctx, emailRefKey, refData)
		if err != nil {
			return "", fmt.Errorf("failed to publish email ref: %s", err)
		}
	}

	certIDRef := fmt.Sprintf("/%s/%s/%x", validatorNS, refCertIDNS, sha3.Sum256(c.ID))
	fmt.Printf("Publishing DHT key %s\n", certIDRef)
	err = scs.s.rNode.DHT.PutValue(ctx, certIDRef, refData)
	if err != nil {
		if err.Error() == "can't replace a newer value with an older value" {
			return path, nil
		}
		return "", fmt.Errorf("failed to publish cert ID ref: %s", err)
	}

	return path, err
}

//Lookup attempts to find a certificate based on the lookup request. The IPFS DHT may be used
//to search for certificate IDs or emails, otherwise block lookup is used.
func (scs *IPFSCertStore) Lookup(ctx context.Context, l *Lookup) (io.Reader, error) {
	var refKey string

	switch l.LookupType {
	case RefLookup:
		return scs.s.ipfs.Block().Get(ctx, path.New(string(l.Data)))
	case CertIDLookup:
		data, err := base64.StdEncoding.DecodeString(string(l.Data))
		if err != nil {
			return nil, err
		}
		refKey = fmt.Sprintf("/%s/%s/%x", validatorNS, refCertIDNS, sha3.Sum256(data))
	case EmailLookup:
		refKey = fmt.Sprintf("/%s/%s/%x", validatorNS, refEmailNS, sha3.Sum256([]byte(l.Data)))
	}

	fmt.Printf("Looking up: %s\n", refKey)

	refData, err := scs.s.rNode.DHT.GetValue(ctx, refKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get DHT value: %s", err)
	}

	ref := &CertRef{}
	err = msgpack.Unmarshal(refData, ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ref: %s", err)
	}

	dR, err := scs.s.ipfs.Block().Get(ctx, path.New(ref.Ref))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block: %s", err)
	}

	d, err := ioutil.ReadAll(io.LimitReader(dR, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read cert: %s", err)
	}

	return bytes.NewReader(d), nil
}
