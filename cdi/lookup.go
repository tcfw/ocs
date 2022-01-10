package cdi

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"

	icore "github.com/ipfs/interface-go-ipfs-core"
	"github.com/ipfs/interface-go-ipfs-core/path"
	"github.com/tcfw/ocs/cki"
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
	Ref       string `msgpack:"r"`
	Signature []byte `msgpack:"s"`
	Nonce     []byte `msgpack:"n"`
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
