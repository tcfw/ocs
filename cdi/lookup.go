package cdi

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/interface-go-ipfs-core/path"
	"github.com/tcfw/ocs/cki"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/crypto/sha3"
)

type LookupType string

const (
	RefLookup    = "ref"
	CertIDLookup = "id"
	EmailLookup  = "email"
)

type CertRef struct {
	Ref           string `msgpack:"r"`
	Signature     []byte `msgpack:"s"`
	SignatureData []byte `msgpack:"sd"`
}

type Lookup struct {
	LookupType LookupType `json:"t" msgpack:"t"`
	Data       []byte     `json:"d" msgpack:"d"`
}

type CertStore interface {
	Lookup(context.Context, *Lookup) (io.Reader, error)
	Publish(context.Context, *cki.Certificate, *PublishRequest) (string, error)
}

type SimpleCertStore struct {
	s *Server
}

func (scs *SimpleCertStore) Publish(ctx context.Context, c *cki.Certificate, r *PublishRequest) (string, error) {
	d, err := c.Bytes()
	if err != nil {
		return "", err
	}

	block := blocks.NewBlock(d)

	err = scs.s.rNode.Blocks.AddBlock(block)
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
		return "", fmt.Errorf("failed to publish cert ID ref: %s", err)
	}

	return path, err
}

func (scs *SimpleCertStore) Lookup(ctx context.Context, l *Lookup) (io.Reader, error) {
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
