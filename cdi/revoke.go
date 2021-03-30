package cdi

import (
	"context"
	"fmt"

	"github.com/tcfw/ocs/cki"
)

//Revoke stores a revoke certificate with signature to verify the revocation
//TODO(tcfw)
func (s *Server) Revoke(ctx context.Context, c *cki.Certificate, sig []byte) error {
	err := s.rNode.DHT.PutValue(ctx, `/ocs/test`, []byte(`test`))
	if err != nil {
		return err
	}

	return nil
}

//RevokeSignature revokes an individual signature on a certificate for use in Multi-PKI mode
//TODO(tcfw)
func (s *Server) RevokeSignature(ctx context.Context, c *cki.Certificate, sig []byte) error {
	return fmt.Errorf("not implemented")
}

//GetRevoke searches for a certificate revoke in the DHT
//TODO(tcfw)
func (s *Server) GetRevoke(ctx context.Context, id []byte) ([]byte, error) {
	return s.rNode.DHT.GetValue(ctx, `/ocs/test`)
}

//GetRevokeSignature searches for a signature revoke in the DHT
//TODO(tcfw)
func (s *Server) GetRevokeSignature(ctx context.Context, id []byte, parent []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
