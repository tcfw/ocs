package cdi

import (
	"context"
	"fmt"

	"github.com/tcfw/ocs/cki"
)

func (s *Server) Revoke(ctx context.Context, c *cki.Certificate, sig []byte) error {
	err := s.rNode.DHT.PutValue(ctx, `/ocs/test`, []byte(`test`))
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) RevokeSignature(ctx context.Context, c *cki.Certificate, sig []byte) error {
	return fmt.Errorf("not implemented")
}

func (s *Server) GetRevoke(ctx context.Context, id []byte) ([]byte, error) {
	return s.rNode.DHT.GetValue(ctx, `/ocs/test`)
}

func (s *Server) GetRevokeSignature(ctx context.Context, id []byte, parent []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
