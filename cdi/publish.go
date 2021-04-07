package cdi

//PublishRequest represents a certificate publish request
type PublishRequest struct {
	Cert      []byte `msgpack:"c" json:"c"`
	Signature []byte `msgpack:"s" json:"s"`
	Nonce     []byte `msgpack:"n" json:"n"`
}
