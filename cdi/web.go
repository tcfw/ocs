package cdi

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/spf13/viper"
	"github.com/tcfw/ocs/cki"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	//OCSCertificateMIME MIME type which can be used in web requests/responses
	OCSCertificateMIME = "application/x-ocs-certificate"
)

func (s *Server) router() *mux.Router {
	mux := mux.NewRouter()

	mux.HandleFunc("/internal/peers", s.webListPeers).Methods("GET")
	mux.HandleFunc("/publish", s.webPublish).Methods("POST")
	mux.HandleFunc("/lookup", s.webLookup).Methods("GET")
	mux.HandleFunc("/revoke", s.webRevoke).Methods("POST")

	return mux
}

//startWebAPI creates a router and associated http server to respond with API requests
func (s *Server) startWebAPI() {
	mux := s.router()

	var wg sync.WaitGroup

	if viper.GetBool("http.enabled") {
		wg.Add(1)
		go func() {
			addr := fmt.Sprintf("%s:%d", viper.GetString("http.addr"), viper.GetInt("http.port"))
			fmt.Printf("Starting web api (%s)\n", addr)

			err := http.ListenAndServe(addr, mux)
			if err != nil {
				fmt.Printf("[error (http)] %s\n", err)
			}
			wg.Done()
		}()
	}

	if viper.GetBool("https.enabled") {
		wg.Add(1)
		go func() {
			addr := fmt.Sprintf("%s:%d", viper.GetString("https.addr"), viper.GetInt("https.port"))
			fmt.Printf("Starting web api (https %s)\n", addr)

			key := viper.GetString("https.key")
			cert := viper.GetString("https.cert")
			err := http.ListenAndServeTLS(addr, key, cert, mux)
			if err != nil {
				fmt.Printf("[error (https)] %s\n", err)
			}
			wg.Done()
		}()
	}

	wg.Wait()
}

//webListPeers provides a list of peers the node has in it's peer store
func (s *Server) webListPeers(w http.ResponseWriter, r *http.Request) {
	remoteIP := net.ParseIP(r.RemoteAddr)
	if remoteIP != nil && remoteIP.IsGlobalUnicast() {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	list := map[string]peer.AddrInfo{}

	for _, p := range s.rNode.Peerstore.PeersWithAddrs() {
		if p == s.rNode.Identity {
			continue
		}
		info := s.rNode.Peerstore.PeerInfo(p)
		list[p.Pretty()] = info
	}

	w.Header().Add("content-type", "application/json")
	json.NewEncoder(w).Encode(list)
}

//webPublish uses a publish request to publish the certificate to the cert store
func (s *Server) webPublish(w http.ResponseWriter, r *http.Request) {
	br := io.LimitReader(r.Body, 10<<20) //10MB limit
	body, err := ioutil.ReadAll(br)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	req := &PublishRequest{}
	if r.Header.Get("content-type") == "application/json" {
		err = json.Unmarshal(body, req)
	} else {
		err = msgpack.Unmarshal(body, req)
	}
	if err != nil {
		http.Error(w, "failed to parse request", http.StatusBadRequest)
		return
	}

	if len(req.Cert) == 0 || len(req.Signature) == 0 || len(req.Nonce) != 32 {
		http.Error(w, "invalid request data", http.StatusBadRequest)
		return
	}

	var cert *cki.Certificate

	pemFormat := r.URL.Query().Get("pem")
	if pemFormat == "true" {
		cert, _, err = cki.ParsePEMCertificate(req.Cert)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to parse PEM certificate: %s", err), http.StatusBadRequest)
			return
		}
	} else {
		cert, err = cki.ParseCertificate(req.Cert)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to parse certificate: %s", err), http.StatusBadRequest)
			return
		}
	}

	err = s.validatePublishRequest(req, cert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	path, err := s.certificates.Publish(r.Context(), cert, req)
	if err != nil {
		//Reject when we have a 'better' certificate
		if strings.Contains(err.Error(), "can't replace a newer value with an older value") {
			http.Error(w, "failed to publish certificate", http.StatusBadRequest)
		} else {
			http.Error(w, fmt.Sprintf("failed to publish certificate: %s", err), http.StatusInternalServerError)
		}
		return
	}

	w.Write([]byte(`OK `))
	w.Write([]byte(path))
}

func (s *Server) validatePublishRequest(req *PublishRequest, c *cki.Certificate) error {
	pk, err := c.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to parse public key")
	}

	certBytes, err := c.Bytes()
	if err != nil {
		return fmt.Errorf("failed to remarshal certificate")
	}

	sigData := make([]byte, 0, len(certBytes)+len(req.Nonce))
	sigData = append(sigData, certBytes...)
	sigData = append(sigData, req.Nonce...)

	if !pk.Verify(sigData, req.Signature) {
		return fmt.Errorf("bad signature")
	}

	return nil

}

func (s *Server) webRevoke(w http.ResponseWriter, r *http.Request) {
	err := s.Revoke(r.Context(), &cki.Certificate{}, []byte(``))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte(`OK`))
}

//webLookup looks up certificates based on the Lookup request
func (s *Server) webLookup(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")

	switch t {
	case RefLookup, CertIDLookup, EmailLookup:
	default:
		http.Error(w, fmt.Sprintf("unknown lookup type (%s)", t), http.StatusBadRequest)
		return
	}

	lookup := &Lookup{
		LookupType: LookupType(t),
		Data:       []byte(r.URL.Query().Get("d")),
	}

	d, err := s.certificates.Lookup(r.Context(), lookup)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	certd, err := ioutil.ReadAll(d)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cert, err := cki.ParseCertificate(certd)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse certificate: %s", err), http.StatusFailedDependency)
		return
	}
	pem, err := cert.PEM()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse certificate: %s", err), http.StatusFailedDependency)
		return
	}

	w.Header().Add("Content-Type", OCSCertificateMIME)

	w.Write(pem)
}
