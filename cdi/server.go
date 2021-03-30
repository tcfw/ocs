package cdi

import (
	"context"
	"fmt"

	"github.com/ipfs/go-ipfs/core"
	"github.com/ipfs/go-ipfs/core/bootstrap"
	icore "github.com/ipfs/interface-go-ipfs-core"
	"github.com/libp2p/go-libp2p-core/event"
)

type Server struct {
	rNode        *core.IpfsNode
	ipfs         icore.CoreAPI
	certificates CertStore
}

func NewServer() *Server {
	s := &Server{}
	s.certificates = &IPFSCertStore{s}

	return s
}

func (s *Server) Start() error {
	ctx := context.Background()

	fmt.Println("Starting IPFS node...")

	var err error
	s.rNode, s.ipfs, err = spawnIPFSNode(ctx)
	if err != nil {
		return err
	}

	s.setupDHTValidator()

	go s.listenForEvents()

	fmt.Println("Bootstrapping IPFS node...")
	err = s.rNode.Bootstrap(bootstrap.DefaultBootstrapConfig)
	if err != nil {
		return err
	}

	addrs, err := s.ipfs.Swarm().ListenAddrs(ctx)
	if err != nil {
		return err
	}

	fmt.Println("Listening on...")

	for _, a := range addrs {
		fmt.Printf("%s/p2p/%s\n", a.String(), s.rNode.Identity.Pretty())
	}

	go s.startWebAPI()

	err = s.rNode.DHT.Bootstrap(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) listenForEvents() {
	ebus := s.rNode.PeerHost.EventBus()
	sub, err := ebus.Subscribe(event.WildcardSubscription)
	if err != nil {
		fmt.Printf("ERR: %s", err.Error())
		return
	}
	defer sub.Close()

	fmt.Println("Listening for events")

	for e := range sub.Out() {
		switch e.(type) {
		case event.GenericDHTEvent:
			dhte := e.(event.GenericDHTEvent)
			fmt.Printf("DHT %+v\n", dhte)
		case event.EvtPeerConnectednessChanged:
			pcc := e.(event.EvtPeerConnectednessChanged)
			fmt.Printf("Peer connectivity changed: %s %s\n", pcc.Peer, pcc.Connectedness)
		default:
			fmt.Printf("Unknown event handle %T: %+v\n", e, e)
		}
	}
}
