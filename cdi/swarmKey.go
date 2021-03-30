package cdi

import (
	"fmt"
	"os"
)

const (
	swarmKey     = "/key/swarm/psk/1.0.0/\n/base16/\na94cad321dd716a568ff62a65e3d2457ea4cd454d15d0d6194e0d59a9d858a30"
	swarmKeyFile = "swarm.key"
)

//initSwarmKey creates the swarm key in the IPFS repo
func initSwarmKey(repoPath string) error {
	floc := fmt.Sprintf("%s/%s", repoPath, swarmKeyFile)
	f, err := os.OpenFile(floc, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(swarmKey)
	if err != nil {
		return err
	}

	return nil
}
