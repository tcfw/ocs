package cdi

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	config "github.com/ipfs/go-ipfs-config"
	"github.com/ipfs/go-ipfs/repo/fsrepo"
	"github.com/ipfs/interface-go-ipfs-core/options"
	"github.com/spf13/viper"
)

const (
	//DefaultIPFSConfigPath default config path for IPFS node
	DefaultIPFSConfigPath = "~/.ocs/ipfs/"
)

var (
	bootstrapPeers = []string{}
)

func init() {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("ocs")

	viper.SetDefault("ipfs.config", DefaultIPFSConfigPath)

	viper.SetDefault("http.enabled", true)
	viper.SetDefault("http.addr", "")
	viper.SetDefault("http.port", 80)

	viper.SetDefault("https.enabled", false)
	viper.SetDefault("https.addr", "")
	viper.SetDefault("https.port", 443)
	viper.SetDefault("https.key", "")
	viper.SetDefault("https.cert", "")
}

//initIPFSConfig creates a new IPFS repo and associated config, updating the IPFS bootstrap nodes
//to the OCS bootstrap nodes
func initIPFSConfig(path string) error {
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = fmt.Sprintf("%s/%s", home, path[1:])
		path = filepath.Clean(path)
	}

	fmt.Printf("Setting up IPFS repo: %s\n", path)

	err := os.MkdirAll(path, 0700)
	if err != nil {
		return err
	}

	id, err := config.CreateIdentity(ioutil.Discard, []options.KeyGenerateOption{options.Key.Type(options.Ed25519Key)})
	if err != nil {
		return err
	}

	cfg, err := config.InitWithIdentity(id)
	if err != nil {
		return err
	}

	cfg.Bootstrap = bootstrapPeers

	// Create the repo with the config
	err = fsrepo.Init(path, cfg)
	if err != nil {
		return fmt.Errorf("failed to init ephemeral node: %s", err)
	}

	err = initSwarmKey(path)
	if err != nil {
		return err
	}

	return nil
}
