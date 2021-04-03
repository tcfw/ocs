package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tcfw/ocs/cdi"
)

func main() {
	cmd := &cobra.Command{
		Use:   "cdi",
		Short: "Run a CDI node",
		Long:  "Open Cryptography Standard CDI node (Certificate Distribution Infrastructure) allows sharing, finding and revoking OCS certificates",
		Run:   runServer,
	}

	cmd.Flags().String("ipfs-config", cdi.DefaultIPFSConfigPath, "ipfs config directory")
	cmd.Flags().String("http-addr", "", "http listening addr")
	cmd.Flags().Int("http-port", 80, "http web port")
	cmd.Flags().String("https-addr", "", "http listening addr")
	cmd.Flags().Int("https-port", 443, "http web port")
	cmd.Flags().String("https-key", "", "https TLS key")
	cmd.Flags().String("https-cert", "", "https TLS cert")

	viper.BindPFlag("ipfs.config", cmd.Flag("ipfs-config"))
	viper.BindPFlag("http.addr", cmd.Flag("http-addr"))
	viper.BindPFlag("http.port", cmd.Flag("http-port"))
	viper.BindPFlag("https.addr", cmd.Flag("https-addr"))
	viper.BindPFlag("https.port", cmd.Flag("https-port"))
	viper.BindPFlag("https.key", cmd.Flag("https-key"))
	viper.BindPFlag("https.cert", cmd.Flag("https-cert"))

	err := cmd.Execute()
	if err != nil {
		fmt.Printf("[error] %s", err)
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	tlsKey, _ := cmd.Flags().GetString("https.key")
	tlsCert, _ := cmd.Flags().GetString("https.cert")

	if tlsKey != "" || tlsCert != "" {
		viper.Set("https.enabled", true)
	}

	s := cdi.NewServer()
	err := s.Start()
	if err != nil {
		fmt.Printf("[error] %s", err)
		os.Exit(1)
	}

	select {}

}
