package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "ocs",
		Short: "OCS - Open Cryptography Standard",
		Long:  "The Open Cryptography Standard provides mechanisms for public key sharing, verification and encrypted message transfer",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

//Execute run the ocs cli
func Execute() {
	setup()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setup() {
	rootCmd.AddCommand(certCmd)
}
