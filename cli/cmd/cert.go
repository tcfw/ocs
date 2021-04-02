package cmd

import (
	"github.com/spf13/cobra"
	ckiCmd "github.com/tcfw/ocs/cli/cmd/cki"
)

var (
	certCmd = &cobra.Command{
		Use:   "cki",
		Short: "Manage CKI Certificates",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

func init() {
	ckiCmd.Attach(certCmd)
}

//ocs cki new --mode pki --priv
