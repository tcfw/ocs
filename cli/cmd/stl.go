package cmd

import (
	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cli/cmd/stl"
)

var (
	stlCmd = &cobra.Command{
		Use:   "stl",
		Short: "Create/Troubleshoot STL connections & tunnels",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

func init() {
	stl.Attach(stlCmd)
}
