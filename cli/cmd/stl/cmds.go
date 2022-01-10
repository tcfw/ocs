package stl

import "github.com/spf13/cobra"

//Attach attaches the cki commands to a root/parent command
func Attach(parent *cobra.Command) {
	parent.AddCommand(connectCmd)
	parent.AddCommand(echoCmd)
}
