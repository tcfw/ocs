package cki

import "github.com/spf13/cobra"

const (
	//DefaultEndpoint default CDI HTTP endpoint for publishing, revoking & looking up certificates
	DefaultEndpoint = "https://ocs.tcfw.com.au"
)

//Attach attaches the cki commands to a root/parent command
func Attach(parent *cobra.Command) {
	parent.AddCommand(newCmd)
	parent.AddCommand(pkCmd)
	parent.AddCommand(pubCmd)
	parent.AddCommand(lookupCmd)
}
