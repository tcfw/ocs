package cki

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cki"
)

var (
	infoCmd = &cobra.Command{
		Use:   "info {file}",
		Short: "View certificate information",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := runInfo(cmd, args[0])
			if err != nil {
				fmt.Printf("[error] %s\n", err.Error())
				os.Exit(1)
			}
		},
	}
)

func init() {
	infoCmd.Flags().BoolP("chain", "c", false, "show all certificates in the chain")
}

func runInfo(cmd *cobra.Command, file string) error {
	cp := cki.NewIntermCertPool(cki.SystemRootsPool(), nil)

	f, err := os.OpenFile(file, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("opening file: %s", err)
	}

	b, err := ioutil.ReadAll(io.LimitReader(f, 1<<20*30))
	if err != nil {
		return fmt.Errorf("reading file: %s", err)
	}

	certs := []*cki.Certificate{}

	for len(b) != 0 {
		c, r, err := cki.ParsePEMCertificate(b)
		if err != nil {
			return fmt.Errorf("reading certificate: %s", err)
		}
		certs = append(certs, c)

		cp.AddCert(c)

		b = r
	}

	for _, c := range certs {
		fmt.Printf("------- Certificate ------\n%s", info(c, cp))

		switch c.CertType {
		case cki.PKI:
		case cki.MultiPKI:
		case cki.WOT:
		default:
			fmt.Println("Unsupported chain parsing")
		}

		fmt.Printf("--------------------------\n")
	}

	return nil
}

func info(c *cki.Certificate, cp cki.CertPool) string {
	buf := bytes.NewBuffer(nil)

	buf.WriteString(fmt.Sprintf("Version: %d\n", c.Version))
	buf.WriteString(fmt.Sprintf("Type: %s\n", strings.ToUpper(c.CertType.String())))
	buf.WriteString(fmt.Sprintf("Algo: %s\n", c.Algo.String()))
	buf.WriteString(fmt.Sprintf("Cert ID: %s\n", hexOut(c.ID)))
	buf.WriteString(fmt.Sprintf("Is CA: %t\n", c.IsCA))
	buf.WriteString(fmt.Sprintf("Public Key: %s\n", hexOut(c.PublicKey)))
	buf.WriteString(fmt.Sprintf("Is Revoke: %t\n", c.Revoke))
	buf.WriteString(fmt.Sprintf("Subject: %s\n", c.Subject))
	buf.WriteString(fmt.Sprintf("Not-before: %s\n", c.NotBefore.String()))
	buf.WriteString(fmt.Sprintf("Not-After: %s\n", c.NotAfter.String()))
	buf.WriteString("Entity:\n")
	if c.Entity != nil {
		buf.WriteString(fmt.Sprintf("\tName: %s\n", c.Entity.Name))
		buf.WriteString(fmt.Sprintf("\tUnit: %s\n", c.Entity.Unit))
		buf.WriteString(fmt.Sprintf("\tLocality: %s\n", c.Entity.Locality))
		buf.WriteString(fmt.Sprintf("\tState: %s\n", c.Entity.State))
		buf.WriteString(fmt.Sprintf("\tCountry: %s\n", c.Entity.Country))
		buf.WriteString(fmt.Sprintf("\tEmail: %s\n", c.Entity.Email))
	}
	buf.WriteString("Extensions:\n")
	for _, ext := range c.Extensions {
		buf.WriteString(fmt.Sprintf("\tType: %s\n\tData: %s\n", ext.Type.String(), ext.Data))
	}

	buf.WriteString("Signatures:\n")
	for i, sig := range c.Signatures {
		buf.WriteString(fmt.Sprintf("\tSignature[%d] ", i))
		if bytes.Equal(sig.ID, c.ID) {
			buf.WriteString("(Self Signed)\n")
		} else {
			buf.WriteString("\n")
		}
		buf.WriteString(fmt.Sprintf("\tCert ID: %s\n", hexOut(sig.ID)))
		buf.WriteString(fmt.Sprintf("\tAlgo: %s\n", sig.Algo.String()))
		buf.WriteString(fmt.Sprintf("\tSignature: %s\n", hexOut(sig.Signature)))
		buf.WriteString(fmt.Sprintf("\tPublic Ref: %s\n", hexOut(sig.PublicRef)))
		buf.WriteString(fmt.Sprintf("\tValid: %t\n", checkSignature(c, sig, cp)))
	}

	return buf.String()
}

func checkSignature(c *cki.Certificate, sig cki.Signature, cf cki.CertFinder) bool {
	pc, err := cf.FindCertificate(sig.ID, sig.PublicRef)
	if err != nil {
		fmt.Printf("failed to find certificate: %s", err)
		return false
	}

	pk, err := pc.GetPublicKey()
	if err != nil {
		return false
	}

	return c.VerifySignatureOnly(pc.ID, pk) == nil
}

func hexOut(b []byte) string {
	var out string

	for _, i := range b {
		out += fmt.Sprintf("%02x:", i)
	}

	if len(out) == 0 {
		return out
	}

	return out[:len(out)-1]
}
