package cki

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cki"
	"golang.org/x/term"
)

var (
	pkCmd = &cobra.Command{
		Use:   "pk",
		Short: "Create private keys",
		Run: func(cmd *cobra.Command, args []string) {
			err := newPk(cmd)
			if err != nil {
				fmt.Printf("[error] %s\n", err.Error())
				os.Exit(1)
			}
		},
	}

	pkType   string
	pkBits   int
	pkOut    string
	secLevel int
)

func init() {
	pkCmd.Flags().StringVarP(&pkType, "type", "t", "p256", "Private key type [ed25519, p256, p384, rsa, di]")
	pkCmd.Flags().IntVarP(&pkBits, "bits", "c", 4096, "Number of bits of RSA key")
	pkCmd.Flags().IntVarP(&secLevel, "sec-level", "s", 3, "CRYSTALS Dilithium security level of 2, 3 (recommended) or 5")
	pkCmd.Flags().StringVarP(&pkOut, "out", "o", "", "Destintation file")
	pkCmd.Flags().StringP("pass", "p", "", "Private key encryption password")
}

func newPk(cmd *cobra.Command) error {
	pk, err := generatePkFromType(pkType, pkBits)
	if err != nil {
		return err
	}

	password, err := cmd.Flags().GetString("pass")
	if err != nil {
		return err
	}

	var raw []byte

	if password != "" {
		if password == "-" {
			fmt.Printf("Encryption Password: ")
			l, err := term.ReadPassword(0)
			if err != nil {
				return err
			}
			fmt.Printf("\n\n")
			password = string(l)
		}
		raw, err = cki.MarshalEncryptedPrivateKey(pk, []byte(password))
	} else {
		raw, err = cki.MarshalPrivateKey(pk)
	}
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		panic("empty pk generated")
	}

	var dest io.Writer
	dest = os.Stdout

	if pkOut != "" {
		f, err := os.OpenFile(pkOut, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		f.Truncate(0)
		dest = f
	}

	err = cki.MarshalPEMRawPrivateKey(raw, dest, password != "")
	if err != nil {
		return err
	}

	return nil
}

func generatePkFromType(pkType string, bitCount int) (pk cki.PrivateKey, err error) {
	switch pkType {
	case "ed25519":
		_, pk, err = cki.GenerateEd25519Key()
	case "p256":
		_, pk, err = cki.GenerateECKey(cki.ECDSAsecp256r1)
	case "p384":
		_, pk, err = cki.GenerateECKey(cki.ECDSAsecp384r1)
	case "rsa":
		_, pk, err = cki.GenerateRSAKey(bitCount)
	case "di":
		_, pk, err = cki.GenerateCRYSTALSDilithiumKey(secLevel)
	default:
		return nil, fmt.Errorf("unknown private key type")
	}

	return
}
