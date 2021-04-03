package cki

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cki"
	"golang.org/x/crypto/ssh/terminal"
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
)

func init() {
	pkCmd.Flags().StringP("type", "t", "p256", "Private key type [ed25519, p256, p384, rsa]")
	pkCmd.Flags().IntP("bits", "c", 4096, "Number of bits of RSA key")
	pkCmd.Flags().StringP("out", "o", "", "Destintation file")
	pkCmd.Flags().StringP("pass", "p", "", "Private key encryption password")
}

func newPk(cmd *cobra.Command) error {
	pkType, err := cmd.Flags().GetString("type")
	if err != nil {
		return err
	}

	bitCount, err := cmd.Flags().GetInt("bits")
	if err != nil {
		return err
	}

	destFile, err := cmd.Flags().GetString("out")
	if err != nil {
		return err
	}

	var pk cki.PrivateKey

	switch pkType {
	case "ed25519":
		_, pk, err = cki.GenerateEd25519Key()
	case "p256":
		_, pk, err = cki.GenerateECKey(cki.ECDSAsecp256r1)
	case "p384":
		_, pk, err = cki.GenerateECKey(cki.ECDSAsecp384r1)
	case "rsa":
		if bitCount != 2048 && bitCount != 4096 {
			return fmt.Errorf("unsupposed RSA bit count (must be 2048 or 4096)")
		}
		_, pk, err = cki.GenerateRSAKey(bitCount)
	default:
		return fmt.Errorf("unknown private key type")
	}
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
			fmt.Printf("Password: ")
			l, err := terminal.ReadPassword(0)
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

	if destFile != "" {
		f, err := os.OpenFile(destFile, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		f.Truncate(0)
		dest = f
	}

	err = cki.MarshalPEMPrivateKey(raw, dest, password != "")
	if err != nil {
		return err
	}

	return nil
}
