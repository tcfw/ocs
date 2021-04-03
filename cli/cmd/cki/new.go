package cki

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cki"
)

var (
	newCmd = &cobra.Command{
		Use:   "new",
		Short: "Create a new certificate",
		Run: func(cmd *cobra.Command, args []string) {
			err := newCert(cmd)
			if err != nil {
				fmt.Printf("[error] %s\n", err.Error())
				os.Exit(1)
			}
		},
	}
)

//Attach attaches the cki commands to a root/parent command
func Attach(parent *cobra.Command) {
	parent.AddCommand(newCmd)
	parent.AddCommand(pkCmd)
}

func init() {
	newCmd.Flags().Bool("nointeraction", false, "Disable UI interaction")

	newCmd.Flags().StringP("mode", "m", "pki", "Certificate Mode [pki, mpki, wot]")
	newCmd.Flags().StringP("key", "k", "", "Private key to use (in PEM format)")
	newCmd.Flags().StringP("out", "o", "", "Output file")

	newCmd.Flags().String("notbefore", "", "Set the not before field")
	newCmd.Flags().String("notafter", "", "Set the not after field (overrides 'days')")
	newCmd.Flags().IntP("days", "d", 30, "Number of days until the certificate should expire")

	newCmd.Flags().Bool("selfsign", false, "Self-sign the certificate")
	newCmd.Flags().Bool("ca", false, "Set CA flag in certificate")
	newCmd.Flags().String("cakey", "", "Certificate Authority private key (in PEM format)")

	newCmd.Flags().StringP("subject", "s", "", "Certificate subject")
	newCmd.Flags().String("email", "", "Email address")

	newCmd.Flags().String("entityName", "", "Entity name")
	newCmd.Flags().String("entityUnit", "", "Entity organisation unit")
	newCmd.Flags().String("entityLocality", "", "Entity locality")
	newCmd.Flags().String("entityState", "", "Entity state")
	newCmd.Flags().String("entityCountry", "", "Entity country")
}

func newCert(cmd *cobra.Command) error {
	notBefore, notAfter, err := calcNotBeforeAfter(cmd)
	if err != nil {
		return err
	}

	isCa, err := cmd.Flags().GetBool("ca")
	if err != nil {
		return err
	}

	subject, err := cmd.Flags().GetString("subject")
	if err != nil {
		return err
	}

	certType, err := getCertType(cmd)
	if err != nil {
		return err
	}

	email, err := cmd.Flags().GetString("email")
	if err != nil {
		return err
	}
	if certType == cki.WOT {
		subject = email
	}

	entity, err := readEntity(cmd)
	if err != nil {
		return err
	}

	temp := cki.Certificate{
		CertType:  certType,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA:      isCa,
		Subject:   subject,
		Entity:    entity,
	}

	selfsigned, err := cmd.Flags().GetBool("selfsign")
	if err != nil {
		return err
	}

	pubk, privk, err := readPubPriv(cmd, "key")
	if err != nil {
		return err
	}

	var issuer *cki.Certificate

	if !selfsigned {
		cakey, err := cmd.Flags().GetString("cakey")
		if err != nil {
			return err
		}
		if cakey == "" {
			return fmt.Errorf("CA key cannot be empty when not self signing")
		}

		_, issuerprivk, err := readPubPriv(cmd, "cakey")
		if err != nil {
			return err
		}

		privk = issuerprivk
	}

	c, err := cki.NewCertificate(temp, pubk, issuer, privk)
	if err != nil {
		return err
	}

	destFile, err := cmd.Flags().GetString("out")
	if err != nil {
		return err
	}

	pem, err := c.PEM()
	if err != nil {
		return err
	}

	fmt.Printf("%+v", destFile)

	if destFile == "" {
		fmt.Printf("%s", pem)
		return nil
	}

	f, err := os.OpenFile(destFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(pem); err != nil {
		return err
	}

	return nil
}

func readPubPriv(cmd *cobra.Command, flag string) (cki.PublicKey, cki.PrivateKey, error) {
	src, err := cmd.Flags().GetString(flag)
	if err != nil {
		return nil, nil, err
	}

	if src == "" {
		return nil, nil, fmt.Errorf("no file specified in param %s", flag)
	}

	f, err := os.Open(src)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	r := io.LimitReader(f, 10<<20)

	d, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}

	pempk, err := cki.ParsePEMPrivateKey(d)
	if err != nil {
		return nil, nil, err
	}

	pk, err := cki.ParsePrivateKey(pempk)
	if err != nil {
		return nil, nil, err
	}

	pubk := pk.PublicKey()

	return pubk, pk, nil
}

func readEntity(cmd *cobra.Command) (*cki.Entity, error) {
	var entity *cki.Entity

	email, err := cmd.Flags().GetString("email")
	if err != nil {
		return nil, err
	}

	noninteract, err := cmd.Flags().GetBool("nointeraction")
	if err != nil {
		return nil, err
	}
	if noninteract {
		name, err := cmd.Flags().GetString("entityName")
		if err != nil {
			return nil, err
		}
		unit, err := cmd.Flags().GetString("entityUnit")
		if err != nil {
			return nil, err
		}
		locality, err := cmd.Flags().GetString("entityLocality")
		if err != nil {
			return nil, err
		}
		state, err := cmd.Flags().GetString("entityState")
		if err != nil {
			return nil, err
		}
		country, err := cmd.Flags().GetString("entityCountry")
		if err != nil {
			return nil, err
		}

		entity = &cki.Entity{
			Name:     name,
			Unit:     unit,
			Locality: locality,
			State:    state,
			Country:  country,
			Email:    email,
		}
	} else {
		reader := bufio.NewScanner(os.Stdin)

		fmt.Printf("Entity Name: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			return nil, err
		}
		name := reader.Text()
		fmt.Printf("Entity Unit: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			return nil, err
		}
		unit := reader.Text()
		fmt.Printf("Entity Locality: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			return nil, err
		}
		locality := reader.Text()
		fmt.Printf("Entity State: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			return nil, err
		}
		state := reader.Text()
		fmt.Printf("Entity Country: ")
		reader.Scan()
		if err := reader.Err(); err != nil {
			return nil, err
		}
		country := reader.Text()

		entity = &cki.Entity{
			Name:     string(name),
			Unit:     string(unit),
			Locality: string(locality),
			State:    string(state),
			Country:  string(country),
			Email:    email,
		}
	}

	return entity, nil
}

func calcNotBeforeAfter(cmd *cobra.Command) (time.Time, time.Time, error) {
	var notBefore, notAfter time.Time

	notBeforeRaw, err := cmd.Flags().GetString("notbefore")
	if err != nil {
		return notBefore, notAfter, err
	}

	notAfterRaw, err := cmd.Flags().GetString("notafter")
	if err != nil {
		return notBefore, notAfter, err
	}

	days, err := cmd.Flags().GetInt("days")
	if err != nil {
		return notBefore, notAfter, err
	}

	if notBeforeRaw != "" {
		notBefore, err = time.Parse(time.RFC3339, notBeforeRaw)
		if err != nil {
			return notBefore, notAfter, err
		}
	}
	if notAfterRaw == "" {
		if days < 1 {
			return notBefore, notAfter, fmt.Errorf("invalid certificate validity dates")
		}
		notAfter = time.Now().Add(time.Duration(days) * 24 * time.Hour)
	} else {
		notAfter, err = time.Parse(time.RFC3339, notAfterRaw)
		if err != nil {
			return notBefore, notAfter, err
		}
	}

	return notBefore, notAfter, nil
}

func getCertType(cmd *cobra.Command) (cki.CertificateType, error) {
	modeRaw, err := cmd.Flags().GetString("mode")
	if err != nil {
		return cki.UnknownCertType, err
	}

	var mode cki.CertificateType

	switch modeRaw {
	case "pki":
		mode = cki.PKI
	case "mpki":
		mode = cki.MultiPKI
	case "wot":
		mode = cki.WOT
	default:
		return cki.UnknownCertType, fmt.Errorf("invalid certificate mode")
	}

	return mode, nil
}
