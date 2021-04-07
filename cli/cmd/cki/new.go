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

	newCmdNointeraction  bool
	newCmdCertType       string
	newCmdKey            string
	newCmdOut            string
	newCmdNotbefore      string
	newCmdNotafter       string
	newCmdDays           int
	newCmdIsSelfSigned   bool
	newCmdIsCa           bool
	newCmdCakey          string
	newCmdSubject        string
	newCmdEmail          string
	newCmdEntityName     string
	newCmdEntityUnit     string
	newCmdEntityLocality string
	newCmdEntityState    string
	newCmdEntityCountry  string
)

func init() {
	newCmd.Flags().BoolVar(&newCmdNointeraction, "nointeraction", false, "Disable UI interaction")

	newCmd.Flags().StringVarP(&newCmdCertType, "mode", "m", "pki", "Certificate Mode [pki, mpki, wot]")
	newCmd.Flags().StringVarP(&newCmdKey, "key", "k", "", "Private key to use (in PEM format)")
	newCmd.Flags().StringVarP(&newCmdOut, "out", "o", "", "Output file")

	newCmd.Flags().StringVar(&newCmdNotbefore, "notbefore", "", "Set the not before field")
	newCmd.Flags().StringVar(&newCmdNotafter, "notafter", "", "Set the not after field (overrides 'days')")
	newCmd.Flags().IntVarP(&newCmdDays, "days", "d", 30, "Number of days until the certificate should expire")

	newCmd.Flags().BoolVar(&newCmdIsSelfSigned, "selfsign", false, "Self-sign the certificate")
	newCmd.Flags().BoolVar(&newCmdIsCa, "ca", false, "Set CA flag in certificate")
	newCmd.Flags().StringVar(&newCmdCakey, "cakey", "", "Certificate Authority private key (in PEM format)")

	newCmd.Flags().StringVarP(&newCmdSubject, "subject", "s", "", "Certificate subject")
	newCmd.Flags().StringVar(&newCmdEmail, "email", "", "Email address")

	newCmd.Flags().StringVar(&newCmdEntityName, "entityName", "", "Entity name")
	newCmd.Flags().StringVar(&newCmdEntityUnit, "entityUnit", "", "Entity organisation unit")
	newCmd.Flags().StringVar(&newCmdEntityLocality, "entityLocality", "", "Entity locality")
	newCmd.Flags().StringVar(&newCmdEntityState, "entityState", "", "Entity state")
	newCmd.Flags().StringVar(&newCmdEntityCountry, "entityCountry", "", "Entity country")
}

func newCert(cmd *cobra.Command) error {
	notBefore, notAfter, err := calcNotBeforeAfter(cmd)
	if err != nil {
		return err
	}

	certType, err := getCertType()
	if err != nil {
		return err
	}

	if certType == cki.WOT {
		newCmdSubject = newCmdEmail
	}

	entity, err := readEntity(cmd)
	if err != nil {
		return err
	}

	temp := cki.Certificate{
		CertType:  certType,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA:      newCmdIsCa,
		Subject:   newCmdSubject,
		Entity:    entity,
	}

	pubk, privk, err := readPubPriv(cmd, "key")
	if err != nil {
		return err
	}

	var issuer *cki.Certificate

	if !newCmdIsSelfSigned {
		if newCmdCakey == "" {
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

	pem, err := c.PEM()
	if err != nil {
		return err
	}

	if newCmdOut == "" {
		fmt.Printf("%s", pem)
		return nil
	}

	f, err := os.OpenFile(newCmdOut, os.O_CREATE|os.O_RDWR, 0600)
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
	email := newCmdEmail

	if newCmdNointeraction {
		entity = &cki.Entity{
			Name:     newCmdEntityName,
			Unit:     newCmdEntityUnit,
			Locality: newCmdEntityLocality,
			State:    newCmdEntityState,
			Country:  newCmdEntityCountry,
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
	var err error

	if newCmdNotbefore != "" {
		notBefore, err = time.Parse(time.RFC3339, newCmdNotbefore)
		if err != nil {
			return notBefore, notAfter, err
		}
	}
	if newCmdNotafter == "" {
		if newCmdDays < 1 {
			return notBefore, notAfter, fmt.Errorf("invalid certificate validity dates")
		}
		notAfter = time.Now().Add(time.Duration(newCmdDays) * 24 * time.Hour)
	} else {
		notAfter, err = time.Parse(time.RFC3339, newCmdNotafter)
		if err != nil {
			return notBefore, notAfter, err
		}
	}

	return notBefore, notAfter, nil
}

func getCertType() (cki.CertificateType, error) {
	var mode cki.CertificateType

	switch newCmdCertType {
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
