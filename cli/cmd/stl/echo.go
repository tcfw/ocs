package stl

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cki"
	"github.com/tcfw/ocs/stl"
)

var (
	echoCmd = &cobra.Command{
		Use:   "echo [endpoint]",
		Short: "Start an echo server",
		Run: func(cmd *cobra.Command, args []string) {
			err := runEcho(cmd, args)
			if err != nil {
				fmt.Printf("[error] %s\n", err)
				os.Exit(1)
			}
		},
	}
)

func init() {
}

func runEcho(cmd *cobra.Command, args []string) error {
	c, p, err := generateTestCert("localhost")
	if err != nil {
		return err
	}

	config := &stl.Config{}

	cp, err := stl.CKIKeyPair(c, p)
	if err != nil {
		return err
	}

	config.Certificates = []stl.CertificatePair{cp}

	l, err := stl.Listen("tcp", ":4843", config)
	if err != nil {
		return err
	}

	fmt.Printf("Listening on %s\n", l.Addr())

	// err = http.Serve(l, nil)

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Printf("failed to accept conn: %s", err)
			continue
		}
		go pipeOut(c.(*stl.Conn))
	}

	return err
}

func pipeOut(c *stl.Conn) {
	fmt.Printf("New connection to %s\n", c.RemoteAddr())
	defer func() {
		fmt.Printf("Closed connection from %s\n", c.RemoteAddr())
	}()

	r := io.TeeReader(c, os.Stdout)
	buf := make([]byte, 1000)
	for {
		n, err := r.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Err: %s\n", err)
			}
			return
		}
		//write back
		c.Write(buf[:n])
	}
}

func generateTestCert(subject string) ([]byte, []byte, error) {
	pub, priv, err := cki.GenerateECKey(cki.ECDSAsecp256r1)
	if err != nil {
		return nil, nil, err
	}

	template := cki.Certificate{
		Subject: subject,
		Entity: &cki.Entity{
			Name:     "OCS",
			Locality: "Sydney",
			State:    "NSW",
			Country:  "AU",
		},
	}

	cert, err := cki.NewCertificate(template, pub, nil, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM, _ := cert.PEM()

	privBytes, err := cki.MarshalPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	privPEM := cki.MarshalPEMPrivateKey(privBytes)

	return certPEM, privPEM, nil
}
