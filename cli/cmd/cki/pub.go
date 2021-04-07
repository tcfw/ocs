package cki

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/multiformats/go-multihash"
	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cdi"
	"github.com/tcfw/ocs/cki"
	"github.com/vmihailenco/msgpack"
)

var (
	pubCmd = &cobra.Command{
		Use:   "pub",
		Short: "Publish an OCS certificate",
		Run: func(cmd *cobra.Command, args []string) {
			err := runPublish(cmd, args)
			if err != nil {
				fmt.Printf("[error] %s\n", err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	pubCmd.Flags().StringP("cert", "c", "", "OCS Certificate file to publish")
	pubCmd.Flags().StringP("privkey", "k", "", "OCS Private Key file")
	pubCmd.Flags().String("endpoint", DefaultEndpoint, "CDI endpoint")
}

func runPublish(cmd *cobra.Command, args []string) error {
	endpoint, err := cmd.Flags().GetString("endpoint")
	if err != nil {
		return err
	}
	if endpoint == "" {
		return fmt.Errorf("invalid endpoint")
	}

	//Quick URL format check
	url, err := url.Parse(endpoint)
	if err != nil {
		return err
	}

	certData, err := getFileFromFlag(cmd, "cert")
	if err != nil {
		return err
	}

	pkData, err := getFileFromFlag(cmd, "privkey")
	if err != nil {
		return err
	}

	var cert *cki.Certificate

	if certData[0] == '-' && certData[1] == '-' {
		//assume is PEM
		cert, _, err = cki.ParsePEMCertificate(certData)
	} else {
		cert, err = cki.ParseCertificate(certData)
	}
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %s", err)
	}

	if pkData[0] == '-' && pkData[1] == '-' {
		pkData, err = cki.ParsePEMPrivateKey(pkData)
		if err != nil {
			return fmt.Errorf("failed to parse PEM key: %s", err)
		}
	}

	fmt.Printf("Publishing Certificate:\n    %s\n", formatID(cert.ID))

	pk, err := cki.ParsePrivateKey(pkData)
	if err != nil {
		return err
	}

	req, err := newPublishRequest(cert, pk)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url.Path += "/publish"

	mhref, err := doPublish(ctx, url.String(), req)
	if err == nil {
		fmt.Printf("OK - Public Ref: %s\n", mhref)
	}

	return err
}

func newPublishRequest(c *cki.Certificate, pk cki.PrivateKey) (*cdi.PublishRequest, error) {
	certBytes, err := c.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %s", err)
	}

	req := &cdi.PublishRequest{
		Cert:          certBytes,
		SignatureData: make([]byte, 32),
	}

	_, err = rand.Read(req.SignatureData)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature data: %s", err)
	}

	req.Signature, err = pk.Sign(req.SignatureData)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %s", err)
	}

	return req, nil
}

//TODO(tcfw): add to a client struct
func doPublish(ctx context.Context, endpoint string, pubReq *cdi.PublishRequest) (string, error) {
	req, err := msgpack.Marshal(pubReq)
	if err != nil {
		return "", err
	}

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(req))
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		return "", err
	}

	body, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 2048))

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected HTTP response %d expected 200: %s", resp.StatusCode, string(body))
	}

	if !strings.HasPrefix(string(body), "OK ") {
		return "", fmt.Errorf("unexpected response: %s", body)
	}

	ref := strings.TrimPrefix(string(body), "OK ")

	mh, err := multihash.FromB58String(ref)
	if err != nil {
		return "", fmt.Errorf("failed to cast multihash: %s", err)
	}

	return mh.B58String(), nil
}

func getFileFromFlag(cmd *cobra.Command, flag string) ([]byte, error) {
	loc, err := cmd.Flags().GetString(flag)
	if err != nil {
		return nil, err
	}

	if loc == "" {
		return nil, fmt.Errorf("file required for '%s'", flag)
	}

	f, err := os.Open(loc)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := ioutil.ReadAll(io.LimitReader(f, 10<<20))
	if err != nil {
		return nil, err
	}

	return data, nil
}

func formatID(id []byte) string {
	buf := make([]byte, 0, 3*len(id))

	x := buf[1*len(id) : 3*len(id)]
	hex.Encode(x, id)

	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}

	return string(buf[:len(buf)-1])
}
