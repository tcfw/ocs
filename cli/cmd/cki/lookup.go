package cki

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cki"
	"go.uber.org/atomic"
)

var (
	lookupCmd = &cobra.Command{
		Use:   "lookup [data, ...]",
		Short: "Look up published keys",
		Long:  "Look up published keys using an email, ID or public ref",
		Run: func(cmd *cobra.Command, args []string) {
			err := runLookup(cmd)
			if err != nil {
				fmt.Printf("[error] %s\n", err)
				os.Exit(1)
			}
		},
	}
	httpClient = &http.Client{}

	lookupEndpoint string
	lookupEmails   []string
	lookupRefs     []string
	lookupIDs      []string
)

func init() {
	lookupCmd.Flags().StringSliceVarP(&lookupEmails, "email", "e", nil, "Lookup via email")
	lookupCmd.Flags().StringSliceVarP(&lookupIDs, "id", "i", nil, "Lookup via id")
	lookupCmd.Flags().StringSliceVarP(&lookupRefs, "ref", "r", nil, "Lookup via ref")
	lookupCmd.Flags().StringVar(&lookupEndpoint, "endpoint", DefaultEndpoint, "CDI endpoint")
}

func runLookup(cmd *cobra.Command) error {
	if lookupEndpoint == "" {
		return fmt.Errorf("invalid endpoint")
	}

	//Quick URL format check
	url, err := url.Parse(lookupEndpoint)
	if err != nil {
		return err
	}

	url.Path += "/lookup"

	for i, id := range lookupIDs {
		if strings.Contains(id, ":") {
			lookupIDs[i], err = decodeColonFormat(lookupIDs[i])
			if err != nil {
				return fmt.Errorf("failed to parse id %s", id)
			}
		}

	}

	lookups := map[string][]string{
		"email": lookupEmails,
		"ref":   lookupRefs,
		"id":    lookupIDs,
	}

	n := len(lookupEmails) + len(lookupIDs) + len(lookupRefs)

	if n == 0 {
		return fmt.Errorf("at least 1 argument is required")
	}

	stdoutBuf := bufio.NewWriter(os.Stdout)
	defer stdoutBuf.Flush()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	results := make(chan string)

	//Start lookups
	for t, lookupGroup := range lookups {
		for _, lookup := range lookupGroup {
			wg.Add(1)

			go func(t string, lookup string) {
				defer wg.Done()

				doLookup(ctx, results, *url, t, lookup)
			}(t, lookup)
		}
	}

	resCount := atomic.NewInt32(0)
	var resWg sync.WaitGroup
	resWg.Add(1)

	//Print results
	go func() {
		defer resWg.Done()

		seenIDs := &sync.Map{}

		for cert := range results {
			pCert, _, err := cki.ParsePEMCertificate([]byte(cert))
			if err != nil {
				fmt.Fprintf(stdoutBuf, "[error] failed to parse cert\n")
				continue
			}

			if _, seen := seenIDs.LoadOrStore(string(pCert.ID), true); seen {
				continue
			}

			fmt.Fprintf(stdoutBuf, "%s", cert)
			resCount.Inc()
		}
	}()

	wg.Wait()
	close(results)
	resWg.Wait()

	if resCount.Load() == 0 {
		fmt.Fprintln(stdoutBuf, "0 results")
	}

	return nil
}

//TODO(tcfw): add to a client struct
func doLookup(ctx context.Context, r chan string, endpoint url.URL, t string, data string) {
	q := endpoint.Query()
	q.Set("t", t)
	q.Set("d", data)
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		r <- fmt.Sprintf("[error] %s\n", err)
		return
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		r <- fmt.Sprintf("[error] %s\n", err)
		return
	}

	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		r <- fmt.Sprintf("[error] %s\n", err)
		return
	}

	if resp.StatusCode == http.StatusInternalServerError {
		return
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		r <- fmt.Sprintf("[error] unexpected results: %d Body: %s", resp.StatusCode, body)
		return
	}

	r <- string(body)
}

func decodeColonFormat(od string) (string, error) {
	d := strings.ReplaceAll(od, ":", "")
	b, err := hex.DecodeString(d)
	if err != nil {
		return od, err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}
