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
)

func init() {
	lookupCmd.Flags().StringSliceP("email", "e", nil, "Lookup via email")
	lookupCmd.Flags().StringSliceP("id", "i", nil, "Lookup via id")
	lookupCmd.Flags().StringSliceP("ref", "r", nil, "Lookup via ref")
	lookupCmd.Flags().String("endpoint", DefaultEndpoint, "CDI endpoint")
}

func runLookup(cmd *cobra.Command) error {
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

	url.Path += "/lookup"

	emails, err := cmd.Flags().GetStringSlice("email")
	if err != nil {
		return err
	}

	ids, err := cmd.Flags().GetStringSlice("id")
	if err != nil {
		return err
	}

	refs, err := cmd.Flags().GetStringSlice("ref")
	if err != nil {
		return err
	}

	lookups := map[string][]string{
		"email": emails,
		"ref":   refs,
		"id":    ids,
	}

	n := len(emails) + len(ids) + len(refs)

	if n == 0 {
		return fmt.Errorf("at least 1 argument is required")
	}

	stdoutBuf := bufio.NewWriter(os.Stdout)
	defer stdoutBuf.Flush()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	results := make(chan string)

	for t, lookupGroup := range lookups {
		for _, lookup := range lookupGroup {
			wg.Add(1)

			if t == "id" && strings.Contains(lookup, ":") {
				lookup, err = decodeColonFormat(lookup)
				if err != nil {
					return fmt.Errorf("failed to parse id %s", lookup)
				}
			}

			go func(t string, lookup string) {
				defer wg.Done()

				doLookup(ctx, results, *url, t, lookup)
			}(t, lookup)
		}
	}

	resCount := atomic.NewInt32(0)
	var resWg sync.WaitGroup
	resWg.Add(1)

	seenIDs := &sync.Map{}

	//Print results
	go func() {
		defer resWg.Done()

		for cert := range results {
			pCert, _, err := cki.ParsePEMCertificate([]byte(cert))
			if err != nil {
				fmt.Fprintf(stdoutBuf, "[error] failed to parse cert\n")
				continue
			}

			_, seen := seenIDs.LoadOrStore(string(pCert.ID), true)
			if seen {
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
