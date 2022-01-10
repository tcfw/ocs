package stl

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tcfw/ocs/cki"
	"github.com/tcfw/ocs/stl"
)

var (
	connectCmd = &cobra.Command{
		Use:   "connect [endpoint]",
		Short: "Connect to an STL endpoint",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := runConnect(cmd, args)
			if err != nil {

				fmt.Printf("[error] %s\n", err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	connectCmd.Flags().BoolP("udp", "u", false, "connect over UDP")
	connectCmd.Flags().BoolP("skipVerify", "k", false, "skip certificate verification")
	connectCmd.Flags().BoolP("info", "i", false, "show connection info")
	connectCmd.Flags().BoolP("secure", "s", false, "keep host info secure")
}

func runConnect(cmd *cobra.Command, args []string) error {
	host, port, err := parseHost(args[0])
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%s", host, port)

	network := "tcp"
	if useUDP, _ := cmd.Flags().GetBool("udp"); useUDP {
		network = "udp"
	}

	config, err := buildConfig(cmd)
	if err != nil {
		return err
	}

	c, err := stl.Dial(network, addr, config)
	if err != nil {
		return fmt.Errorf("failed to dial: %s", err)
	}
	defer c.Close()

	fmt.Printf("Dialed %s\n", c.RemoteAddr())

	if si, _ := cmd.Flags().GetBool("info"); si {
		if err = showInfo(c); err != nil {
			return err
		}
	}

	errCh := make(chan error)

	go func() {
		buf := make([]byte, 1000)
		for {
			n, err := c.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			fmt.Printf("%s", buf[:n])
		}
	}()

	go func() {
		buf := make([]byte, 1000)
		for {
			// msg, _, err := bufio.NewReader(os.Stdin).ReadLine()
			n, err := os.Stdin.Read(buf)
			if err != nil {
				errCh <- err
				return
			}

			_, err = c.Write(buf[:n])
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	err = <-errCh
	if err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}

	return nil
}

func parseHost(h string) (host string, port string, err error) {
	if strings.Contains(h, ":") {
		host, port, err = net.SplitHostPort(h)
		return
	}

	host = h
	port = defaultPort

	return
}

func buildConfig(cmd *cobra.Command) (*stl.Config, error) {
	c := &stl.Config{}

	if skip, _ := cmd.Flags().GetBool("skipVerify"); skip {
		fmt.Printf("!! Warning. skipping certificate verification !!\n")
		c.SkipCertificateVerification = true
	}

	if secHost, _ := cmd.Flags().GetBool("secure"); secHost {
		c.HostnameMode = stl.HostnameType_OnRequest
	}

	return c, nil
}

func showInfo(c *stl.Conn) error {
	state := c.State()

	fmt.Printf("---\n")
	fmt.Printf("Connected: %v\n", state.HandshakeComplete)
	fmt.Printf("---\n")
	fmt.Printf("Name: %s\n", state.PeerName)
	fmt.Printf("Version: %d\n", state.Version)
	fmt.Printf("Suite: %d:%d\n", state.Suite.Handshake, state.Suite.Application)
	if len(state.PeerCertificates) > 0 {
		fmt.Printf("---\nResponder Certificates\n")
		for _, cert := range state.PeerCertificates {

			c, err := cki.ParseCertificate(cert.Certificate)
			if err != nil {
				return err
			}

			pem, _ := c.PEM()

			fmt.Printf("%s", pem)
		}
	}
	fmt.Printf("---\n")

	return nil
}
