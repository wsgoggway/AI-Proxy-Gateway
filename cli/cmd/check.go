package cmd

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Verify system readiness",
	Run: func(cmd *cobra.Command, args []string) {
		ok := true
		check := func(name string, fn func() error) {
			if err := fn(); err != nil {
				fmt.Printf("  %s %s — %v\n", internal.CheckMark(false), name, err)
				ok = false
			} else {
				fmt.Printf("  %s %s\n", internal.CheckMark(true), name)
			}
		}

		fmt.Println(internal.Title("System Readiness Check"))
		check("proxy reachable", func() error {
			u := fmt.Sprintf("http://%s:%s/ca.pem", internal.Cfg.ProxyHost, internal.Cfg.ProxyPort)
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(u)
			if err != nil {
				return fmt.Errorf("unreachable at %s:%s: %w", internal.Cfg.ProxyHost, internal.Cfg.ProxyPort, err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("returned %d", resp.StatusCode)
			}
			return nil
		})
		check("CA downloaded", func() error {
			_, err := os.Stat(internal.Cfg.CAFile)
			return err
		})
		check("CA validates as X.509", func() error {
			data, err := os.ReadFile(internal.Cfg.CAFile)
			if err != nil {
				return err
			}
			_, err = internal.ParseCert(data)
			return err
		})
		check("CA bundle present", func() error {
			_, err := os.Stat(internal.Cfg.BundleFile)
			return err
		})
		check("CA in bundle", func() error {
			bundle, err := os.ReadFile(internal.Cfg.BundleFile)
			if err != nil {
				return err
			}
			caData, err := os.ReadFile(internal.Cfg.CAFile)
			if err != nil {
				return err
			}
			caCert, err := internal.ParseCert(caData)
			if err != nil {
				return err
			}
			caFP := internal.CertFingerprint(caCert)
			certs, err := internal.ParseCerts(bundle)
			if err != nil {
				return err
			}
			for _, c := range certs {
				if internal.CertFingerprint(c) == caFP {
					return nil
				}
			}
			return fmt.Errorf("CA not found in bundle — run 'apx install'")
		})
		check("sandbox / isolation", func() error {
			if runtime.GOOS == "darwin" {
				return internal.CheckKeychainTrust()
			}
			return internal.CheckBwrap()
		})
		check("config present", func() error {
			if _, err := os.Stat(internal.Cfg.EnvConfig); err != nil {
				return fmt.Errorf("run 'apx install' first: %w", err)
			}
			return nil
		})

		fmt.Println()
		if ok {
			fmt.Printf("%s All checks passed.\n", internal.Success("✓"))
		} else {
			fmt.Printf("%s Some checks failed — run 'apx install'\n", internal.Error("✗"))
		}
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
