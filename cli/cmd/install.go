package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Download CA, build bundle, write config (no root)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", internal.Title("AI Proxy — user-space setup (no root)"))
		fmt.Printf("  Proxy: %s:%s\n", internal.Cfg.ProxyHost, internal.Cfg.ProxyPort)

		// 1. Download CA.
		// Migrate legacy ~/ai-proxy-ca.pem into the config dir once.
		legacyCA := filepath.Join(internal.Home(), "ai-proxy-ca.pem")
		if internal.FileExists(legacyCA) && !internal.FileExists(internal.Cfg.CAFile) {
			if err := os.MkdirAll(internal.Cfg.CfgDir, 0755); err != nil {
				dieErr(fmt.Errorf("create config dir: %w", err))
			}
			if err := os.Rename(legacyCA, internal.Cfg.CAFile); err != nil {
				dieErr(fmt.Errorf("migrate legacy CA: %w", err))
			}
			fmt.Printf("  %s %s\n", internal.Warn("⚠"), internal.Dim("migrated legacy CA to "+internal.Cfg.CAFile))
		}
		changed, err := internal.DownloadCAIfChanged()
		if err != nil {
			dieErr(fmt.Errorf("download CA: %w", err))
		}
		caData, err := os.ReadFile(internal.Cfg.CAFile)
		if err != nil {
			dieErr(fmt.Errorf("read CA: %w", err))
		}
		cert, err := internal.ParseCert(caData)
		if err != nil {
			dieErr(fmt.Errorf("invalid CA: %w", err))
		}
		if !changed {
			fmt.Printf("[1/3] CA up to date: %s\n", internal.CertFingerprint(cert))
		} else {
			fmt.Printf("[1/3] Downloading CA...\n")
			fmt.Printf("  %s %s\n", internal.Success("✓"), internal.Dim("fingerprint: "+internal.CertFingerprint(cert)))
			fmt.Printf("  %s %s\n", internal.Dim("saved:"), internal.Cfg.CAFile)
		}

		// 2. Build bundle.
		fmt.Printf("[2/3] Building CA bundle...\n")
		os.MkdirAll(internal.Cfg.CacheDir, 0755)
		if err := internal.BuildBundle(); err != nil {
			dieErr(fmt.Errorf("build bundle: %w", err))
		}
		fmt.Printf("  %s %s\n", internal.Dim("bundle:"), internal.Cfg.BundleFile)

		// 3. Write config.
		fmt.Printf("[3/3] Writing config...\n")
		os.MkdirAll(internal.Cfg.CfgDir, 0755)
		os.MkdirAll(internal.Cfg.BinDir, 0755)

		cfg := map[string]string{
			"AI_PROXY_HOST": internal.Cfg.ProxyHost,
			"AI_PROXY_PORT": internal.Cfg.ProxyPort,
			"AI_PROXY_CA_FILE": internal.Cfg.CAFile,
		}
		if internal.Cfg.AuthToken != "" {
			cfg["AI_PROXY_TOKEN"] = internal.Cfg.AuthToken
		}
		if internal.Cfg.LoginUser != "" && internal.Cfg.LoginPass != "" {
			cfg["AI_PROXY_USER"] = internal.Cfg.LoginUser
			cfg["AI_PROXY_PASS"] = internal.Cfg.LoginPass
		}
		if err := internal.UpdateEnvConfig(cfg); err != nil {
			dieErr(err)
		}
		fmt.Printf("  %s %s\n", internal.Dim("config:"), internal.Cfg.EnvConfig)

		// Self-update.
		dst := filepath.Join(internal.Cfg.BinDir, "apx")
		tmp := filepath.Join(internal.Cfg.BinDir, ".apx.tmp"+strconv.Itoa(os.Getpid()))
		if err := internal.DownloadApx(tmp); err != nil {
			fmt.Fprintf(os.Stderr, "%s apx self-update failed: %v\n", internal.Warn("⚠"), err)
		} else if err := os.Rename(tmp, dst); err != nil {
			fmt.Fprintf(os.Stderr, "%s apx self-update rename failed: %v\n", internal.Warn("⚠"), err)
			os.Remove(tmp)
		} else {
			fmt.Printf("  %s %s (%s/%s)\n", internal.Success("✓"), internal.Dim("updated:"), runtime.GOOS, runtime.GOARCH)
		}

		fmt.Println()
		fmt.Println(internal.Success("Done — system trust store untouched."))
		fmt.Printf("Ensure %s is on PATH, then use:\n", internal.Cfg.BinDir)
		fmt.Printf("  %s  launch apps through the proxy\n", internal.Key("apx run <command>"))
		fmt.Printf("  %s  interactive shell\n", internal.Key("apx shell"))
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
}
