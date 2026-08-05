package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Print export lines for eval: eval \"$(apx env)\"",
	Run: func(cmd *cobra.Command, args []string) {
		proxyURL := os.Getenv("HTTPS_PROXY")
		if proxyURL == "" {
			if internal.Cfg.LoginUser != "" && internal.Cfg.LoginPass != "" {
				proxyURL = fmt.Sprintf("http://%s:%s@%s:%s", internal.Cfg.LoginUser, internal.Cfg.LoginPass, internal.Cfg.ProxyHost, internal.Cfg.ProxyPort)
			} else {
				proxyURL = fmt.Sprintf("http://%s:%s", internal.Cfg.ProxyHost, internal.Cfg.ProxyPort)
			}
		}
		noProxy := "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
		fmt.Printf("export HTTPS_PROXY=%q\n", proxyURL)
		fmt.Printf("export HTTP_PROXY=%q\n", proxyURL)
		fmt.Printf("export NO_PROXY=%q\n", noProxy)
		if internal.FileExists(internal.Cfg.BundleFile) {
			fmt.Printf("export SSL_CERT_FILE=%q\n", internal.Cfg.BundleFile)
			fmt.Printf("export REQUESTS_CA_BUNDLE=%q\n", internal.Cfg.BundleFile)
			fmt.Printf("export CURL_CA_BUNDLE=%q\n", internal.Cfg.BundleFile)
			fmt.Printf("export GIT_SSL_CAINFO=%q\n", internal.Cfg.BundleFile)
		}
		if internal.FileExists(internal.Cfg.CAFile) {
			fmt.Printf("export NODE_EXTRA_CA_CERTS=%q\n", internal.Cfg.CAFile)
		}
	},
}

// ── aliases ──

var aliasesInstall bool

var aliasesCmd = &cobra.Command{
	Use:   "aliases",
	Short: "Print or install shell wrapper functions",
	Run: func(cmd *cobra.Command, args []string) {
		block := `# ── AI Proxy agent functions ──
pi()      { apx run pi "$@"; }
claude()  { apx run claude "$@"; }
codex()   { apx run codex "$@"; }
cursor()  { apx run cursor "$@"; }
`
		if !aliasesInstall {
			fmt.Println("Add these functions to ~/.zshrc or ~/.bashrc:")
			fmt.Println(block)
			fmt.Println("Or auto-install: apx aliases --install")
			return
		}
		for _, rcPath := range []string{
			filePathJoin(internal.Home(), ".zshrc"),
			filePathJoin(internal.Home(), ".bashrc"),
		} {
			if !internal.FileExists(rcPath) {
				continue
			}
			data, _ := os.ReadFile(rcPath)
			if strings.Contains(string(data), "AI Proxy agent functions") {
				fmt.Printf("%s Already in %s — skipped\n", internal.Dim("·"), rcPath)
				continue
			}
			f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				continue
			}
			f.WriteString("\n" + block)
			f.Close()
			fmt.Printf("%s Added to %s\n", internal.Success("✓"), rcPath)
		}
	},
}

func filePathJoin(parts ...string) string {
	return strings.Join(parts, "/")
}

func init() {
	aliasesCmd.Flags().BoolVarP(&aliasesInstall, "install", "i", false, "auto-install into shell profiles")
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(aliasesCmd)
}
