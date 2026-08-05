package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to the proxy (saves credentials)",
	Run: func(cmd *cobra.Command, args []string) {
		if loginAdminHost != "" {
			internal.Cfg.AdminHost = loginAdminHost
		}
		if loginAdminPort != "" {
			internal.Cfg.AdminPort = loginAdminPort
		}
		if internal.Cfg.AdminHost == "127.0.0.1" {
			internal.Cfg.AdminHost = internal.Cfg.ProxyHost
		}
		if loginUsername == "" {
			prompt := &survey.Input{Message: "Username:"}
			survey.AskOne(prompt, &loginUsername)
		}
		if loginPassword == "" {
			prompt := &survey.Password{Message: "Password:"}
			survey.AskOne(prompt, &loginPassword)
		}
		if loginUsername == "" || loginPassword == "" {
			dieErr(fmt.Errorf("username and password are required"))
		}

		loginURL := fmt.Sprintf("http://%s:%s/api/login", internal.Cfg.AdminHost, internal.Cfg.AdminPort)
		internal.Vprintf("login: POST %s", loginURL)
		resp, err := internal.DirectClient().Post(loginURL, "application/json",
			strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, loginUsername, loginPassword)))
		if err != nil {
			dieErr(fmt.Errorf("login request failed: %w", err))
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			dieErr(fmt.Errorf("login failed: %s %s", resp.Status, body))
		}
		var result internal.LoginResponse
		if err := json.Unmarshal(body, &result); err != nil {
			dieErr(fmt.Errorf("parse login response: %w", err))
		}

		internal.Cfg.AuthToken = result.Token
		updates := map[string]string{
			"AI_PROXY_TOKEN":      result.Token,
			"AI_PROXY_USER":       loginUsername,
			"AI_PROXY_PASS":       loginPassword,
			"AI_PROXY_HOST":       internal.Cfg.ProxyHost,
			"AI_PROXY_PORT":       internal.Cfg.ProxyPort,
			"AI_PROXY_ADMIN_HOST": internal.Cfg.AdminHost,
			"AI_PROXY_ADMIN_PORT": internal.Cfg.AdminPort,
		}
		if err := internal.UpdateEnvConfig(updates); err != nil {
			dieErr(err)
		}
		internal.CleanupSystemProxy()

		fmt.Printf("%s Logged in as %s (%s, %d days)\n",
			internal.Success("✓"), result.User.Username, result.User.Role, result.ExpiresInDays)
		fmt.Printf("  %s %s\n", internal.Dim("token saved:"), internal.Cfg.EnvConfig)
		fmt.Printf("  %s %s\n", internal.Dim("use:"), "apx run <command>")
	},
}

var (
	loginUsername  string
	loginPassword  string
	loginAdminHost string
	loginAdminPort string
)

func init() {
	loginCmd.Flags().StringVar(&loginUsername, "user", "", "username")
	loginCmd.Flags().StringVar(&loginPassword, "pass", "", "password")
	loginCmd.Flags().StringVar(&loginAdminHost, "admin-host", "", "admin API host")
	loginCmd.Flags().StringVar(&loginAdminPort, "admin-port", "", "admin API port")
	rootCmd.AddCommand(loginCmd)
}

// ── Logout ──

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Forget saved credentials",
	Run: func(cmd *cobra.Command, args []string) {
		if internal.Cfg.AuthToken == "" && internal.Cfg.LoginUser == "" {
			fmt.Println("Not logged in.")
			return
		}
		if err := internal.UpdateEnvConfig(map[string]string{
			"AI_PROXY_TOKEN": "",
			"AI_PROXY_USER":  "",
			"AI_PROXY_PASS":  "",
		}); err != nil {
			dieErr(err)
		}
		internal.CleanupSystemProxy()
		fmt.Printf("%s Logged out.\n", internal.Success("✓"))
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

// ── Whoami ──

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the authenticated user",
	Run: func(cmd *cobra.Command, args []string) {
		if internal.Cfg.AuthToken == "" && internal.Cfg.LoginUser == "" {
			fmt.Println("not logged in")
			return
		}
		parts := strings.Split(internal.Cfg.AuthToken, ".")
		if len(parts) == 3 {
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var claims struct {
					Display string `json:"display"`
					Role    string `json:"role"`
				}
				if json.Unmarshal(payload, &claims) == nil {
					fmt.Printf("%s (%s)\n", claims.Display, internal.RoleBadge(claims.Role))
					return
				}
			}
		}
		fmt.Println("(token present, unparseable)")
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}

// unused import guard
var _ = http.StatusOK
var _ = os.Stdout
