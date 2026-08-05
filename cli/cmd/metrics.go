package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var metricsWatch bool

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "System and per-user metrics",
	Long: "Show proxy metrics. Default: system overview.\n\n" +
		"Flags:\n" +
		"  --all     show per-user usage table\n" +
		"  --self    show your own metrics\n" +
		"  --user X  show metrics for user X\n" +
		"  --watch   auto-refresh every 5s",
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		if metricsWatch {
			for {
				fmt.Print("\033[H\033[2J") // clear screen
				runMetrics(cmd)
				time.Sleep(5 * time.Second)
			}
		}
		runMetrics(cmd)
	},
}

func runMetrics(cmd *cobra.Command) {
	switch {
	case cmd.Flags().Changed("all"):
		showUsersMetrics()
	case cmd.Flags().Changed("self"):
		showSingleMetric("self")
	case cmd.Flags().Changed("user"):
		u, _ := cmd.Flags().GetString("user")
		uid, err := internal.ResolveUserID(u)
		if err != nil {
			dieErr(err)
		}
		showSingleMetric("users/" + uid)
	default:
		showSystemMetrics()
	}
}

func showSystemMetrics() {
	resp, err := internal.APIGet(internal.AdminAPIBase() + "/metrics/system")
	if err != nil {
		dieErr(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		dieErr(fmt.Errorf("metrics failed: %s %s", resp.Status, data))
	}
	var m internal.SystemMetrics
	json.Unmarshal(data, &m)

	vaultStatus := internal.Success("✓ connected")
	if m.VaultConnected == 0 {
		vaultStatus = internal.Error("✗ disconnected")
	}
	rows := [][]string{
		{"Active Connections", fmt.Sprintf("%d", m.ActiveConnections)},
		{"Cert Cache Entries", fmt.Sprintf("%d", m.CertCacheEntries)},
		{"Prometheus Lines", fmt.Sprintf("%d", m.PrometheusRawLines)},
		{"Vault", vaultStatus},
	}
	fmt.Println(internal.Title("System Metrics"))
	internal.PrintTable([]string{"METRIC", "VALUE"}, rows)
}

func showUsersMetrics() {
	resp, err := internal.APIGet(internal.AdminAPIBase() + "/metrics/users")
	if err != nil {
		dieErr(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		dieErr(fmt.Errorf("metrics failed: %s %s", resp.Status, data))
	}
	var users []internal.UserMetrics
	json.Unmarshal(data, &users)

	headers := []string{"USERNAME", "ROLE", "REQ", "TOK IN", "TOK OUT", "BYTES IN", "BYTES OUT"}
	var rows [][]string
	for _, u := range users {
		rows = append(rows, []string{
			u.Username,
			internal.RoleBadge(u.Role),
			fmt.Sprintf("%d", u.Req),
			internal.FormatTokens(u.TokIn),
			internal.FormatTokens(u.TokOut),
			internal.FormatBytes(u.BytesIn),
			internal.FormatBytes(u.BytesOut),
		})
	}
	if len(rows) == 0 {
		fmt.Println("No user metrics.")
		return
	}
	internal.PrintTable(headers, rows)
}

func showSingleMetric(path string) {
	resp, err := internal.APIGet(internal.AdminAPIBase() + "/metrics/" + path)
	if err != nil {
		dieErr(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		dieErr(fmt.Errorf("metrics failed: %s %s", resp.Status, data))
	}
	var u internal.UserMetrics
	if json.Unmarshal(data, &u) == nil {
		headers := []string{"USERNAME", "ROLE", "REQ", "TOK IN", "TOK OUT", "BYTES IN", "BYTES OUT"}
		rows := [][]string{{
			u.Username,
			internal.RoleBadge(u.Role),
			fmt.Sprintf("%d", u.Req),
			internal.FormatTokens(u.TokIn),
			internal.FormatTokens(u.TokOut),
			internal.FormatBytes(u.BytesIn),
			internal.FormatBytes(u.BytesOut),
		}}
		internal.PrintTable(headers, rows)
	} else {
		// Fallback to JSON pretty-print.
		var v interface{}
		json.Unmarshal(data, &v)
		pretty, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(pretty))
	}
}

func init() {
	metricsCmd.Flags().Bool("all", false, "show all users")
	metricsCmd.Flags().Bool("self", false, "show your own metrics")
	metricsCmd.Flags().String("user", "", "show metrics for a specific user")
	metricsCmd.Flags().BoolVar(&metricsWatch, "watch", false, "auto-refresh every 5s")
	rootCmd.AddCommand(metricsCmd)
}

// guard unused import
var _ = strings.TrimSpace
