package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var quotaCmd = &cobra.Command{
	Use:   "quota",
	Short: "Show your own quotas and usage",
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		resp, err := internal.APIGet(internal.AdminAPIBase() + "/quota/self")
		if err != nil {
			dieErr(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			dieErr(fmt.Errorf("quota failed: %s %s", resp.Status, data))
		}
		var q internal.QuotaResponse
		if json.Unmarshal(data, &q) == nil {
			// Get username from JWT.
			username := "you"
			printQuotaTable(username, &q)
		} else {
			fmt.Println(string(data))
		}
	},
}

func init() {
	rootCmd.AddCommand(quotaCmd)
}
