package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage proxy users (admin)",
}


// ── user add ──

var userAddDisplay, userAddNote string

var userAddCmd = &cobra.Command{
	Use:   "add USERNAME",
	Short: "Create a new user",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		payload := map[string]string{"username": args[0]}
		if userAddDisplay != "" {
			payload["display"] = userAddDisplay
		}
		if userAddNote != "" {
			payload["note"] = userAddNote
		}
		body, _ := json.Marshal(payload)
		resp, err := internal.AdminReq(internal.DirectClient(), internal.AdminAPIBase()+"/users", "POST", body)
		if err != nil {
			dieErr(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 201 {
			dieErr(fmt.Errorf("create failed: %s %s", resp.Status, data))
		}
		var created struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		json.Unmarshal(data, &created)
		fmt.Printf("%s User created: %s\n", internal.Success("✓"), created.Username)
		fmt.Printf("  %s %s\n", internal.Dim("one-time password:"), internal.Key(created.Password))
	},
}

// ── user list ──

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		users, err := internal.ListUsers()
		if err != nil {
			dieErr(err)
		}
		headers := []string{"USERNAME", "ROLE", "STATUS", "LAST LOGIN", "NOTE"}
		var rows [][]string
		for _, u := range users {
			last := "—"
			if u.LastLoginAt != nil {
				last = *u.LastLoginAt
			}
			role := ""
			if u.Role != nil {
				role = *u.Role
			}
			note := ""
			if u.Note != nil {
				note = *u.Note
			}
			rows = append(rows, []string{
				u.Username,
				internal.RoleBadge(role),
				internal.StatusBadge(u.Status),
				last,
				note,
			})
		}
		internal.PrintTable(headers, rows)
	},
}

// ── user delete (interactive) ──

var userDeleteCmd = &cobra.Command{
	Use:   "delete [USERNAME]",
	Short: "Delete a user (interactive if no username given)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		username := ""
		if len(args) > 0 {
			username = args[0]
		} else {
			users, err := internal.ListUsers()
			if err != nil {
				dieErr(err)
			}
			options := make([]string, len(users))
			for i, u := range users {
				options[i] = fmt.Sprintf("%s (%s)", u.Username, u.Status)
			}
			prompt := &survey.Select{
				Message: "Select user to delete:",
				Options: options,
			}
			var choice string
			if err := survey.AskOne(prompt, &choice); err != nil {
				return
			}
			username = strings.SplitN(choice, " ", 2)[0]
		}
		confirm := &survey.Confirm{
			Message: fmt.Sprintf("Delete user '%s'?", username),
			Default: false,
		}
		sure := false
		survey.AskOne(confirm, &sure)
		if !sure {
			fmt.Println("Cancelled.")
			return
		}
		uid, err := internal.ResolveUserID(username)
		if err != nil {
			dieErr(err)
		}
		resp, err := internal.AdminReq(internal.DirectClient(), internal.AdminAPIBase()+"/users/"+uid, "DELETE", nil)
		if err != nil {
			dieErr(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			dieErr(fmt.Errorf("delete failed: %s %s", resp.Status, data))
		}
		fmt.Printf("%s User '%s' deleted.\n", internal.Success("✓"), username)
	},
}

// ── user passwd ──

var userPasswdCmd = &cobra.Command{
	Use:   "passwd USERNAME",
	Short: "Reset user password",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		userActionPrint(args[0], "passwd", "POST")
	},
}

// ── user disable ──

var userDisableCmd = &cobra.Command{
	Use:   "disable USERNAME",
	Short: "Disable a user",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		userActionPrint(args[0], "disable", "POST")
	},
}

// ── user enable ──

var userEnableCmd = &cobra.Command{
	Use:   "enable USERNAME",
	Short: "Enable a user",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		userActionPrint(args[0], "enable", "POST")
	},
}

// ── user show ──

var userShowCmd = &cobra.Command{
	Use:   "show USERNAME",
	Short: "Show user details",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		uid, err := internal.ResolveUserID(args[0])
		if err != nil {
			dieErr(err)
		}
		resp, err := internal.AdminReq(internal.DirectClient(), internal.AdminAPIBase()+"/users/"+uid+"/quota", "GET", nil)
		if err != nil {
			dieErr(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			dieErr(fmt.Errorf("show failed: %s %s", resp.Status, data))
		}
		var q internal.QuotaResponse
		if json.Unmarshal(data, &q) == nil {
			printQuotaTable(args[0], &q)
		} else {
			fmt.Println(string(data))
		}
	},
}

// ── user quota ──

var userQuotaCmd = &cobra.Command{
	Use:   "quota USERNAME [--req-day N] [--tok-in N] [--tok-out N] [--bytes-in N] [--bytes-out N]",
	Short: "Show or update user quotas",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := requireAdmin(); err != nil {
			dieErr(err)
		}
		username := args[0]
		uid, err := internal.ResolveUserID(username)
		if err != nil {
			dieErr(err)
		}

		// If no quota flags set → show.
		anySet := cmd.Flags().Changed("req-day") || cmd.Flags().Changed("tok-in") ||
			cmd.Flags().Changed("tok-out") || cmd.Flags().Changed("bytes-in") ||
			cmd.Flags().Changed("bytes-out")

		if !anySet {
			resp, err := internal.AdminReq(internal.DirectClient(), internal.AdminAPIBase()+"/users/"+uid+"/quota", "GET", nil)
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
				printQuotaTable(username, &q)
			} else {
				fmt.Println(string(data))
			}
			return
		}

		// Update.
		payload := map[string]interface{}{}
		if cmd.Flags().Changed("req-day") {
			payload["req_day"] = quotaReqDay
		}
		if cmd.Flags().Changed("tok-in") {
			payload["tok_in"] = quotaTokIn
		}
		if cmd.Flags().Changed("tok-out") {
			payload["tok_out"] = quotaTokOut
		}
		if cmd.Flags().Changed("bytes-in") {
			payload["bytes_in"] = quotaBytesIn
		}
		if cmd.Flags().Changed("bytes-out") {
			payload["bytes_out"] = quotaBytesOut
		}
		body, _ := json.Marshal(payload)
		resp, err := internal.AdminReq(internal.DirectClient(), internal.AdminAPIBase()+"/users/"+uid+"/quota", "PUT", body)
		if err != nil {
			dieErr(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			dieErr(fmt.Errorf("quota update failed: %s %s", resp.Status, data))
		}
		fmt.Printf("%s Quota updated for %s\n", internal.Success("✓"), username)
	},
}

var (
	quotaReqDay   int64
	quotaTokIn    int64
	quotaTokOut   int64
	quotaBytesIn  int64
	quotaBytesOut int64
)

// ── helpers ──

func userActionPrint(username, action, method string) {
	uid, err := internal.ResolveUserID(username)
	if err != nil {
		dieErr(err)
	}
	resp, err := internal.AdminReq(internal.DirectClient(), internal.AdminAPIBase()+"/users/"+uid+"/"+action, method, nil)
	if err != nil {
		dieErr(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		dieErr(fmt.Errorf("%s failed: %s %s", action, resp.Status, data))
	}
	if action == "passwd" {
		var r struct {
			Password string `json:"password"`
		}
		json.Unmarshal(data, &r)
		fmt.Printf("%s New one-time password for %s: %s\n",
			internal.Success("✓"), username, internal.Key(r.Password))
	} else {
		fmt.Printf("%s %s: %s\n", internal.Success("✓"), action, strings.TrimSpace(string(data)))
	}
}

func printQuotaTable(username string, q *internal.QuotaResponse) {
	fmt.Printf("\n%s\n", internal.Title("Quota for "+username))
	headers := []string{"METRIC", "LIMIT", "USED TODAY", "%", "BAR"}
	var rows [][]string
	pct := func(used int64, limit *int64) (string, string) {
		if limit == nil {
			return "—", internal.ProgressBar(0)
		}
		if *limit == 0 {
			return "100", internal.ProgressBar(100)
		}
		p := float64(used) / float64(*limit) * 100
		return fmt.Sprintf("%.0f%%", p), internal.ProgressBar(p)
	}
	type row struct {
		name  string
		limit *int64
		used  int64
		fmtF  func(int64) string
	}
	metrics := []row{
		{"Requests", q.Quota.ReqDay, q.UsageToday.Req, func(v int64) string { return strconv.FormatInt(v, 10) }},
		{"Tokens In", q.Quota.TokIn, q.UsageToday.TokIn, internal.FormatTokens},
		{"Tokens Out", q.Quota.TokOut, q.UsageToday.TokOut, internal.FormatTokens},
		{"Bytes In", q.Quota.BytesIn, q.UsageToday.BytesIn, internal.FormatBytes},
		{"Bytes Out", q.Quota.BytesOut, q.UsageToday.BytesOut, internal.FormatBytes},
	}
	for _, m := range metrics {
		p, bar := pct(m.used, m.limit)
		rows = append(rows, []string{m.name, internal.FormatOptionalInt64(m.limit), m.fmtF(m.used), p, bar})
	}
	internal.PrintTable(headers, rows)
}

func init() {
	userAddCmd.Flags().StringVar(&userAddDisplay, "display", "", "display name")
	userAddCmd.Flags().StringVar(&userAddNote, "note", "", "note")

	userQuotaCmd.Flags().Int64Var(&quotaReqDay, "req-day", 0, "requests per day limit")
	userQuotaCmd.Flags().Int64Var(&quotaTokIn, "tok-in", 0, "input tokens limit")
	userQuotaCmd.Flags().Int64Var(&quotaTokOut, "tok-out", 0, "output tokens limit")
	userQuotaCmd.Flags().Int64Var(&quotaBytesIn, "bytes-in", 0, "input bytes limit")
	userQuotaCmd.Flags().Int64Var(&quotaBytesOut, "bytes-out", 0, "output bytes limit")

	userCmd.AddCommand(userAddCmd, userListCmd, userDeleteCmd, userPasswdCmd,
		userDisableCmd, userEnableCmd, userShowCmd, userQuotaCmd)
	rootCmd.AddCommand(userCmd)
}
