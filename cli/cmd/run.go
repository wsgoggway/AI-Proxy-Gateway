package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command through the proxy (auto env/sandbox)",
	Long: "Launches a command inside a bwrap sandbox with proxy env vars,\n" +
		"CA bundle overlay, and credential injection.\n\n" +
		"Flags:\n" +
		"  --no-sandbox   env-only mode (no bwrap isolation)\n\n" +
		"All arguments after the command name are passed through verbatim.\n" +
		"Use -- to separate apx flags from the command's own flags.",
	// Disable cobra flag parsing so flags like -s, -o belong to the child command.
	// We manually extract --no-sandbox before dispatching.
	DisableFlagParsing: true,
	Run: func(cmd *cobra.Command, args []string) {
		useSandbox := true
		var cmdArgs []string
		for _, a := range args {
			if a == "--no-sandbox" && len(cmdArgs) == 0 {
				useSandbox = false
				continue
			}
			if a == "--sandbox" && len(cmdArgs) == 0 {
				continue // already default
			}
			if a == "--bwrap" && len(cmdArgs) == 0 {
				continue // alias
			}
			if a == "--" && len(cmdArgs) == 0 {
				continue // separator
			}
			cmdArgs = append(cmdArgs, a)
		}
		if len(cmdArgs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: apx run [--no-sandbox] <command> [args...]")
			os.Exit(1)
		}
		if err := internal.QuickCheck(); err != nil {
			fmt.Fprintf(os.Stderr, "apx: %v\nRun 'apx install' first.\n", err)
			os.Exit(1)
		}
		if useSandbox {
			internal.RunSandbox(cmdArgs)
		} else {
			internal.RunEnv(cmdArgs)
		}
	},
}

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Interactive shell through the proxy",
	Run: func(cmd *cobra.Command, args []string) {
		internal.RunShell()
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(shellCmd)
}

// guard unused import
var _ = strings.TrimSpace
