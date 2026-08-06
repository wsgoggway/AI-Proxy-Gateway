package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var uninstallPurge bool

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove all AI Proxy files (CA, config, bundle)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", internal.Title("AI Proxy — uninstall"))

		legacyCA := filepath.Join(internal.Home(), "ai-proxy-ca.pem")
		fmt.Println("This will remove:")
		fmt.Printf("  %s %s\n", internal.Dim("-"), internal.Cfg.CAFile)
		fmt.Printf("  %s %s\n", internal.Dim("-"), internal.Cfg.CacheDir+"/")
		fmt.Printf("  %s %s\n", internal.Dim("-"), internal.Cfg.EnvConfig)
		if internal.FileExists(legacyCA) {
			fmt.Printf("  %s %s\n", internal.Dim("-"), legacyCA)
		}
		if uninstallPurge {
			fmt.Printf("  %s %s\n", internal.Dim("-"), filepath.Join(internal.Cfg.BinDir, "apx"))
		}

		confirm := &survey.Confirm{
			Message: "Remove all AI Proxy files?",
			Default: false,
		}
		sure := false
		if err := survey.AskOne(confirm, &sure); err != nil {
			return
		}
		if !sure {
			fmt.Println("Cancelled.")
			return
		}

		for _, f := range []string{internal.Cfg.CAFile, legacyCA, internal.Cfg.EnvConfig} {
			if internal.FileExists(f) {
				if err := os.Remove(f); err != nil {
					fmt.Fprintf(os.Stderr, "%s remove %s: %v\n", internal.Warn("⚠"), f, err)
				} else {
					fmt.Printf("  %s %s %s\n", internal.Success("✓"), internal.Dim("removed:"), f)
				}
			}
		}
		if internal.DirExists(internal.Cfg.CacheDir) {
			if err := os.RemoveAll(internal.Cfg.CacheDir); err != nil {
				fmt.Fprintf(os.Stderr, "%s remove %s: %v\n", internal.Warn("⚠"), internal.Cfg.CacheDir, err)
			} else {
				fmt.Printf("  %s %s %s\n", internal.Success("✓"), internal.Dim("removed:"), internal.Cfg.CacheDir+"/")
			}
		}
		if uninstallPurge {
			apxBin := filepath.Join(internal.Cfg.BinDir, "apx")
			if internal.FileExists(apxBin) {
				if err := os.Remove(apxBin); err != nil {
					fmt.Fprintf(os.Stderr, "%s remove %s: %v\n", internal.Warn("⚠"), apxBin, err)
				} else {
					fmt.Printf("  %s %s %s\n", internal.Success("✓"), internal.Dim("removed:"), apxBin)
				}
			}
		}

		internal.RemoveShellEnv()
		internal.CleanupSystemProxy()

		if runtime.GOOS == "darwin" {
			exec.Command("security", "delete-certificate", "-c", "AI Proxy CA").Run()
		}

		if entries, err := os.ReadDir(internal.Cfg.CfgDir); err == nil && len(entries) == 0 {
			os.Remove(internal.Cfg.CfgDir)
		}

		fmt.Println()
		fmt.Println(internal.Success("Done — AI Proxy removed."))
	},
}

func init() {
	uninstallCmd.Flags().BoolVar(&uninstallPurge, "purge", false, "also remove the apx binary")
	rootCmd.AddCommand(uninstallCmd)
}
