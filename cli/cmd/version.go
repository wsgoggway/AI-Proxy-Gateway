package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("apx %s\n", internal.Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
