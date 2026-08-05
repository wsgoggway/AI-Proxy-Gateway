package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wsgoggway/AI-Proxy-Gateway/cli/internal"
)

var rootCmd = &cobra.Command{
	Use:   "apx",
	Short: "AI Proxy eXec — zero-root proxy launcher",
	Long: "apx manages proxy credentials, CA bundles, and launches apps\n" +
		"through the AI proxy with DPI/tokenization protection.\n\n" +
		"Use 'apx run <command>' to launch any app through the proxy.",
	SilenceUsage: true,
}

var (
	flagHost    string
	flagPort    string
	flagVerbose bool
)

func init() {
	rootCmd.PersistentFlags().StringVar(&flagHost, "host", "", "proxy host")
	rootCmd.PersistentFlags().StringVar(&flagPort, "port", "", "proxy port")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "verbose output")
	rootCmd.CompletionOptions.HiddenDefaultCmd = false

	// Cobra checks --help BEFORE preRun/OnInitialize, so initConfig won't
	// fire for help output. Wrap the help function to load config first,
	// then hide admin commands before the template renders.
	defaultHelp := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		initConfig()
		defaultHelp(cmd, args)
	})

	// Also call initConfig for normal command execution.
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	internal.Init()
	if flagHost != "" {
		internal.Cfg.ProxyHost = flagHost
		internal.Cfg.FlagHostSet = true
	}
	if flagPort != "" {
		internal.Cfg.ProxyPort = flagPort
		internal.Cfg.FlagPortSet = true
	}
	internal.Cfg.Verbose = flagVerbose
	internal.LoadEnvConfig()

	// Hide admin-only commands for non-admin users.
	hideAdmin := !internal.IsAdmin()
	userCmd.Hidden = hideAdmin
	metricsCmd.Hidden = hideAdmin
	quotaCmd.Hidden = hideAdmin
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func dieErr(err error) {
	fmt.Fprintf(os.Stderr, "%s %v\n", internal.Error("apx:"), err)
	os.Exit(1)
}

// requireAuth checks that the user has credentials loaded.
func requireAuth() error {
	if internal.Cfg.AuthToken == "" && internal.Cfg.LoginUser == "" {
		return fmt.Errorf("not logged in: run 'apx login' first")
	}
	return nil
}

// requireAdmin checks that the user is authenticated AND has admin role.
func requireAdmin() error {
	if err := requireAuth(); err != nil {
		return err
	}
	if !internal.IsAdmin() {
		return fmt.Errorf("admin access required (current role: user)")
	}
	return nil
}
