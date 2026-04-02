// Package cmd implements the Cobra CLI commands for OpenAnt.
package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags.
var version = "dev"

// Persistent flags shared across commands.
var (
	jsonOutput          bool
	quiet               bool
	snowflakePATFlag    string
	snowflakeAccountFlag string
	projectFlag         string
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "openant",
	Short: "LLM-powered static analysis security testing",
	Long: `OpenAnt is a two-stage SAST tool that uses Claude to find real vulnerabilities
in Python, JavaScript, Go, and C/C++ codebases.

Stage 1: Detect potential vulnerabilities via code analysis
Stage 2: Simulate an attacker to eliminate false positives

Commands:
  scan          Full pipeline: parse → enhance → detect → verify → report
  parse         Extract code units from a repository
  enhance       Add security context to a parsed dataset
  analyze       Run Stage 1 vulnerability detection
  verify        Run Stage 2 attacker simulation
  build-output  Assemble pipeline_output.json from verified results
  dynamic-test  Docker-isolated exploit testing
  report        Generate reports from analysis results
  config        Manage CLI configuration (API key, etc.)`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

// resolvedSnowflakePAT returns the Snowflake PAT resolved from flag > config file.
func resolvedSnowflakePAT() string {
	return config.ResolveSnowflakePAT(snowflakePATFlag)
}

// resolvedSnowflakeAccount returns the Snowflake account resolved from flag > config file.
func resolvedSnowflakeAccount() string {
	return config.ResolveSnowflakeAccount(snowflakeAccountFlag)
}

// resolvedSnowflakeUser returns the Snowflake user from config.
func resolvedSnowflakeUser() string {
	return config.ResolveSnowflakeUser()
}

// requireSnowflakeCreds returns the resolved Snowflake PAT and account, or exits
// with a helpful error telling the user how to configure them.
func requireSnowflakeCreds() (string, string, string) {
	pat := resolvedSnowflakePAT()
	account := resolvedSnowflakeAccount()
	user := resolvedSnowflakeUser()
	if pat != "" && account != "" {
		return pat, account, user
	}
	fmt.Fprintln(os.Stderr, "Error: Snowflake credentials not configured.")
	fmt.Fprintln(os.Stderr, "")
	if pat == "" {
		fmt.Fprintln(os.Stderr, "  Missing: SNOWFLAKE_PAT")
	}
	if account == "" {
		fmt.Fprintln(os.Stderr, "  Missing: SNOWFLAKE_ACCOUNT")
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run:  openant config set snowflake-pat")
	fmt.Fprintln(os.Stderr, "      openant config set snowflake-account")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Generate a PAT in Snowsight: Settings → Authentication → Programmatic Access Tokens")
	os.Exit(2)
	return "", "", "" // unreachable
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output raw JSON (machine-readable)")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	rootCmd.PersistentFlags().StringVar(&snowflakePATFlag, "snowflake-pat", "", "Snowflake PAT (overrides config)")
	rootCmd.PersistentFlags().StringVar(&snowflakeAccountFlag, "snowflake-account", "", "Snowflake account identifier (overrides config)")
	rootCmd.PersistentFlags().StringVarP(&projectFlag, "project", "p", "", "Project to use (overrides active project, e.g. grafana/grafana)")

	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(parseCmd)
	rootCmd.AddCommand(enhanceCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(buildOutputCmd)
	rootCmd.AddCommand(dynamicTestCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(setAPIKeyCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(versionCmd)
}
