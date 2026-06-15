package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Snowflake via browser OAuth",
	Long: `Opens your browser to authenticate with Snowflake using OAuth.

This is the recommended authentication method. After logging in, your
credentials are cached locally and refreshed automatically.

Requires snowflake-account and snowflake-user to be configured:
  openant config set snowflake-account
  openant config set snowflake-user

The PAT-based authentication (openant config set snowflake-pat) still
works as a fallback but is no longer required.`,
	Run: runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear cached OAuth credentials",
	Long:  `Removes the cached OAuth token, requiring re-authentication on next use.`,
	Run:   runLogout,
}

func init() {
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
}

func runLogin(cmd *cobra.Command, args []string) {
	account := resolvedSnowflakeAccount()
	user := resolvedSnowflakeUser()

	if account == "" {
		output.PrintError("Snowflake account not configured.\nRun: openant config set snowflake-account")
		os.Exit(2)
	}
	if user == "" {
		output.PrintError("Snowflake username not configured.\nRun: openant config set snowflake-user")
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	role := resolvedSnowflakeRole()

	// Run the Python auth module to trigger browser OAuth flow
	script := `from utilities.snowflake_auth import get_access_token; get_access_token()`
	pyCmd := exec.Command(rt.Path, "-c", script)
	pyCmd.Env = os.Environ()
	pyCmd.Env = python.SetEnvPublic(pyCmd.Env, "SNOWFLAKE_ACCOUNT", account)
	pyCmd.Env = python.SetEnvPublic(pyCmd.Env, "SNOWFLAKE_USER", user)
	if role != "" {
		pyCmd.Env = python.SetEnvPublic(pyCmd.Env, "SNOWFLAKE_ROLE", role)
	}
	pyCmd.Stdout = os.Stdout
	pyCmd.Stderr = os.Stderr
	pyCmd.Stdin = os.Stdin

	if err := pyCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		output.PrintError(fmt.Sprintf("Login failed: %s", err))
		os.Exit(1)
	}

	output.PrintSuccess("Logged in to Snowflake successfully.")
}

func runLogout(cmd *cobra.Command, args []string) {
	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	script := `from utilities.snowflake_auth import clear_cached_token; clear_cached_token()`
	pyCmd := exec.Command(rt.Path, "-c", script)
	pyCmd.Stdout = os.Stdout
	pyCmd.Stderr = os.Stderr

	if err := pyCmd.Run(); err != nil {
		output.PrintError(fmt.Sprintf("Logout failed: %s", err))
		os.Exit(1)
	}

	// Also clear the PAT from config if set
	cfg, err := config.Load()
	if err == nil && cfg.SnowflakePAT != "" {
		cfg.SnowflakePAT = ""
		_ = config.Save(cfg)
		fmt.Fprintln(os.Stderr, "PAT removed from config.")
	}

	output.PrintSuccess("Logged out of Snowflake.")
}
