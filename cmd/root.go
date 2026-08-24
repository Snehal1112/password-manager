/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/container"
	"rocketvault/internal/db"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/internal/retry"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)

// cfgFile is the config file name
var cfgFile string

// buildCommitHash, buildTime, and buildGoVersion hold the extra build
// metadata shown by --version alongside rootCmd.Version. Populated by
// SetVersionInfo, which main.go calls before Execute() with the values
// ldflags injected into its own package-level vars -- cmd cannot import
// main directly, since main already imports cmd.
var (
	buildCommitHash = "unknown"
	buildTime       = "unknown"
	buildGoVersion  = "unknown"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rocketvault",
	Short: "A secure password manager for secrets, keys, and certificates",
	Long: `RocketVault is a self-hosted vault for secrets, cryptographic keys, and
X.509 certificates. This single binary is both the server that stores them
(rocketvault serve) and the client used to administer it.

Commands run in local mode against the instance described by
.rocketvault.yaml; --config selects a different file. Remote mode (--server,
ROCKETVAULT_ADDR, or an active context) is implemented only for the context
group — every other command refuses to run while a remote target is set,
rather than silently falling back to the local instance.

Log in once with 'rocketvault users login'. The session is cached under
~/.rocketvault/sessions and refreshed automatically, so everyday commands need
no credential flags. These commands need no session at all: health, serve,
users admin, users login, users logout, the migrate commands, vaults
preview-migration, vault-access roles, secrets generate-password, and the
whole context group.

Secrets, keys, and certificates live inside a vault. Those commands act on the
vault named by --vault or ROCKETVAULT_VAULT, falling back to "default".`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Store a secret and read it back
  rocketvault secrets create <name> <value>
  rocketvault secrets get <id>

  # Start the API server
  rocketvault serve --listen :8774`,
	PersistentPreRunE:  persistentPreRun,
	PersistentPostRunE: persistentPostRun,
	// Run: func(cmd *cobra.Command, args []string) {},
}

// Execute adds all child commands to the root command, sets flags
// appropriately, and exits the process with the resulting status code.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	os.Exit(run(rootCmd))
}

// SetVersionInfo records the build metadata ldflags injected into main.go's
// package-level vars and wires it up to the --version flag Cobra
// auto-generates from rootCmd.Version. main.go must call this before
// Execute() -- ldflags targets main.Version etc., not this package, so
// there is no other path for that metadata to reach the CLI. See build.sh
// and .github/workflows/release.yml for the ldflags that populate the
// values passed in here.
func SetVersionInfo(version, commitHash, buildTimeVal, goVersion string) {
	rootCmd.Version = version
	buildCommitHash = commitHash
	buildTime = buildTimeVal
	buildGoVersion = goVersion
	rootCmd.SetVersionTemplate(`{{.Name}} version {{.Version}}
commit:     ` + buildCommitHash + `
built:      ` + buildTime + `
go version: ` + buildGoVersion + `
`)
}

// run executes cmd and returns the process exit code: 0 on success, 1 on
// any error. Separated from Execute so the exit-code decision is
// unit-testable without terminating the test binary via a real os.Exit
// call — see TestRun_ReturnsNonZeroOnError / TestRun_ReturnsZeroOnSuccess.
func run(cmd *cobra.Command) int {
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		return 1
	}
	return 0
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.rocketvault.yaml)")

	// Persistent flags for authentication.
	rootCmd.PersistentFlags().String("username", "", "Username for authentication")
	rootCmd.PersistentFlags().String("password", "", "Password for authentication")
	rootCmd.PersistentFlags().String("totp-code", "", "TOTP code for MFA")
	rootCmd.PersistentFlags().String("output", "table", "Output format: table, json, yaml")

	// Persistent flag selecting the target vault for resource commands.
	rootCmd.PersistentFlags().String("vault", "", "Target vault name (default: \"default\")")
	_ = viper.BindPFlag("vault", rootCmd.PersistentFlags().Lookup("vault"))

	// Persistent flag selecting a remote RocketVault server to target,
	// instead of local mode against .rocketvault.yaml.
	rootCmd.PersistentFlags().String("server", "", "Remote RocketVault server URL (default: local mode against .rocketvault.yaml)")
	rootCmd.PersistentFlags().String("ca-cert", "", "Path to an additional CA certificate to trust for remote server connections (or set ROCKETVAULT_CA_CERT)")
	rootCmd.PersistentFlags().Bool("insecure-skip-verify", false, "Disable TLS certificate verification for remote server connections (unsafe — dev/test only)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// isContextCommandArgs reports whether the command cobra is about to
// execute for the given post-binary-name args is part of the `context`
// command group (add/list/use/current/remove). It re-runs cobra's own
// command-resolution logic (rootCmd.Find) rather than string-matching args
// directly, so it stays correct regardless of global-flag placement.
//
// This exists because initConfig runs as a cobra.OnInitialize hook, which
// cobra invokes with no *cobra.Command argument — unlike persistentPreRun,
// which does receive one and does its own equivalent check directly. See
// C1 in the 2026-08-17 final review: context commands must never require a
// local config file/database, and previously nothing exempted them from
// initConfig's panic when neither was present.
func isContextCommandArgs(args []string) bool {
	cmd, _, err := rootCmd.Find(args)
	if err != nil || cmd == nil {
		return false
	}
	return cmd.Name() == "context" || (cmd.Parent() != nil && cmd.Parent().Name() == "context")
}

// isCobraBuiltinCommand reports whether cmd is one cobra adds automatically
// rather than one this project defines: "help", the "completion" group and
// its per-shell subcommands, and the hidden "__complete"/"__completeNoDesc"
// commands shell completion scripts invoke on every keystroke. None of these
// talk to a server or a local database, so they must never be blocked by the
// remote-target guard below — see NB1 in the 2026-08-17 final review: with an
// active context, `rocketvault help` and `rocketvault completion bash` (and
// therefore live shell tab-completion) were refused outright.
func isCobraBuiltinCommand(cmd *cobra.Command) bool {
	switch cmd.Name() {
	case "help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
		return true
	}
	return cmd.Parent() != nil && cmd.Parent().Name() == "completion"
}

// isLocalOnlyCommand reports whether cmd never needs to contact any
// server -- local or remote -- so it must be exempt from the remote-target
// guard the same way isContextGroup and isCobraBuiltinCommand are.
// "vault-access roles" reads only compiled-in role definitions (see its own
// doc comment: "Requires no authentication: this reads only compiled-in
// role definitions, never the database.") -- --server or an active context
// must not block it, since it was never going to touch a server either way.
func isLocalOnlyCommand(cmd *cobra.Command) bool {
	if cmd.Name() == "roles" && cmd.Parent() != nil && cmd.Parent().Name() == "vault-access" {
		return true
	}
	// generate-password is pure local RNG (see cmd/secrets/generate.go): it
	// stores nothing and touches no vault, local or remote, so it needs no
	// local/remote distinction any more than "vault-access roles" does.
	return cmd.Name() == "generate-password" && cmd.Parent() != nil && cmd.Parent().Name() == "secrets"
}

// remoteCapableSecretsCommands are the "secrets" subcommands with their own
// remote-mode adapter in internal/cliclient/secrets.go — see
// docs/superpowers/specs/2026-08-17-cli-remote-server-support-design.md's
// Command Support Matrix. Other resource groups (keys, certificates,
// vaults, vault-access, users, audit) still go through the remote-target
// guard until each gets its own adapter.
var remoteCapableSecretsCommands = map[string]bool{
	"list":   true,
	"get":    true,
	"create": true,
	"update": true,
	"delete": true,
	"export": true,
	"import": true,
}

// isRemoteCapableCommand reports whether cmd has its own remote-mode
// adapter and should be let through the remote-target guard instead of
// being rejected by it.
func isRemoteCapableCommand(cmd *cobra.Command) bool {
	return cmd.Parent() != nil && cmd.Parent().Name() == "secrets" && remoteCapableSecretsCommands[cmd.Name()]
}

// isSystemCommand reports whether cmd is exempt from persistentPreRun's
// authentication requirement -- either because it performs no vault/data
// operation at all (e.g. "health", "roles", "generate-password"), or
// because it is itself part of bootstrapping or clearing a session (e.g.
// "login", "logout"). Checked against both cmd.Name() and, for a leaf
// command, its parent's name, so a whole command group (e.g. "context")
// can be exempted at once.
func isSystemCommand(cmd *cobra.Command) bool {
	systemCmds := map[string]bool{
		"health":                        true,
		"serve":                         true, // Server startup doesn't require prior authentication
		"admin":                         true, // Allow admin registration without prior authentication
		"migrate":                       true, // Database migrations don't require authentication
		"migrate:status":                true, // Migration status check
		"migrate:to":                    true, // Targeted migrations
		"migrate:create":                true, // Migration file creation
		"roles":                         true, // Lists built-in vault roles; pure client-side, no auth needed
		"preview-migration":             true, // Reads ownership to plan role assignments; no auth, no writes
		"login":                         true, // Bootstraps a session (password or --oidc); cannot itself require one
		"logout":                        true, // Clears a cached session; must work even if that session is broken
		"context":                       true, // Local-only config (add/list/use/current/remove); no DB, no auth
		"help":                          true, // Cobra built-in; must never require login (see isCobraBuiltinCommand)
		"completion":                    true, // Cobra built-in; ditto, for the per-shell completion-script commands
		"generate-password":             true, // Pure local RNG; stores nothing, touches no vault -- see B41
		cobra.ShellCompRequestCmd:       true, // "__complete" -- invoked by live shell tab-completion
		cobra.ShellCompNoDescRequestCmd: true, // "__completeNoDesc" -- ditto, no-description variant
	}

	if systemCmds[cmd.Name()] {
		return true
	}
	return cmd.Parent() != nil && systemCmds[cmd.Parent().Name()]
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		// home, err := os.UserHomeDir()
		// cobra.CheckErr(err)

		// Search config in home directory with name ".rocketvault" (without extension).
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".rocketvault")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in. A missing/unreadable config
	// file is fatal in local mode (today's behavior, unchanged) but not in
	// remote mode — remote mode needs no local database or crypto config at
	// all, only a target server — nor for the `context` command group, which
	// never needs a local database/config at all, remote target or not (it
	// only reads/writes ~/.rocketvault/contexts.json).
	if err := viper.ReadInConfig(); err != nil && !isContextCommandArgs(os.Args[1:]) {
		serverFlag, _ := rootCmd.PersistentFlags().GetString("server")
		target, targetErr := cliclient.ResolveTarget(serverFlag)
		if targetErr != nil || target == nil {
			log.Panicf("Error reading config file: %v (%s)", err, viper.ConfigFileUsed())
		}
	}

	// Configure retry system with defaults and environment variable bindings.
	retry.SetRetryDefaults(viper.GetViper())
	retry.BindRetryConfig(viper.GetViper())
}

// resolveAuthentication determines the CLI caller's identity for a command
// that requires authentication. It tries, in order:
//  1. --username + --password (+ --totp-code): fresh password/TOTP login,
//     cached to disk on success.
//  2. --username alone (no --password): load that user's cached session.
//  3. no flags at all: load whichever session ~/.rocketvault/sessions/current
//     currently points at.
//
// A cached session past its ExpiresAt is refreshed transparently via its
// refresh token (and the cache updated) before being returned.
func resolveAuthentication(cmd *cobra.Command, authSvc authServices.AuthenticationService) (*authServices.AuthenticationResult, error) {
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	totpCode, _ := cmd.Flags().GetString("totp-code")

	if username != "" && password != "" {
		result, err := authSvc.AuthenticateUser(cmd.Context(), username, password, totpCode)
		if err != nil {
			return nil, err
		}
		if saveErr := common.SaveSession(&common.SessionCache{
			Token:        result.Token,
			RefreshToken: result.RefreshToken,
			UserID:       result.UserID,
			Username:     result.Username,
			Roles:        result.Roles,
			ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
		}); saveErr != nil {
			logrus.WithError(saveErr).Warn("failed to cache CLI session")
		}
		return result, nil
	}

	var cached *common.SessionCache
	var err error
	if username != "" {
		cached, err = common.LoadSession(username)
	} else {
		cached, err = common.LoadCurrentSession()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read cached session: %w", err)
	}
	if cached == nil {
		return nil, errors.New("no credentials provided and no cached session found")
	}

	if time.Now().Before(cached.ExpiresAt) {
		claims, validateErr := authSvc.ValidateSession(cmd.Context(), cached.Token)
		if validateErr == nil {
			return &authServices.AuthenticationResult{
				Token:        cached.Token,
				RefreshToken: cached.RefreshToken,
				UserID:       claims.UserID,
				Username:     claims.Username,
				Roles:        claims.Roles,
			}, nil
		}
		// The cache file's ExpiresAt is only a pre-filter — it can't see
		// server-side revocation. A ValidateSession failure here (expired,
		// revoked, or malformed) falls through to the same refresh attempt
		// used when the cache file itself says it's already expired.
	}

	refreshed, err := authSvc.RefreshAccessToken(cmd.Context(), cached.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("cached session expired and refresh failed: %w", err)
	}

	if saveErr := common.SaveSession(&common.SessionCache{
		Token:        refreshed.Token,
		RefreshToken: refreshed.RefreshToken,
		UserID:       refreshed.UserID,
		Username:     refreshed.Username,
		Roles:        refreshed.Roles,
		ExpiresAt:    refreshed.ExpiresAt,
	}); saveErr != nil {
		logrus.WithError(saveErr).Warn("failed to cache refreshed CLI session")
	}

	return &authServices.AuthenticationResult{
		Token:        refreshed.Token,
		RefreshToken: refreshed.RefreshToken,
		UserID:       refreshed.UserID,
		Username:     refreshed.Username,
		Roles:        refreshed.Roles,
	}, nil
}

// resolveRemoteAuthentication is resolveAuthentication's remote-mode
// counterpart: same three-tier precedence (fresh login > cached session for
// an explicit --username > whichever session is "current"), but every call
// goes to target.Server over HTTP instead of the local service container.
//
// The "current" session pointer is global across servers (see
// common/session.go), so when no --username is given, a cached current
// session is only used if it actually belongs to this target -- otherwise a
// different server's token could leak into a request against this one.
func resolveRemoteAuthentication(cmd *cobra.Command, target *cliclient.Target, httpClient *http.Client) (*authServices.AuthenticationResult, error) {
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	totpCode, _ := cmd.Flags().GetString("totp-code")
	if username == "" {
		username = target.Username // context's default username, if any
	}

	serverKey := common.SanitizeServerKey(target.Server)

	if username != "" && password != "" {
		result, err := cliclient.LoginRemote(cmd.Context(), httpClient, target.Server, username, password, totpCode)
		if err != nil {
			return nil, err
		}
		if saveErr := common.SaveSession(&common.SessionCache{
			Token:        result.Token,
			RefreshToken: result.RefreshToken,
			UserID:       result.UserID,
			Username:     result.Username,
			Roles:        result.Roles,
			ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
			ServerKey:    serverKey,
		}); saveErr != nil {
			logrus.WithError(saveErr).Warn("failed to cache remote CLI session")
		}
		return result, nil
	}

	var cached *common.SessionCache
	var err error
	if username != "" {
		cached, err = common.LoadSessionForServer(serverKey, username)
	} else {
		cached, err = common.LoadCurrentSession()
		if cached != nil && cached.ServerKey != serverKey {
			cached = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read cached session: %w", err)
	}
	if cached == nil {
		return nil, fmt.Errorf("no credentials provided and no cached session found for server %s; pass --username/--password/--totp-code", target.Server)
	}

	if time.Now().Before(cached.ExpiresAt) {
		return &authServices.AuthenticationResult{
			Token:        cached.Token,
			RefreshToken: cached.RefreshToken,
			UserID:       cached.UserID,
			Username:     cached.Username,
			Roles:        cached.Roles,
		}, nil
	}

	refreshed, err := cliclient.RefreshRemote(cmd.Context(), httpClient, target.Server, cached.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("cached session expired and refresh failed: %w", err)
	}

	if saveErr := common.SaveSession(&common.SessionCache{
		Token:        refreshed.Token,
		RefreshToken: refreshed.RefreshToken,
		UserID:       refreshed.UserID,
		Username:     refreshed.Username,
		Roles:        refreshed.Roles,
		ExpiresAt:    refreshed.ExpiresAt,
		ServerKey:    serverKey,
	}); saveErr != nil {
		logrus.WithError(saveErr).Warn("failed to cache refreshed remote CLI session")
	}

	return &authServices.AuthenticationResult{
		Token:        refreshed.Token,
		RefreshToken: refreshed.RefreshToken,
		UserID:       refreshed.UserID,
		Username:     refreshed.Username,
		Roles:        refreshed.Roles,
	}, nil
}

// remotePersistentPreRun is the remote-mode counterpart of persistentPreRun
// for commands with their own remote adapter (see isRemoteCapableCommand).
// It never boots the local DB or service container: it configures a TLS
// trust-aware HTTP client, authenticates against target.Server, and stashes
// the token/target/client in the command's context for the adapter to use.
func remotePersistentPreRun(cmd *cobra.Command, target *cliclient.Target) error {
	caCertPath, _ := cmd.Flags().GetString("ca-cert")
	if caCertPath == "" {
		caCertPath = os.Getenv("ROCKETVAULT_CA_CERT")
	}
	insecureSkipVerify, _ := cmd.Flags().GetBool("insecure-skip-verify")

	opts := cliclient.HTTPClientOptions{CACertPath: caCertPath, InsecureSkipVerify: insecureSkipVerify}
	cliclient.WarnIfInsecure(opts)
	httpClient, err := cliclient.NewHTTPClient(opts)
	if err != nil {
		return fmt.Errorf("failed to configure remote TLS trust: %w", err)
	}

	authResult, err := resolveRemoteAuthentication(cmd, target, httpClient)
	if err != nil {
		cmd.PrintErrln("Error: remote authentication failed -", err.Error())
		return errors.New("remote authentication failed")
	}

	ctx := context.WithValue(cmd.Context(), common.TokenKey, authResult.Token)
	ctx = context.WithValue(ctx, common.UserIDKey, authResult.UserID)
	ctx = context.WithValue(ctx, common.RemoteTargetKey, target)
	ctx = context.WithValue(ctx, common.RemoteHTTPClientKey, httpClient)

	outputFlag, _ := cmd.Flags().GetString("output")
	fmtr, fmtrErr := formatter.New(formatter.Format(outputFlag))
	if fmtrErr != nil {
		return fmt.Errorf("invalid --output value %q: must be table, json, or yaml", outputFlag)
	}
	ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
	cmd.SetContext(ctx)

	logrus.WithFields(logrus.Fields{
		"command": cmd.Short,
		"server":  target.Server,
		"user":    authResult.Username,
	}).Info("Authenticated against remote server")
	return nil
}

// persistentPreRun is a Cobra persistent pre-run function that initializes logging,
// database connection, and authentication context for the command execution.
// It checks for restricted commands, initializes the logger and database, and
// sets up the context with database, logger, and user authentication information.
// If username or password flags are missing, or authentication fails, it logs
// an audit error and exits the application.
//
// Parameters:
//   - cmd: *cobra.Command - the command being executed
//   - args: []string - the command-line arguments
//
// Return type: none
func persistentPreRun(cmd *cobra.Command, args []string) error {
	logrus.Info("Persistent PreRun called for command:", cmd.Name())

	// System commands that don't require authentication -- see isSystemCommand.
	isSystemCmd := isSystemCommand(cmd)

	// Remote-target guard: a command that resolves a remote target (via
	// --server, ROCKETVAULT_ADDR, or the current context) must never
	// silently fall back to operating on the local instance — see the CLI
	// remote-server design spec's Global Constraint #3
	// (docs/superpowers/specs/2026-08-17-cli-remote-server-support-design.md).
	// The `context` group is exempt: it only reads/writes local config
	// (~/.rocketvault/contexts.json) and never talks to a server itself.
	// Cobra's own built-in commands (help, completion, and the hidden
	// completion-request commands) are exempt for the same reason — see
	// isCobraBuiltinCommand.
	//
	// This guard is intentionally temporary scaffolding, not a permanent
	// architectural fixture. As each resource group's own remote adapter
	// plan lands (secrets, keys, certificates, vaults, vault-access, users,
	// audit — see the design spec's Command Support Matrix), that group
	// gains real remote support and should be carved out of this blanket
	// check (e.g. by extending isContextGroup-style exemptions, or by
	// replacing this check with a per-command capability check once most
	// groups are remote-capable). Once every command either supports remote
	// mode or has its own explicit local-only refusal (see
	// internal/cliclient.RequireLocal), this guard should be deleted
	// entirely.
	isContextGroup := cmd.Name() == "context" || (cmd.Parent() != nil && cmd.Parent().Name() == "context")
	serverFlag, _ := cmd.Flags().GetString("server")
	target, targetErr := cliclient.ResolveTarget(serverFlag)
	if targetErr != nil {
		return fmt.Errorf("failed to resolve remote target: %w", targetErr)
	}

	// A "secrets" subcommand with its own remote adapter (see
	// isRemoteCapableCommand) hands off to a dedicated remote pre-run
	// instead of booting the local DB/service container at all.
	if target != nil && isRemoteCapableCommand(cmd) {
		return remotePersistentPreRun(cmd, target)
	}

	if target != nil && !isContextGroup && !isCobraBuiltinCommand(cmd) && !isLocalOnlyCommand(cmd) {
		return fmt.Errorf(
			"remote mode (--server/ROCKETVAULT_ADDR/context %q) is not yet supported for %q; unset it to run against the local instance",
			target.Server, cmd.CommandPath(),
		)
	}

	// Initialize the logger.
	log := logging.InitLogger()
	// Start log rotation goroutine
	go log.StartPeriodicRotation()

	// Ensure database is initialized. A failure here must abort startup for
	// any command that actually needs the database: every downstream
	// repository is constructed from database.GetDB(), which returns nil if
	// InitializeDB errored, and callers dereference that connection with no
	// nil-check (it's not expected to ever be nil outside the unit-test
	// path) -- silently continuing turns any schema/connection failure into
	// a nil-pointer panic deep inside an unrelated command instead of a
	// clean error here.
	//
	// context/help/completion/vault-access roles/secrets generate-password are exempt, same as the remote-target guard
	// above: they are documented as local-only/no-DB and must keep working
	// even with no database configured at all (e.g. `rocketvault context
	// list` before .rocketvault.yaml exists).
	database := db.NewRepository(log)
	if err := database.InitializeDB(); err != nil {
		if !isContextGroup && !isCobraBuiltinCommand(cmd) && !isLocalOnlyCommand(cmd) {
			return fmt.Errorf("database initialization failed: %w", err)
		}
		log.WithError(err).Warn("Database initialization failed; continuing since this command does not require it")
	}

	// Create service container
	serviceContainer, err := container.NewServiceContainer(container.Config{
		Database: database.GetDB(),
		Logger:   log,
	})
	if err != nil {
		log.LogAuditError("", "init_services", "failed", "Failed to initialize service container", err)
		return errors.New("failed to initialize services")
	}

	ctx := context.WithValue(cmd.Context(), common.DBKey, database.GetDB())
	ctx = context.WithValue(ctx, common.DBClassKey, database)
	ctx = context.WithValue(ctx, common.LogKey, log)
	ctx = context.WithValue(ctx, common.ServiceContainerKey, serviceContainer)

	outputFlag, _ := cmd.Flags().GetString("output")
	fmtr, fmtrErr := formatter.New(formatter.Format(outputFlag))
	if fmtrErr != nil {
		return fmt.Errorf("invalid --output value %q: must be table, json, or yaml", outputFlag)
	}
	ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
	cmd.SetContext(ctx)

	// Skip authentication for system commands
	if isSystemCmd {
		log.WithField("command", cmd.Name()).Info("System command executed without authentication")
		return nil
	}

	authService := serviceContainer.GetAuthenticationService()
	authResult, err := resolveAuthentication(cmd, authService)
	if err != nil {
		log.LogAuditError("", "secrets", "failed", "Authentication failed", err)
		cmd.PrintErrln("Error: Authentication failed -", err.Error())
		cmd.PrintErrln("Run 'rocketvault users login' or 'rocketvault users login --oidc' first, or pass --username/--password/--totp-code.")
		return errors.New("authentication failed")
	}

	// Create claims from authentication result (no need to parse JWT)
	claims := &model.Claims{
		UserID:   authResult.UserID,
		Username: authResult.Username,
		Roles:    authResult.Roles,
	}

	// Log successful authentication.
	ctx = context.WithValue(ctx, common.TokenKey, authResult.Token)
	// Add userID to context.
	ctx = context.WithValue(ctx, common.UserIDKey, claims.UserID)
	// Add claims to context for further use in the command.
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	cmd.SetContext(ctx)

	jwtPreviewLen := 10
	if len(authResult.Token) < jwtPreviewLen {
		jwtPreviewLen = len(authResult.Token)
	}
	log.WithFields(logrus.Fields{
		"command":  cmd.Short,
		"jwt":      authResult.Token[:jwtPreviewLen] + "...",
		"userID":   claims.UserID,
		"username": authResult.Username,
	}).Info("User authenticated successfully")
	return nil
}

// persistentPostRun is a Cobra persistent post-run function that closes the database connection
// after the command execution. It checks if the command is restricted and if so,
// it skips closing the database connection. Otherwise, it safely closes the database
// connection to ensure no resources are leaked.
// Parameters:
//   - cmd: *cobra.Command - the command that was executed
//   - args: []string - the command-line arguments
//
// Return type: error - returns nil if successful, or an error if closing the database fails.
func persistentPostRun(cmd *cobra.Command, args []string) error {
	if dbRepo, ok := cmd.Context().Value(common.DBClassKey).(*db.DBRepository); ok {
		return dbRepo.CloseDB()
	}
	return nil
}
