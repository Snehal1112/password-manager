package cmd

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/rekey"
	"rocketvault/model"
)

var (
	rotateOldKeyEnv string
	rotateNewKeyEnv string
	rotateDryRun    bool
	rotateBatchSize int
	rotateAssumeYes bool
)

// masterKeyCmd groups master-key maintenance operations. The noun group keeps
// it distinct from the unrelated "rotation" command (scheduled secret
// rotation) and "keys rotate" (per-key material rotation).
var masterKeyCmd = &cobra.Command{
	Use:   "master-key",
	Short: "Manage the master encryption key",
	Long: `Manage the master key that seals secrets, software key PEMs, and certificate
private keys at rest. The only operation today is "rotate", which re-encrypts
every sealed column onto a replacement key.

Requires the global admin role. The master key protects the whole instance,
so this is not a per-vault operation and --vault does not apply.

Key material is never passed on the command line: both keys are named by the
environment variable holding them, and the old key defaults to the master_key
in the configuration file.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Preview a rotation onto a new key, writing nothing
  export NEW_MASTER_KEY="$(openssl rand -base64 32)"
  rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run

  # Perform the rotation
  rocketvault master-key rotate --new-key-env NEW_MASTER_KEY`,
}

// masterKeyRotateCmd re-encrypts all master-key-sealed data onto a new key.
var masterKeyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Re-encrypt all stored data onto a new master key",
	Long: `Read every master-key-sealed value in the database, decrypt it with the old
key and write it back sealed with a new one. Five columns are covered:
secrets.value, secret_versions.value, keys.value, key_versions.value and
certificates.private_key — soft-deleted rows and version history included.
Key rows whose material lives in an HSM hold only a PKCS#11 label, so they
are counted as skipped and left alone.

Requires the global admin role. The key protects every vault at once, so
--vault does not apply.

Both keys are named by the environment variable holding them, so no key
material reaches the command line. The old key defaults to the master_key in
the configuration file; note that an exported MASTER_KEY overrides that file,
which is the usual reason a rotation reports both keys as identical. The new
key must be a fresh base64 32-byte key and is checked against the same
weak-key rules as a configured one.

Stop the RocketVault server and take a database backup first. A real run
prints both key sources and waits for you to type "yes" unless --yes is
given; --dry-run reports the same per-table counts and never prompts or
writes. Each table is fully read and classified before any of its rows are
written, and every update is guarded by the ciphertext it was planned
against, so a row changed underneath the run (a server still running) aborts
it instead of being clobbered. Interrupting is therefore safe: rows already
carrying the new key are recognised and skipped, so re-running with the same
key pair resumes where it stopped.

When it completes, set the new key as master_key in the configuration (or as
MASTER_KEY) and restart the server — nothing is written back to the config
file for you. Backup files made with "rocketvault backup create" are not
touched by this command and stay sealed under the old key, so keep that key
if you may need to restore one.`,
	Example: `  # Preview what would be re-encrypted, without writing
  export NEW_MASTER_KEY="$(openssl rand -base64 32)"
  rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run

  # Perform the rotation, answering the confirmation prompt
  rocketvault master-key rotate --new-key-env NEW_MASTER_KEY

  # Take the old key from an environment variable instead of the config file
  rocketvault master-key rotate --old-key-env OLD_MASTER_KEY \
    --new-key-env NEW_MASTER_KEY

  # Unattended run with smaller transactions
  rocketvault master-key rotate --new-key-env NEW_MASTER_KEY \
    --batch-size 50 --yes`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMasterKeyRotate(cmd)
	},
}

func init() {
	rootCmd.AddCommand(masterKeyCmd)
	masterKeyCmd.AddCommand(masterKeyRotateCmd)

	masterKeyRotateCmd.Flags().StringVar(&rotateNewKeyEnv, "new-key-env", "",
		"Name of the environment variable holding the new base64 master key (required)")
	masterKeyRotateCmd.Flags().StringVar(&rotateOldKeyEnv, "old-key-env", "",
		"Name of the environment variable holding the old base64 master key (default: master_key from config)")
	masterKeyRotateCmd.Flags().BoolVar(&rotateDryRun, "dry-run", false,
		"Report what would be re-encrypted without writing anything")
	masterKeyRotateCmd.Flags().IntVar(&rotateBatchSize, "batch-size", rekey.DefaultBatchSize,
		"Number of row updates per transaction")
	masterKeyRotateCmd.Flags().BoolVar(&rotateAssumeYes, "yes", false,
		"Skip the confirmation prompt on a real run")
	masterKeyRotateCmd.MarkFlagRequired("new-key-env") //nolint:errcheck,gosec
}

// requireMasterKeyAdmin returns the caller's claims if they are logged in as
// admin. Rotation rewrites every vault's data, so there is no vault to scope
// it to -- the global admin role is the only applicable gate, same as backup.
//
// Parameters:
//
//	cmd: The running command, carrying the authenticated context.
//
// Returns:
//
//	The caller's claims, or an error if they are missing or not an admin.
func requireMasterKeyAdmin(cmd *cobra.Command) (*model.Claims, error) {
	claims, ok := cmd.Context().Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("unauthorized: missing authentication claims")
	}
	if claims.Role != model.RoleAdmin {
		return nil, fmt.Errorf("forbidden: requires admin role")
	}
	return claims, nil
}

// resolveRotationKeys reads and validates both master keys. Keys are taken
// from environment variables by name (or, for the old key, from the running
// configuration) so no key material reaches the process argument list. The new
// key must pass the full weak-key validation; the old key only needs to be
// structurally valid, because it is by definition the key being retired.
//
// Parameters:
//
//	oldKeyEnv: Name of the environment variable holding the old key, or "" to use the config value.
//	newKeyEnv: Name of the environment variable holding the new key.
//
// Returns:
//
//	The raw old and new keys, a human-readable description of where the old key
//	came from, and an error if either key is missing, invalid, or identical to
//	the other.
func resolveRotationKeys(oldKeyEnv, newKeyEnv string) (oldKey, newKey []byte, oldSource string, err error) {
	oldEncoded := viper.GetString("master_key")
	oldSource = "config file (master_key)"
	if oldKeyEnv != "" {
		oldEncoded = os.Getenv(oldKeyEnv)
		oldSource = "environment variable " + oldKeyEnv
	}
	if oldEncoded == "" {
		return nil, nil, "", fmt.Errorf("the old master key is empty (source: %s)", oldSource)
	}

	if newKeyEnv == "" {
		return nil, nil, "", errors.New("--new-key-env is required")
	}
	newEncoded := os.Getenv(newKeyEnv)
	if newEncoded == "" {
		return nil, nil, "", fmt.Errorf("environment variable %s is empty — generate a key with "+
			"\"openssl rand -base64 32\" and export it", newKeyEnv)
	}

	if newEncoded == oldEncoded {
		return nil, nil, "", fmt.Errorf("the new master key is identical to the old one (old key "+
			"source: %s); note that an exported MASTER_KEY environment variable takes precedence "+
			"over the config file", oldSource)
	}

	oldKey, err = common.ParseMasterKey(oldEncoded)
	if err != nil {
		return nil, nil, "", fmt.Errorf("old master key: %w", err)
	}
	if err := common.ValidateMasterKey(newEncoded); err != nil {
		return nil, nil, "", fmt.Errorf("new master key: %w", err)
	}
	newKey, err = common.ParseMasterKey(newEncoded)
	if err != nil {
		return nil, nil, "", fmt.Errorf("new master key: %w", err)
	}

	return oldKey, newKey, oldSource, nil
}

// runMasterKeyRotate drives a dry run or a real master key rotation.
func runMasterKeyRotate(cmd *cobra.Command) error {
	if _, err := requireMasterKeyAdmin(cmd); err != nil {
		return err
	}

	ctx := cmd.Context()
	rawDB, ok := ctx.Value(common.DBKey).(*sql.DB)
	if !ok || rawDB == nil {
		return errors.New("database connection not available")
	}
	logger, ok := ctx.Value(common.LogKey).(*logging.Logger)
	if !ok || logger == nil {
		return errors.New("logger not available")
	}

	oldKey, newKey, oldSource, err := resolveRotationKeys(rotateOldKeyEnv, rotateNewKeyEnv)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	mode := "REAL RUN (rows will be rewritten)"
	if rotateDryRun {
		mode = "DRY RUN (no rows will be written)"
	}
	fmt.Fprintf(out, "Old master key source: %s\n", oldSource)                            //nolint:errcheck
	fmt.Fprintf(out, "New master key source: environment variable %s\n", rotateNewKeyEnv) //nolint:errcheck
	fmt.Fprintf(out, "Mode: %s\n\n", mode)                                                //nolint:errcheck

	if !rotateDryRun && !rotateAssumeYes {
		fmt.Fprintln(out, "This rewrites every master-key-encrypted row in the database.")             //nolint:errcheck
		fmt.Fprintln(out, "Stop the RocketVault server and take a database backup before continuing.") //nolint:errcheck
		fmt.Fprint(out, "Type 'yes' to continue: ")                                                    //nolint:errcheck

		var confirmation string
		if _, scanErr := fmt.Scanln(&confirmation); scanErr != nil || confirmation != "yes" {
			fmt.Fprintln(out, "Aborted.") //nolint:errcheck
			return nil
		}
	}

	conn := db.NewConn(rawDB, db.DialectFromDriver(viper.GetString("database.driver")))
	report, runErr := rekey.New(conn, logger).Run(ctx, rekey.Options{
		OldKey:    oldKey,
		NewKey:    newKey,
		DryRun:    rotateDryRun,
		BatchSize: rotateBatchSize,
	})
	if report != nil {
		printRotationReport(out, report)
	}
	if runErr != nil {
		return fmt.Errorf("master key rotation failed: %w", runErr)
	}

	if rotateDryRun {
		fmt.Fprintln(out, "Dry run complete. No rows were modified.") //nolint:errcheck
		return nil
	}
	fmt.Fprintln(out, "Rotation complete. Set the new key as master_key in the configuration "+ //nolint:errcheck
		"(or as the MASTER_KEY environment variable) and restart the server.")
	fmt.Fprintln(out, "Reminder: existing database backup files were sealed under the old key and "+ //nolint:errcheck
		"are not affected by this rotation — they will not restore once the old key is retired.")
	return nil
}

// printRotationReport writes the per-table result table. It prints counters
// only -- never a key, a row value, or a secret name.
func printRotationReport(out io.Writer, report *rekey.Report) {
	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "TABLE\tCOLUMN\tROWS\tRE-ENCRYPTED\tALREADY NEW KEY\tSKIPPED (HSM)") //nolint:errcheck
	for _, target := range report.Targets {
		fmt.Fprintf(writer, "%s\t%s\t%d\t%d\t%d\t%d\n", //nolint:errcheck
			target.Table, target.Column, target.Total,
			target.ReEncrypted, target.AlreadyNewKey, target.SkippedExternal)
	}
	writer.Flush()                                                                   //nolint:errcheck,gosec
	fmt.Fprintf(out, "\nTotal rows re-encrypted: %d\n\n", report.TotalReEncrypted()) //nolint:errcheck
}
