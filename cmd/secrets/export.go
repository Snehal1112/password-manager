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

package secrets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

var (
	exportFormat         string
	exportFile           string
	exportEncrypt        bool
	exportPassphraseFile string
	exportTags           []string
	exportFilterTags     []string
)

// exportPassphraseEnvVar names the environment variable that supplies an export
// passphrase without a terminal. Import reads the same variable.
const exportPassphraseEnvVar = "ROCKETVAULT_EXPORT_PASSPHRASE"

var secretsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets to a file",
	Long: `Export the target vault's secrets to a JSON or CSV file holding each
secret's name, plaintext value and tags.

The file is encrypted by default. --encrypt (default true) seals it under a
passphrase with argon2id key derivation and AES-256-GCM. The passphrase is
read from --passphrase-file, then the ROCKETVAULT_EXPORT_PASSPHRASE
environment variable, then an interactive prompt asking twice. If none of
those yields a passphrase the command fails and writes no file at all.

A sealed export is always a JSON envelope on disk, whatever --format says;
the format describes the payload inside it, so a sealed CSV export is read
back with "secrets import --format csv".

--encrypt=false writes the export in the clear and prints a warning naming
what is exposed. Use it only when something downstream needs a readable
file, and delete that file promptly.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/getSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default". The export
is vault scoped, so it includes secrets created by other members of that
vault, not only the caller's own.

--tags and --filter-tags are merged into one tag filter. Passing neither
exports every secret in the vault. The file is written with 0600
permissions, and any missing parent directories are created.`,
	Example: `  # Export every secret in the default vault, prompting for a passphrase
  rocketvault secrets export --file secrets.json

  # Export non-interactively, reading the passphrase from a file
  rocketvault secrets export --file secrets.json \
    --passphrase-file /run/secrets/export-pass

  # Export a named vault as CSV, restricted to secrets tagged production
  rocketvault secrets export --format csv --file payments.csv \
    --tags production --vault <vault-name>

  # Write plaintext deliberately, accepting the warning
  rocketvault secrets export --file secrets.json --encrypt=false`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		format := strings.ToLower(exportFormat)
		if format != "json" && format != "csv" {
			return fmt.Errorf("unsupported format: %s (supported: json, csv)", exportFormat)
		}

		if target, ok := ctx.Value(common.RemoteTargetKey).(*cliclient.Target); ok && target != nil {
			return runSecretsExportRemote(cmd, ctx, target, format)
		}

		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}
		userID := claims.UserID

		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleSecretsManager) {
			return fmt.Errorf("forbidden: requires admin or secrets_manager role")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsGet.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsGet, model.OpCreate)
		if err != nil {
			return err
		}

		// Resolve the passphrase after the authorization check and before any
		// write, so an unauthorized caller is never prompted and a caller with
		// no passphrase never reaches os.WriteFile.
		if !exportEncrypt && exportPassphraseFile != "" {
			return fmt.Errorf("--passphrase-file was given with --encrypt=false: " +
				"drop one, since a plaintext export has no passphrase")
		}
		var passphrase string
		if exportEncrypt {
			passphrase, err = common.ResolvePassphrase(common.PassphraseSource{
				File:    exportPassphraseFile,
				EnvVar:  exportPassphraseEnvVar,
				Prompt:  "Export passphrase: ",
				Confirm: true,
			})
			if err != nil {
				if errors.Is(err, common.ErrNoPassphraseAvailable) {
					return fmt.Errorf("export encryption is on but no passphrase is available: "+
						"pass --passphrase-file, set %s, or pass --encrypt=false to write plaintext deliberately",
						exportPassphraseEnvVar)
				}
				return fmt.Errorf("failed to resolve export passphrase: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stderr,
				"Warning: --encrypt=false — %s will hold every exported secret's name, "+
					"plaintext value and tags in the clear.\n", exportFile) //nolint:errcheck
		}

		allTags := append(exportTags, exportFilterTags...)

		// Vault-scoped: this matches api/secrets.go's exportSecrets handler,
		// which calls scopeFromRequest and gets a vault scope back on the
		// /vaults/{name}/secrets/... route. Any vault member holding a role
		// that grants ActionSecretsGet can export another member's plaintext
		// secret values into their own local file.
		data, err := sc.GetSecretService().ExportSecrets(ctx, secretServices.ExportSecretsRequest{
			Scope:       model.NewVaultScope(vaultID, userID),
			Format:      format,
			FilterTags:  allTags,
			IncludeTags: true,
			Encrypt:     exportEncrypt,
			Passphrase:  passphrase,
		})
		if err != nil {
			return fmt.Errorf("failed to export secrets: %w", err)
		}

		dir := filepath.Dir(exportFile)
		if dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
		}
		if err := os.WriteFile(exportFile, data, 0o600); err != nil {
			return fmt.Errorf("failed to write export file: %w", err)
		}

		encryption := "none (plaintext)"
		if exportEncrypt {
			encryption = "passphrase (argon2id + AES-256-GCM)"
		}
		fmt.Printf("Secrets exported successfully\nFormat: %s\nEncryption: %s\nFile: %s\n",
			format, encryption, exportFile)
		return nil
	},
}

// runSecretsExportRemote is "secrets export"'s remote-mode path. Format was
// already validated by the caller.
func runSecretsExportRemote(cmd *cobra.Command, ctx context.Context, target *cliclient.Target, format string) error {
	httpClient, ok := ctx.Value(common.RemoteHTTPClientKey).(*http.Client)
	if !ok || httpClient == nil {
		return fmt.Errorf("remote HTTP client not available in context")
	}
	token, ok := ctx.Value(common.TokenKey).(string)
	if !ok || token == "" {
		return fmt.Errorf("remote session token not available in context")
	}

	vault, _ := cmd.Flags().GetString("vault")
	if vault == "" {
		vault = target.Vault
	}

	if !exportEncrypt && exportPassphraseFile != "" {
		return fmt.Errorf("--passphrase-file was given with --encrypt=false: " +
			"drop one, since a plaintext export has no passphrase")
	}
	var passphrase string
	var err error
	if exportEncrypt {
		passphrase, err = common.ResolvePassphrase(common.PassphraseSource{
			File:    exportPassphraseFile,
			EnvVar:  exportPassphraseEnvVar,
			Prompt:  "Export passphrase: ",
			Confirm: true,
		})
		if err != nil {
			if errors.Is(err, common.ErrNoPassphraseAvailable) {
				return fmt.Errorf("export encryption is on but no passphrase is available: "+
					"pass --passphrase-file, set %s, or pass --encrypt=false to write plaintext deliberately",
					exportPassphraseEnvVar)
			}
			return fmt.Errorf("failed to resolve export passphrase: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stderr,
			"Warning: --encrypt=false — %s will hold every exported secret's name, "+
				"plaintext value and tags in the clear.\n", exportFile) //nolint:errcheck
	}

	allTags := append(exportTags, exportFilterTags...)

	data, err := cliclient.ExportSecretsRemote(ctx, httpClient, token, target.Server, vault, model.ExportSecretsRequest{
		Format:      format,
		Tags:        allTags,
		IncludeTags: true,
		Encrypt:     exportEncrypt,
		Passphrase:  passphrase,
	})
	if err != nil {
		return fmt.Errorf("failed to export secrets: %w", err)
	}

	dir := filepath.Dir(exportFile)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}
	if err := os.WriteFile(exportFile, data, 0o600); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	encryption := "none (plaintext)"
	if exportEncrypt {
		encryption = "passphrase (argon2id + AES-256-GCM)"
	}
	fmt.Printf("Secrets exported successfully\nFormat: %s\nEncryption: %s\nFile: %s\n",
		format, encryption, exportFile)
	return nil
}

// InitSecretsExport registers the export sub-command under the given parent.
func InitSecretsExport(parentCmd *cobra.Command) {
	parentCmd.AddCommand(secretsExportCmd)
	secretsExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "Export format (json or csv)")
	secretsExportCmd.Flags().StringVarP(&exportFile, "file", "o", "", "Output file path (required)")
	secretsExportCmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", true, "Encrypt the export file")
	secretsExportCmd.Flags().StringVar(&exportPassphraseFile, "passphrase-file", "",
		"Read the export passphrase from the first line of this file")
	secretsExportCmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "Include only secrets with these tags")
	secretsExportCmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "Filter secrets by these tags")
	secretsExportCmd.MarkFlagRequired("file") //nolint:errcheck,gosec
}
