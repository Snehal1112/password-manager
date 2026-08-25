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

package keys

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	vvalidation "rocketvault/internal/validation"
	"rocketvault/model"
)

// rotationPolicyCmd represents the parent "rotation-policy" command.
var rotationPolicyCmd = &cobra.Command{
	Use:   "rotation-policy",
	Short: "Manage a cryptographic key's automated rotation policy",
	Long: `Get, set or delete the automated rotation policy attached to a cryptographic
key. A rotation policy is distinct from "keys rotate": the policy configures
a schedule that a background scheduler sweeps on its own, whereas "keys
rotate" performs a single manual rotation immediately.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help() //nolint:errcheck,gosec
	},
}

// rotationPolicyGetCmd represents the "rotation-policy get" command.
var rotationPolicyGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Show a cryptographic key's rotation policy",
	Long: `Print the rotation policy attached to a cryptographic key by its UUID: whether
it is enabled, the rotation interval, the pre-expiry notification window, the
per-version expiry, and when it last rotated and will next rotate.

Requires the Microsoft.KeyVault/vaults/keys/rotationpolicy/read data action
in the target vault, which defaults to "default". A key with no policy set
is reported, not treated as an error.`,
	Example: `  # Show a key's rotation policy in the default vault
  rocketvault keys rotation-policy get <key-id>

  # Show a key's rotation policy in a named vault
  rocketvault keys rotation-policy get <key-id> --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		keyID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_key_rotation_policy", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "get_key_rotation_policy", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		keyService := serviceContainer.GetKeyService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysRotationPolicyRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_key_rotation_policy", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		policy, err := keyService.GetKeyRotationPolicy(ctx, keyID, model.NewVaultScope(vaultID, claims.UserID))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.LogAuditInfo(claims.UserID.String(), "get_key_rotation_policy", "success", fmt.Sprintf("no rotation policy for key: %s", keyID))
				fmt.Fprintf(cmd.OutOrStdout(), "No rotation policy set for key %s\n", keyID) //nolint:errcheck,gosec
				return nil
			}
			log.LogAuditError(claims.UserID.String(), "get_key_rotation_policy", "failed", fmt.Sprintf("failed to get rotation policy: %s", err), err)
			return fmt.Errorf("failed to get rotation policy: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "get_key_rotation_policy", "success", fmt.Sprintf("rotation policy retrieved for key: %s", keyID))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		lastRotated := "-"
		if policy.LastRotatedAt != nil {
			lastRotated = policy.LastRotatedAt.Format(time.RFC3339)
		}

		headers := []string{"Enabled", "Rotate-After-Days", "Notify-Before-Expiry-Days", "Expiry-Days", "Last-Rotated", "Next-Rotation"}
		row := []string{
			strconv.FormatBool(policy.Enabled),
			strconv.Itoa(policy.RotateAfterDays),
			strconv.Itoa(policy.NotifyBeforeExpiryDays),
			strconv.Itoa(policy.ExpiryDays),
			lastRotated,
			policy.NextRotationAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// rotationPolicySetCmd represents the "rotation-policy set" command.
var rotationPolicySetCmd = &cobra.Command{
	Use:   "set <id>",
	Short: "Create or replace a cryptographic key's rotation policy",
	Long: `Create or replace the rotation policy attached to a cryptographic key by its
UUID. This is a full replace, not a partial merge, so --rotate-after-days
and --enabled must both be supplied on every call -- read the current
values first with "rotation-policy get" if you only mean to change one
field.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/rotationpolicy/write data action in the
target vault, which defaults to "default".

--rotate-after-days must be at least 7 when --enabled is set, mirroring
Azure Key Vault's minimum rotation interval; a disabled policy accepts any
value since it is never scheduled. A background scheduler sweeps enabled,
due policies and rotates their keys on its own -- this command only manages
the policy, not a one-off rotation (use "keys rotate" for that).`,
	Example: `  # Rotate a key automatically every 90 days
  rocketvault keys rotation-policy set <key-id> --rotate-after-days 90 --enabled

  # Also stamp a 30-day expiry on each new version and notify 7 days before
  rocketvault keys rotation-policy set <key-id> --rotate-after-days 90 \
    --expiry-days 30 --notify-before-expiry-days 7 --enabled

  # Park a policy without deleting it
  rocketvault keys rotation-policy set <key-id> --rotate-after-days 90 --enabled=false`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCryptoManager) {
			log.LogAuditError(claims.UserID.String(), "set_key_rotation_policy", "failed", "forbidden: requires admin or crypto_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}

		keyID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "set_key_rotation_policy", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		if !cmd.Flags().Changed("rotate-after-days") || !cmd.Flags().Changed("enabled") {
			log.LogAuditError(claims.UserID.String(), "set_key_rotation_policy", "failed", "missing required flags: --rotate-after-days and --enabled", nil)
			return fmt.Errorf("--rotate-after-days and --enabled are required: this replaces the whole policy, so every field must be supplied")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "set_key_rotation_policy", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}

		rotateAfterDays, _ := cmd.Flags().GetInt("rotate-after-days")
		notifyBeforeExpiryDays, _ := cmd.Flags().GetInt("notify-before-expiry-days")
		expiryDays, _ := cmd.Flags().GetInt("expiry-days")
		enabled, _ := cmd.Flags().GetBool("enabled")

		if err := vvalidation.ValidateKeyRotationPolicy(vvalidation.KeyRotationPolicyRequest{
			RotateAfterDays: rotateAfterDays,
			Enabled:         enabled,
		}); err != nil {
			log.LogAuditError(claims.UserID.String(), "set_key_rotation_policy", "failed", fmt.Sprintf("invalid rotation policy: %s", err), err)
			return fmt.Errorf("invalid rotation policy: %w", err)
		}

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysRotationPolicyWrite, model.OpSet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "set_key_rotation_policy", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		req := model.UpsertKeyRotationPolicyRequest{
			RotateAfterDays:        rotateAfterDays,
			NotifyBeforeExpiryDays: notifyBeforeExpiryDays,
			ExpiryDays:             expiryDays,
			Enabled:                enabled,
		}
		policy, err := serviceContainer.GetKeyService().UpsertKeyRotationPolicy(ctx, keyID, model.NewVaultScope(vaultID, claims.UserID), req)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "set_key_rotation_policy", "failed", fmt.Sprintf("failed to set rotation policy: %s", err), err)
			return fmt.Errorf("failed to set rotation policy: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "set_key_rotation_policy", "success", fmt.Sprintf("rotation policy set for key: %s", keyID))
		fmt.Fprintf(cmd.OutOrStdout(), "Rotation policy set for key %s: next rotation at %s\n", //nolint:errcheck,gosec
			keyID, policy.NextRotationAt.Format(time.RFC3339))
		return nil
	},
}

// rotationPolicyDeleteCmd represents the "rotation-policy delete" command.
var rotationPolicyDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a cryptographic key's rotation policy",
	Long: `Delete the rotation policy attached to a cryptographic key by its UUID. The
key itself is unaffected; only the schedule is removed, so the background
scheduler stops touching this key. Manual "keys rotate" still works.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/rotationpolicy/write data action in the
target vault, which defaults to "default".`,
	Example: `  # Delete a key's rotation policy in the default vault
  rocketvault keys rotation-policy delete <key-id>

  # Delete a key's rotation policy in a named vault
  rocketvault keys rotation-policy delete <key-id> --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCryptoManager) {
			log.LogAuditError(claims.UserID.String(), "delete_key_rotation_policy", "failed", "forbidden: requires admin or crypto_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or crypto_manager role")
		}

		keyID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_key_rotation_policy", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "delete_key_rotation_policy", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysRotationPolicyWrite, model.OpDelete)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_key_rotation_policy", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		if err := serviceContainer.GetKeyService().DeleteKeyRotationPolicy(ctx, keyID, model.NewVaultScope(vaultID, claims.UserID)); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.LogAuditError(claims.UserID.String(), "delete_key_rotation_policy", "failed", fmt.Sprintf("no rotation policy for key: %s", keyID), err)
				return fmt.Errorf("no rotation policy exists for key %s", keyID)
			}
			log.LogAuditError(claims.UserID.String(), "delete_key_rotation_policy", "failed", fmt.Sprintf("failed to delete rotation policy: %s", err), err)
			return fmt.Errorf("failed to delete rotation policy: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "delete_key_rotation_policy", "success", fmt.Sprintf("rotation policy deleted for key: %s", keyID))
		fmt.Fprintf(cmd.OutOrStdout(), "Rotation policy for key %s deleted successfully\n", keyID) //nolint:errcheck,gosec
		return nil
	},
}

// InitKeysRotationPolicy adds the "rotation-policy" command, and its get,
// set and delete subcommands, to the keys command.
func InitKeysRotationPolicy(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(rotationPolicyCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyGetCmd)
	rotationPolicyCmd.AddCommand(rotationPolicySetCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyDeleteCmd)

	rotationPolicySetCmd.Flags().Int("rotate-after-days", 0, "Days after creation or last rotation before auto-rotating (required, min 7 when --enabled)")
	rotationPolicySetCmd.Flags().Int("notify-before-expiry-days", 0, "Days before a version's expiry to fire a notification")
	rotationPolicySetCmd.Flags().Int("expiry-days", 0, "Lifetime in days stamped on each newly rotated version")
	rotationPolicySetCmd.Flags().Bool("enabled", false, "Whether the policy is active (required)")

	return keysCmd
}
