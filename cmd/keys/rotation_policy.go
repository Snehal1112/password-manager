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
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
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
in the target vault, which defaults to "default". No global role is checked
here. A key with no policy set is reported, not treated as an error.`,
	Example: `  # Show a key's rotation policy in the default vault
  rocketvault keys rotation-policy get <key-id>

  # Show a key's rotation policy in a named vault
  rocketvault keys rotation-policy get <key-id> --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "get_key_rotation_policy", Action: model.ActionKeysRotationPolicyRead, Policy: model.OpGet,
		})
		if err != nil {
			return err
		}
		keyID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid key ID", err)
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetKeyService()

		policy, err := svc.GetKeyRotationPolicy(s.Ctx, keyID, s.Scope)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				s.OK(fmt.Sprintf("no rotation policy for key: %s", keyID))
				fmt.Fprintf(cmd.OutOrStdout(), "No rotation policy set for key %s\n", keyID) //nolint:errcheck,gosec
				return nil
			}
			return s.Fail("failed to get rotation policy", err)
		}

		s.OK(fmt.Sprintf("rotation policy retrieved for key: %s", keyID))
		return vaultcli.Print(s, keyRotationPolicyColumns, policy)
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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "set_key_rotation_policy", Action: model.ActionKeysRotationPolicyWrite, Policy: model.OpSet,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		keyID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid key ID", err)
		}

		if !cmd.Flags().Changed("rotate-after-days") || !cmd.Flags().Changed("enabled") {
			return s.Fail("--rotate-after-days and --enabled are required: this replaces the whole policy, so every field must be supplied", nil)
		}

		rotateAfterDays, _ := cmd.Flags().GetInt("rotate-after-days")
		notifyBeforeExpiryDays, _ := cmd.Flags().GetInt("notify-before-expiry-days")
		expiryDays, _ := cmd.Flags().GetInt("expiry-days")
		enabled, _ := cmd.Flags().GetBool("enabled")

		if err := vvalidation.ValidateKeyRotationPolicy(vvalidation.KeyRotationPolicyRequest{
			RotateAfterDays: rotateAfterDays,
			Enabled:         enabled,
		}); err != nil {
			return s.Fail("invalid rotation policy", err)
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetKeyService()

		req := model.UpsertKeyRotationPolicyRequest{
			RotateAfterDays:        rotateAfterDays,
			NotifyBeforeExpiryDays: notifyBeforeExpiryDays,
			ExpiryDays:             expiryDays,
			Enabled:                enabled,
		}
		policy, err := svc.UpsertKeyRotationPolicy(s.Ctx, keyID, s.Scope, req)
		if err != nil {
			return s.Fail("failed to set rotation policy", err)
		}

		s.OK(fmt.Sprintf("rotation policy set for key: %s", keyID))
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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "delete_key_rotation_policy", Action: model.ActionKeysRotationPolicyWrite, Policy: model.OpDelete,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		keyID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid key ID", err)
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetKeyService()

		if err := svc.DeleteKeyRotationPolicy(s.Ctx, keyID, s.Scope); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return s.Fail(fmt.Sprintf("no rotation policy exists for key %s", keyID), nil)
			}
			return s.Fail("failed to delete rotation policy", err)
		}

		s.OK(fmt.Sprintf("rotation policy deleted for key: %s", keyID))
		fmt.Fprintf(cmd.OutOrStdout(), "Rotation policy for key %s deleted successfully\n", keyID) //nolint:errcheck,gosec
		return nil
	},
}

// rotationPolicyListCmd represents the "rotation-policy list" command.
var rotationPolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every key with a rotation policy set in a vault",
	Long: `List every cryptographic key in the target vault that currently has a
rotation policy set: key ID, key name, whether the policy is enabled, the
rotation interval, and the next scheduled rotation. Keys with no policy set
are simply absent from the list -- this lists policies, not all keys.

Requires the Microsoft.KeyVault/vaults/keys/rotationpolicy/read data action
in the target vault, which defaults to "default". No global role is checked
here.`,
	Example: `  # List rotation policies in the default vault
  rocketvault keys rotation-policy list

  # List rotation policies in a named vault
  rocketvault keys rotation-policy list --vault payments`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "list_key_rotation_policies", Action: model.ActionKeysRotationPolicyRead, Policy: model.OpGet,
		})
		if err != nil {
			return err
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetKeyService()

		policies, err := svc.ListKeyRotationPolicies(s.Ctx, s.Scope)
		if err != nil {
			return s.Fail("failed to list rotation policies", err)
		}

		s.OK(fmt.Sprintf("listed %d key rotation policies", len(policies)))
		return vaultcli.Print(s, keyRotationPolicyListColumns, policies...)
	},
}

// rotationPolicyStatusCmd represents the "rotation-policy status" command.
var rotationPolicyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "View key rotation status and due rotations",
	Long: `Summarise key rotation for the target vault in two parts: keys whose next
rotation date has passed under an enabled policy, and every enabled policy
with its interval.

Requires the Microsoft.KeyVault/vaults/keys/rotationpolicy/read data action
in the target vault, which defaults to "default". No global role is checked
here.

This is a read-only report: nothing is rotated by running it. Automatic
rotation is carried out by the scheduler inside a running "rocketvault serve"
process; "keys rotate" is the only way to rotate from the CLI.`,
	Example: `  # Show key rotation status for the default vault
  rocketvault keys rotation-policy status

  # Show key rotation status for a named vault
  rocketvault keys rotation-policy status --vault payments`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "key_rotation_policy_status", Action: model.ActionKeysRotationPolicyRead, Policy: model.OpGet,
		})
		if err != nil {
			return err
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetKeyService()

		due, err := svc.ListDueKeyRotationPolicies(s.Ctx, s.Scope)
		if err != nil {
			return s.Fail("failed to get due key rotations", err)
		}
		policies, err := svc.ListKeyRotationPolicies(s.Ctx, s.Scope)
		if err != nil {
			return s.Fail("failed to list key rotation policies", err)
		}

		s.OK(fmt.Sprintf("%d due, %d policies", len(due), len(policies)))

		fmt.Fprintln(cmd.OutOrStdout(), "Key Rotation Status")                      //nolint:errcheck
		fmt.Fprintln(cmd.OutOrStdout(), "────────────────────────────────────────") //nolint:errcheck
		if len(due) > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "Keys due for rotation:") //nolint:errcheck
			for _, d := range due {
				fmt.Fprintf(cmd.OutOrStdout(), "  - Key %s (next: %s)\n", //nolint:errcheck
					d.KeyID.String()[:8]+"...", d.NextRotationAt.Format("2006-01-02"))
			}
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "No keys are currently due for rotation.") //nolint:errcheck
		}
		if len(policies) > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "\nActive rotation policies:") //nolint:errcheck
			foundEnabled := false
			for _, p := range policies {
				if p.Enabled {
					foundEnabled = true
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s: every %d days\n", p.KeyName, p.RotateAfterDays) //nolint:errcheck
				}
			}
			if !foundEnabled {
				fmt.Fprintln(cmd.OutOrStdout(), "  (none with rotation enabled)") //nolint:errcheck
			}
		}
		return nil
	},
}

// InitKeysRotationPolicy adds the "rotation-policy" command, and its get,
// set, delete, list and status subcommands, to the keys command.
func InitKeysRotationPolicy(keysCmd *cobra.Command) {
	keysCmd.AddCommand(rotationPolicyCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyGetCmd)
	rotationPolicyCmd.AddCommand(rotationPolicySetCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyDeleteCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyListCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyStatusCmd)

	rotationPolicySetCmd.Flags().Int("rotate-after-days", 0, "Days after creation or last rotation before auto-rotating (required, min 7 when --enabled)")
	rotationPolicySetCmd.Flags().Int("notify-before-expiry-days", 0, "Days before a version's expiry to fire a notification")
	rotationPolicySetCmd.Flags().Int("expiry-days", 0, "Lifetime in days stamped on each newly rotated version")
	rotationPolicySetCmd.Flags().Bool("enabled", false, "Whether the policy is active (required)")
}
