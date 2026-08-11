package authorization

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/model"
)

// RequireDataAction returns nil if principalID holds a role assignment in
// vaultID granting action, and an error otherwise. It is the CLI-callable
// equivalent of the role-assignment half of PolicyMiddleware's check (its
// "2. Deny-by-default for vault data-plane routes" step) and must stay
// behaviorally identical to it: no admin short-circuit. Data-plane access
// has none today, even over HTTP (unlike vault-management's CanManageVault/
// CanPurgeVault, which do short-circuit for the global admin role) — copying
// that idiom here would grant the CLI a bypass the HTTP API doesn't have.
//
// This function alone is NOT full parity with PolicyMiddleware: it doesn't
// check the access_policies explicit-deny override (PolicyMiddleware's
// step "1"), because that check needs a *policy operation*, a different unit
// than the *data action* this function's callers already have on hand, and
// needs AccessPolicyService, not RoleAssignmentService. cmd/vaultcli's
// RequireDataAction wraps both steps in the correct order; this function is
// deliberately only the second one. Do not call this function directly from
// a CLI command — call cmd/vaultcli.RequireDataAction instead.
func RequireDataAction(ctx context.Context, roles RoleAssignmentService, principalID, vaultID uuid.UUID, action model.DataAction) error {
	ok, err := roles.HasDataAction(ctx, principalID, vaultID, action)
	if err != nil {
		return fmt.Errorf("checking vault authorization: %w", err)
	}
	if !ok {
		return fmt.Errorf("forbidden: no role grants %s in this vault", action)
	}
	return nil
}
