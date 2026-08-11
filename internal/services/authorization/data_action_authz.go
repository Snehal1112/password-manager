package authorization

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/model"
)

// RequireDataAction returns nil if principalID holds a role assignment in
// vaultID granting action, and an error otherwise. It is the CLI-callable
// equivalent of PolicyMiddleware's HasDataAction check and must stay
// behaviorally identical to it: no admin short-circuit. Data-plane access has
// none today, even over HTTP (unlike CanManageVault/CanPurgeVault, which do
// short-circuit for the global admin role) — copying that idiom here would
// grant the CLI a bypass the HTTP API doesn't have.
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
