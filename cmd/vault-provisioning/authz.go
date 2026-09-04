// Package vaultprovisioning — authz.go provides the authorization check for
// the CLI vault-provisioning commands (grant/revoke/list). The CLI calls the
// service layer directly and bypasses PolicyMiddleware entirely, so this is
// the only authorization enforcement point on this path -- a command that
// skips it bypasses authorization completely. It mirrors
// cmd/vault-access/authz.go, whose header comment records the
// privilege-escalation gap that arose from omitting exactly this check.
package vaultprovisioning

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)

// callerIdentity extracts the acting principal's account roles and user ID
// from the CLI's authenticated context, populated by persistentPreRun in
// cmd/root.go. Returns an error if claims are missing -- a command reaching
// this far without prior authentication indicates a wiring bug, not a
// permission denial.
func callerIdentity(ctx context.Context) (roles []string, principalID uuid.UUID, err error) {
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, uuid.Nil, fmt.Errorf("authenticated claims not available in context")
	}
	return claims.Roles, claims.UserID, nil
}

// requireGrantAdmin authorizes a provisioning-grant operation. Global admin
// only, and deliberately non-delegable: a principal able to amend grants could
// raise its own quota, and the bound the grant exists to impose would be
// decorative. This is why there is no access-policy or role-assignment path
// here, unlike every other CLI authz helper in this tree.
//
// Returns the authorized principal's ID so the caller can attribute the change
// in the audit trail. The CLI has no middleware to stamp an actor for it, so a
// command that discards this value produces an audit record naming nobody.
func requireGrantAdmin(ctx context.Context) (uuid.UUID, error) {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if !common.HasAnyRole(roles, model.RoleAdmin) {
		return uuid.Nil, fmt.Errorf("permission denied: managing vault provisioning grants requires the admin role")
	}
	return principalID, nil
}
