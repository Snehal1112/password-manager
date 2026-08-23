// Package vaultwebhook — authz.go provides the authorization check for the
// CLI vault-webhook commands (set/get/delete). The CLI calls the service
// layer directly and bypasses PolicyMiddleware entirely, so this is the only
// authorization enforcement point on this path -- a command that skips it
// bypasses authorization completely. It mirrors cmd/vault-access/authz.go,
// whose header comment records the privilege-escalation gap that arose from
// omitting exactly this check.
package vaultwebhook

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// callerIdentity extracts the acting principal's account role and user ID from
// the CLI's authenticated context, populated by persistentPreRun in
// cmd/root.go. Returns an error if claims are missing — a command reaching
// this far without prior authentication indicates a wiring bug, not a
// permission denial.
func callerIdentity(ctx context.Context) (roles []string, principalID uuid.UUID, err error) {
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, uuid.Nil, fmt.Errorf("authenticated claims not available in context")
	}
	return claims.Roles, claims.UserID, nil
}

// requireCanManageVault authorizes a webhook-config operation on vaultID with
// the same primitive the HTTP handlers use, so CLI and API cannot drift.
//
// The CLI calls the service layer directly and bypasses PolicyMiddleware
// entirely, so this is the only authorization enforcement point on this path
// -- a command that skips it bypasses authorization completely.
//
// It returns the authorized principal's id so the caller can attribute the
// change in the audit trail. The CLI has no middleware to stamp an actor for
// it, so a command that discards this value produces an audit record naming
// nobody.
func requireCanManageVault(ctx context.Context, sc container.ServiceContainerInterface, vaultID uuid.UUID, vaultName string) (uuid.UUID, error) {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if !authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, vaultID) {
		return uuid.Nil, fmt.Errorf("permission denied: managing webhook config for vault %q requires admin or vaults/manage", vaultName)
	}
	return principalID, nil
}
