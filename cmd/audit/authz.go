// Package audit — authz.go provides the authorization check shared by every
// audit CLI command. Audit logs and compliance reports span every vault, so
// (like cmd/backup.go's requireBackupAdmin) there is no vault to scope this
// to — the global admin role is the only applicable gate, mirroring the
// identical claims.Role != model.RoleAdmin restriction api/audit.go enforces
// on every audit HTTP route (getAuditLogs, getSOC2Report, getGDPRReport,
// getAuditConfig, patchAuditConfig).
package audit

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/model"
)

// requireAuditAdmin returns the caller's claims if they are logged in as
// admin, and an error otherwise. CLI commands bypass the HTTP middleware
// chain entirely (see CLAUDE.md's "CLI Authorization" section), so each
// audit command must reproduce this check itself.
func requireAuditAdmin(cmd *cobra.Command) (*model.Claims, error) {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("unauthorized: missing authentication claims")
	}
	if claims.Role != model.RoleAdmin {
		return nil, fmt.Errorf("forbidden: requires admin role")
	}
	return claims, nil
}
