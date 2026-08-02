package db

import (
	"context"
	"fmt"
	"sort"

	"rocketvault/model"
)

// RoleBackfillGrant is one (principal, role, vault) assignment the P2 upgrade
// migration would create. Source records which ownership table implied it, so
// an operator reviewing a preview can tell a derived grant from an admin grant.
type RoleBackfillGrant struct {
	PrincipalID string
	VaultID     string
	VaultName   string
	Role        string
	Source      string
}

// ownershipBackfillSource pairs an ownership table with the Azure role its
// owners receive in the vault holding the objects they own.
type ownershipBackfillSource struct {
	Table string
	Role  string
}

// ownershipBackfillSources is the mapping from spec section 6.3 steps 1 and 2.
var ownershipBackfillSources = []ownershipBackfillSource{
	{Table: "secrets", Role: model.RoleKeyVaultSecretsOfficer},
	{Table: "keys", Role: model.RoleKeyVaultCryptoOfficer},
	{Table: "certificates", Role: model.RoleKeyVaultCertificatesOfficer},
}

// PlanRoleBackfill derives the role assignments the P2 upgrade migration would
// create from existing object ownership. It writes nothing, so the migration and
// the "rocketvault vaults preview-migration" command run the same computation
// and an operator's preview is exactly what the upgrade will do.
//
// Derivation, per spec section 6.3:
//  1. Each distinct secrets.user_id owning rows in a vault -> Key Vault Secrets Officer there.
//  2. Same for keys -> Key Vault Crypto Officer and certificates -> Key Vault Certificates Officer.
//  3. Every user holding the global admin role -> Key Vault Administrator in every vault.
//
// A source table missing its ownership columns is skipped: migrateSchema runs
// against arbitrary old shapes, and secrets.user_id predates secrets.vault_id.
// A vault_id with no vaults row is skipped too, because role_assignments has a
// foreign key to vaults(id).
//
// The result is sorted by (vault name, role, principal) so output is stable.
func PlanRoleBackfill(ctx context.Context, q DBTX, dialect Dialect) ([]RoleBackfillGrant, error) {
	vaultNames, err := vaultNamesByID(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(vaultNames) == 0 {
		return nil, nil
	}

	type grantKey struct{ principal, vault, role string }
	seen := map[grantKey]bool{}
	var grants []RoleBackfillGrant

	add := func(principal, vault, role, source string) {
		name, known := vaultNames[vault]
		if principal == "" || vault == "" || !known {
			return
		}
		k := grantKey{principal, vault, role}
		if seen[k] {
			return
		}
		seen[k] = true
		grants = append(grants, RoleBackfillGrant{
			PrincipalID: principal,
			VaultID:     vault,
			VaultName:   name,
			Role:        role,
			Source:      source,
		})
	}

	for _, src := range ownershipBackfillSources {
		usable, err := hasOwnershipColumns(ctx, q, dialect, src.Table)
		if err != nil {
			return nil, err
		}
		if !usable {
			continue
		}
		if err := scanOwnership(ctx, q, src, add); err != nil {
			return nil, err
		}
	}

	adminIDs, err := globalAdminIDs(ctx, q, dialect)
	if err != nil {
		return nil, err
	}
	for _, adminID := range adminIDs {
		for vaultID := range vaultNames {
			add(adminID, vaultID, model.RoleKeyVaultAdministrator, "global-admin")
		}
	}

	sort.Slice(grants, func(i, j int) bool {
		if grants[i].VaultName != grants[j].VaultName {
			return grants[i].VaultName < grants[j].VaultName
		}
		if grants[i].Role != grants[j].Role {
			return grants[i].Role < grants[j].Role
		}
		return grants[i].PrincipalID < grants[j].PrincipalID
	})
	return grants, nil
}

// vaultNamesByID returns every vault id mapped to its name.
func vaultNamesByID(ctx context.Context, q DBTX) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name FROM vaults`)
	if err != nil {
		return nil, fmt.Errorf("list vaults for role backfill: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan vault for role backfill: %w", err)
		}
		out[id] = name
	}
	return out, rows.Err()
}

// hasOwnershipColumns reports whether the table carries both ownership columns
// the backfill reads. A table missing either is skipped, not an error.
func hasOwnershipColumns(ctx context.Context, q DBTX, dialect Dialect, table string) (bool, error) {
	hasUser, err := dialect.ColumnExists(ctx, q, table, "user_id")
	if err != nil {
		return false, fmt.Errorf("inspect %s.user_id: %w", table, err)
	}
	if !hasUser {
		return false, nil
	}
	hasVault, err := dialect.ColumnExists(ctx, q, table, "vault_id")
	if err != nil {
		return false, fmt.Errorf("inspect %s.vault_id: %w", table, err)
	}
	return hasVault, nil
}

// scanOwnership walks the distinct (owner, vault) pairs in one source table.
// The table name is a compile-time constant from ownershipBackfillSources, never
// caller input, so interpolating it introduces no injection surface.
func scanOwnership(ctx context.Context, q DBTX, src ownershipBackfillSource,
	add func(principal, vault, role, source string)) error {
	query := fmt.Sprintf(
		`SELECT DISTINCT user_id, vault_id FROM %s WHERE user_id IS NOT NULL AND user_id <> ''`, src.Table)
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("scan %s ownership: %w", src.Table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var userID, vaultID string
		if err := rows.Scan(&userID, &vaultID); err != nil {
			return fmt.Errorf("scan %s ownership row: %w", src.Table, err)
		}
		add(userID, vaultID, src.Role, src.Table)
	}
	return rows.Err()
}

// globalAdminIDs returns the ids of users holding the legacy global admin role.
// A database with no users table yields no admins rather than an error.
func globalAdminIDs(ctx context.Context, q DBTX, dialect Dialect) ([]string, error) {
	hasRole, err := dialect.ColumnExists(ctx, q, "users", "role")
	if err != nil {
		return nil, fmt.Errorf("inspect users.role: %w", err)
	}
	if !hasRole {
		return nil, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT id FROM users WHERE role = ?`, model.RoleAdmin)
	if err != nil {
		return nil, fmt.Errorf("list global admins: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan global admin: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
