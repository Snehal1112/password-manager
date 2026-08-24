package vaultapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// itemKindPath validates a kind for the item routes.
func itemKindPath(kind Kind) (string, error) {
	switch kind {
	case KindSecrets, KindKeys, KindCertificates:
		return string(kind), nil
	default:
		return "", fmt.Errorf("vaultapi: unsupported item kind %q", kind)
	}
}

// DeleteItem soft-deletes a secret, key or certificate.
//
// The item remains recoverable until its retention period elapses, so this is
// reversible -- PurgeItem is not.
//
// It resolves through the live listing, since the item is still live.
func (c *Client) DeleteItem(ctx context.Context, vault string, kind Kind, name string) error {
	if vault == "" {
		return fmt.Errorf("vaultapi: vault is required to delete a %s", kind)
	}
	segment, err := itemKindPath(kind)
	if err != nil {
		return err
	}

	id, err := c.Resolver().Resolve(ctx, vault, kind, name)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/%s/%s", vault, segment, id)
	return c.Do(ctx, http.MethodDelete, path, nil, nil)
}

// PurgeItem permanently destroys a soft-deleted secret, key or certificate.
//
// This is irreversible. It resolves through the deleted listing, since only
// an already-deleted item can be purged.
//
// Purge protection is not checked here: whether it applies is server state,
// and pre-empting it would mean duplicating a rule that can change. A
// protected item fails server-side with its own message.
func (c *Client) PurgeItem(ctx context.Context, vault string, kind Kind, name string) error {
	if vault == "" {
		return fmt.Errorf("vaultapi: vault is required to purge a %s", kind)
	}
	segment, err := itemKindPath(kind)
	if err != nil {
		return err
	}

	id, err := c.ResolveDeleted(ctx, vault, kind, name)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/deleted/%s/%s/purge", vault, segment, id)
	return c.Do(ctx, http.MethodDelete, path, nil, nil)
}

// PurgeVault permanently destroys a soft-deleted vault and everything in it.
//
// A vault's name is its identifier, so no resolution applies.
func (c *Client) PurgeVault(ctx context.Context, vault string) error {
	if vault == "" {
		return fmt.Errorf("vaultapi: vault is required to purge a vault")
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/purge", vault)
	return c.Do(ctx, http.MethodDelete, path, nil, nil)
}

// DeleteRoleAssignment revokes a role grant.
//
// It takes an assignment id rather than a principal, because the route is
// keyed by assignment and one principal can hold several roles in a vault --
// accepting a name would mean choosing among them, which is a guess this
// client must not make. Callers get the id from ListRoleAssignments or from
// CreateRoleAssignment's result.
func (c *Client) DeleteRoleAssignment(ctx context.Context, vault, assignmentID string) error {
	if vault == "" {
		return fmt.Errorf("vaultapi: vault is required to revoke a role assignment")
	}
	if _, err := uuid.Parse(assignmentID); err != nil {
		return fmt.Errorf(
			"vaultapi: an assignment id is required, not a principal name: one principal can hold several roles in a vault, "+
				"so list the assignments first to choose one (got %q)", assignmentID)
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/role-assignments/%s", vault, assignmentID)
	return c.Do(ctx, http.MethodDelete, path, nil, nil)
}
