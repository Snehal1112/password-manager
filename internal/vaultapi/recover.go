package vaultapi

import (
	"context"
	"fmt"
	"net/http"
)

// RecoverDeleted restores a soft-deleted secret, key or certificate.
//
// It resolves through the deleted listing, not the live one: the item is
// invisible to the live route by definition, so resolving there would report
// "not found" for something that exists and is recoverable.
func (c *Client) RecoverDeleted(ctx context.Context, vault string, kind Kind, name string) error {
	if vault == "" {
		return fmt.Errorf("vaultapi: vault is required to recover a %s", kind)
	}
	segment, err := itemKindPath(kind)
	if err != nil {
		return err
	}

	id, err := c.ResolveDeleted(ctx, vault, kind, name)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/deleted/%s/%s/restore", vault, segment, id)
	return c.Do(ctx, http.MethodPost, path, nil, nil)
}
