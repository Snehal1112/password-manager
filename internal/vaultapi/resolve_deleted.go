package vaultapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// ResolveDeleted maps the name of a soft-deleted item to its UUID.
//
// It exists because Resolver.Resolve lists live items, and a soft-deleted
// item is absent from that listing by definition -- resolving a name for a
// purge through the live route would report "not found" for an item that
// exists and is purgeable. This queries a different route with a different
// wrapper key, so it is a separate function rather than a flag on Resolve,
// which would leave that function's contract ambiguous.
//
// A UUID passes through unchanged. Ambiguity is an error naming every
// candidate: purging the wrong item cannot be undone.
func (c *Client) ResolveDeleted(ctx context.Context, vault string, kind Kind, name string) (uuid.UUID, error) {
	if vault == "" {
		return uuid.Nil, fmt.Errorf("vaultapi: vault is required to resolve a deleted %s", kind)
	}
	if name == "" {
		return uuid.Nil, fmt.Errorf("vaultapi: deleted %s name is required", kind)
	}
	if parsed, err := uuid.Parse(name); err == nil {
		return parsed, nil
	}

	// No limit: a resolution must see every candidate, or it could miss the
	// item or fail to notice a duplicate.
	items, _, err := c.ListDeleted(ctx, vault, kind, 0)
	if err != nil {
		return uuid.Nil, err
	}

	var matches []DeletedItem
	for _, item := range items {
		if item.Name == name {
			matches = append(matches, item)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0].ID, nil
	case 0:
		return uuid.Nil, fmt.Errorf(
			"vaultapi: no deleted %s named %q in vault %q; list_deleted shows what can be recovered or purged: %w",
			kind, name, vault, ErrResourceNotFound)
	default:
		ids := make([]string, 0, len(matches))
		for _, match := range matches {
			ids = append(ids, match.ID.String())
		}
		sort.Strings(ids)
		return uuid.Nil, fmt.Errorf(
			"vaultapi: %d deleted %s named %q in vault %q; address one by id: %s",
			len(matches), kind, name, vault, strings.Join(ids, ", "))
	}
}
