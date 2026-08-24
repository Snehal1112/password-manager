package vaultapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// DeletedItem is one soft-deleted secret, key or certificate awaiting
// recovery or purge.
//
// It has no value field. The soft-delete handlers return metadata only
// (api/soft_delete.go:44), and omitting the field means a stray server-side
// value can never surface through this type.
type DeletedItem struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Version   int       `json:"version,omitempty"`
	DeletedAt string    `json:"deleted_at,omitempty"`
	CreatedAt string    `json:"created_at,omitempty"`
}

type deletedItemWire struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   int    `json:"version"`
	DeletedAt string `json:"deleted_at"`
	CreatedAt string `json:"created_at"`
}

// deletedWrapperKey returns the response key for a kind. Each soft-delete
// handler names its array differently.
func deletedWrapperKey(kind Kind) (string, error) {
	switch kind {
	case KindSecrets:
		return "deleted_secrets", nil
	case KindKeys:
		return "deleted_keys", nil
	case KindCertificates:
		return "deleted_certificates", nil
	default:
		return "", fmt.Errorf("vaultapi: unsupported deleted-item kind %q", kind)
	}
}

// ListDeleted returns the soft-deleted items of one kind in vault, capped at
// limit. The bool reports truncation.
//
// One method covers all three kinds: the payloads are identical apart from
// the wrapper key, so three near-copies would be duplication rather than
// clarity.
func (c *Client) ListDeleted(ctx context.Context, vault string, kind Kind, limit int) ([]DeletedItem, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to list deleted %s", kind)
	}
	wrapperKey, err := deletedWrapperKey(kind)
	if err != nil {
		return nil, false, err
	}

	var response map[string]json.RawMessage
	path := fmt.Sprintf("/api/v1/vaults/%s/deleted/%s", vault, kind)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	var wires []deletedItemWire
	if raw, ok := response[wrapperKey]; ok {
		if err := json.Unmarshal(raw, &wires); err != nil {
			return nil, false, fmt.Errorf("vaultapi: decode deleted %s: %w", kind, err)
		}
	}

	truncated := limit > 0 && len(wires) > limit
	if truncated {
		wires = wires[:limit]
	}

	items := make([]DeletedItem, 0, len(wires))
	for _, wire := range wires {
		item := DeletedItem{
			Name:      wire.Name,
			Version:   wire.Version,
			DeletedAt: wire.DeletedAt,
			CreatedAt: wire.CreatedAt,
		}
		if id, parseErr := uuid.Parse(wire.ID); parseErr == nil {
			item.ID = id
		}
		items = append(items, item)
	}
	return items, truncated, nil
}
