package vaultapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// ErrResourceNotFound wraps every "no such name" resolution failure, so a
// caller can distinguish it from a denial, an ambiguous name, or an
// unreachable server with errors.Is rather than matching on message text.
var ErrResourceNotFound = errors.New("vaultapi: no such resource")

// Kind identifies a vault-scoped resource collection.
type Kind string

const (
	KindSecrets      Kind = "secrets"
	KindKeys         Kind = "keys"
	KindCertificates Kind = "certificates"
)

// namedItem is the minimal shape resolution needs.
//
// It deliberately has no value field. model.SecretResponse carries
// `value,omitempty` even though the list handler never populates it, and
// defining our own narrow type means a future server change cannot start
// feeding secret values through the resolution path.
type namedItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// listEnvelope covers all three list wrappers, since each route names its
// array differently. Exactly one field is populated per response.
type listEnvelope struct {
	Secrets      []namedItem `json:"secrets"`
	Keys         []namedItem `json:"keys"`
	Certificates []namedItem `json:"certificates"`
}

// items returns whichever collection the response carried.
func (e listEnvelope) items(kind Kind) []namedItem {
	switch kind {
	case KindKeys:
		return e.Keys
	case KindCertificates:
		return e.Certificates
	default:
		return e.Secrets
	}
}

type cacheKey struct {
	vault string
	kind  Kind
}

// Resolver maps resource names to UUIDs, caching one list per vault and kind.
//
// A Resolver is scoped to a single MCP tool call. Creating a fresh one per
// call is what keeps a rename from being served stale, so it is intentionally
// not shared across calls.
type Resolver struct {
	client *Client
	cache  map[cacheKey][]namedItem
}

// NewResolver returns a Resolver backed by c.
func NewResolver(c *Client) *Resolver {
	return &Resolver{client: c, cache: make(map[cacheKey][]namedItem)}
}

// Resolver returns a new Resolver for this client.
func (c *Client) Resolver() *Resolver { return NewResolver(c) }

// Resolve maps name to a UUID within vault. A name that already parses as a
// UUID is returned unchanged without a list call.
//
// Ambiguity is an error, never a guess: acting on the wrong secret is worse
// than stopping to ask.
func (r *Resolver) Resolve(ctx context.Context, vault string, kind Kind, name string) (uuid.UUID, error) {
	if vault == "" {
		return uuid.Nil, fmt.Errorf("vaultapi: vault is required to resolve a %s name", kind)
	}
	if name == "" {
		return uuid.Nil, fmt.Errorf("vaultapi: %s name is required", kind)
	}
	if parsed, err := uuid.Parse(name); err == nil {
		return parsed, nil
	}

	items, err := r.list(ctx, vault, kind)
	if err != nil {
		return uuid.Nil, err
	}

	var matches []namedItem
	for _, item := range items {
		if item.Name == name {
			matches = append(matches, item)
		}
	}

	switch len(matches) {
	case 1:
		parsed, err := uuid.Parse(matches[0].ID)
		if err != nil {
			return uuid.Nil, fmt.Errorf("vaultapi: %s %q has an unparseable id: %w", kind, name, err)
		}
		return parsed, nil
	case 0:
		return uuid.Nil, notFoundError(vault, kind, name, items)
	default:
		return uuid.Nil, ambiguousError(vault, kind, name, matches)
	}
}

// list fetches and caches one collection.
func (r *Resolver) list(ctx context.Context, vault string, kind Kind) ([]namedItem, error) {
	key := cacheKey{vault: vault, kind: kind}
	if cached, ok := r.cache[key]; ok {
		return cached, nil
	}

	var envelope listEnvelope
	path := fmt.Sprintf("/api/v1/vaults/%s/%s", vault, kind)
	if err := r.client.Do(ctx, http.MethodGet, path, nil, &envelope); err != nil {
		return nil, err
	}

	items := envelope.items(kind)
	r.cache[key] = items
	return items, nil
}

// notFoundError reports a missing name, suggesting near misses so the caller
// can correct a typo without a second round trip.
//
// It wraps ErrResourceNotFound so a caller can test for absence with
// errors.Is rather than matching on this message's wording.
func notFoundError(vault string, kind Kind, name string, items []namedItem) error {
	near := nearMisses(name, items)
	if len(near) == 0 {
		return fmt.Errorf("vaultapi: no %s named %q in vault %q: %w", kind, name, vault, ErrResourceNotFound)
	}
	return fmt.Errorf("vaultapi: no %s named %q in vault %q; did you mean %s?: %w",
		kind, name, vault, strings.Join(quoteAll(near), ", "), ErrResourceNotFound)
}

// ambiguousError reports a name matching more than one resource, naming every
// candidate by id.
func ambiguousError(vault string, kind Kind, name string, matches []namedItem) error {
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	return fmt.Errorf("vaultapi: %d %s named %q in vault %q; address one by id: %s",
		len(matches), kind, name, vault, strings.Join(ids, ", "))
}

// nearMisses returns up to three candidate names sharing a prefix or
// substring with name, compared case-insensitively.
func nearMisses(name string, items []namedItem) []string {
	lowered := strings.ToLower(name)
	var near []string
	for _, item := range items {
		candidate := strings.ToLower(item.Name)
		if candidate == lowered || strings.Contains(candidate, lowered) || strings.Contains(lowered, candidate) {
			near = append(near, item.Name)
		}
	}
	sort.Strings(near)
	if len(near) > 3 {
		near = near[:3]
	}
	return near
}

func quoteAll(values []string) []string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return quoted
}
