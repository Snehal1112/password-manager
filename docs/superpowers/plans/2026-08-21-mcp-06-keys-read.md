# Keys Read Methods Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `ListKeys`, `GetKey`, `GetKeyVersions` and `GetKeyRotationPolicy` to `internal/vaultapi`, exposing each key's public JWK components while carrying no field that could ever hold private material.

**Architecture:** The same shape plan 05 established — vault-scoped route, unexported wire type decoded into exported types, `Resolver.Resolve` before any by-id fetch, truncation reported on lists. No redacting type is needed: key routes return public components only.

**Tech Stack:** Go 1.25, `github.com/google/uuid`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Read tier".

**Plan-of-plans:** This is plan 06 of 31. Requires plans 01, 04 and 05 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Vault-scoped routes only** — `/api/v1/vaults/{vault}/keys`.
- **No type in this plan may carry private key material.** `api.KeyResponse` has no value or PEM field, and neither may anything here. This mirrors the guarantee `api.KeyVersionResponse` documents about `model.KeyVersion`: "there is deliberately no Value or PEM field here, and none may be added" (`api/keys.go:92-97`).
- `vaultapi` must not import the MCP SDK or `internal/mcpserver`.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified route contracts

| Method | Route | Response |
|---|---|---|
| List | `GET /api/v1/vaults/{v}/keys` | `{"keys":[KeyResponse...]}` (`api/keys.go:107`) |
| Get | `GET /api/v1/vaults/{v}/keys/{id}` | `KeyResponse` (`api/keys.go:70`) |
| Versions | `GET /api/v1/vaults/{v}/keys/{id}/versions` | array of `KeyVersionResponse` (`api/keys.go:98`) |
| Rotation policy | `GET /api/v1/vaults/{v}/keys/{id}/rotationpolicy` | `model.KeyRotationPolicy` (`model/key_rotation_policy.go:15`) |

`KeyResponse` fields: `id`, `name`, `type`, `user_id`, `revoked`, `created_at`, `updated_at`, `tags`, `enabled`, `expires_at`, `not_before`, `bits`, `curve`, and the JWK components `n`, `e`, `x`, `y` — all `omitempty`.

**HSM-backed keys legitimately have empty JWK components.** The material never left the token, so `n`/`e`/`x`/`y` are absent. That is not an error and must not be treated as one.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/keys.go` (new) | `Key`, `KeySummary`, `KeyVersion`, `KeyRotationPolicy`, and the four read methods |
| `internal/vaultapi/keys_test.go` (new) | Route shapes, JWK components, HSM empties, rotation policy |

---

### Task 1: `ListKeys` and `GetKey`

**Files:**
- Create: `internal/vaultapi/keys.go`
- Create: `internal/vaultapi/keys_test.go`

**Interfaces:**
- Consumes: `Client.Do` (plan 01), `Resolver.Resolve` and `KindKeys` (plan 04).
- Produces — plan 14's tools depend on these:
  - `type PublicJWK struct { N, E, X, Y string }` with `func (j PublicJWK) IsEmpty() bool`
  - `type KeySummary struct { ID uuid.UUID; Name, Type string; Tags []string; Enabled, Revoked bool; CreatedAt time.Time; ExpiresAt, NotBefore *time.Time }`
  - `type Key struct { KeySummary; Bits int; Curve string; PublicJWK PublicJWK; UpdatedAt *time.Time }`
  - `func (c *Client) ListKeys(ctx context.Context, vault string, limit int) ([]KeySummary, bool, error)`
  - `func (c *Client) GetKey(ctx context.Context, vault, name string) (*Key, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/keys_test.go`:

```go
package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const rsaKeyID = "4a1504e0-4f89-11d3-9a0c-0305e82c3401"

func TestListKeys_UsesVaultScopedRouteAndKeysWrapper(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[
			{"id":"` + rsaKeyID + `","name":"signing-key","type":"RSA","enabled":true,
			 "revoked":false,"tags":["prod"],"created_at":"2026-08-01T00:00:00Z"}
		]}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListKeys(context.Background(), "prod", 50)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/keys", gotPath)
	require.False(t, truncated)
	require.Len(t, got, 1)
	require.Equal(t, "signing-key", got[0].Name)
	require.Equal(t, "RSA", got[0].Type)
	require.Equal(t, uuid.MustParse(rsaKeyID), got[0].ID)
	require.True(t, got[0].Enabled)
	require.False(t, got[0].Revoked)
}

func TestListKeys_TruncatesAtLimitAndReportsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[
			{"id":"` + rsaKeyID + `","name":"a","type":"RSA"},
			{"id":"` + dbSecretID + `","name":"b","type":"EC"},
			{"id":"` + apiSecretID + `","name":"c","type":"RSA"}
		]}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListKeys(context.Background(), "prod", 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.True(t, truncated)
}

func TestListKeys_RequiresVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListKeys(context.Background(), "", 50)
	require.ErrorContains(t, err, "vault is required")
}

func TestGetKey_ReturnsRSAPublicComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"signing-key","type":"RSA",
			"bits":2048,"enabled":true,"n":"sXchDaQ","e":"AQAB","created_at":"2026-08-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Equal(t, "signing-key", got.Name)
	require.Equal(t, 2048, got.Bits)
	require.Equal(t, "sXchDaQ", got.PublicJWK.N)
	require.Equal(t, "AQAB", got.PublicJWK.E)
	require.False(t, got.PublicJWK.IsEmpty())
}

func TestGetKey_ReturnsECPublicComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"ec-key","type":"EC",
			"curve":"P-256","x":"f83OJ3D2","y":"x_FEzRu9","enabled":true}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Equal(t, "P-256", got.Curve)
	require.Equal(t, "f83OJ3D2", got.PublicJWK.X)
	require.Equal(t, "x_FEzRu9", got.PublicJWK.Y)
	require.False(t, got.PublicJWK.IsEmpty())
}

func TestGetKey_HSMKeyWithNoComponentsIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// An HSM-backed key's material never left the token, so the JWK
		// components are omitted. That is expected, not a failure.
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"hsm-key","type":"RSA","enabled":true}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err, "an HSM key without public components must not be an error")
	require.True(t, got.PublicJWK.IsEmpty())
	require.Equal(t, "hsm-key", got.Name)
}

func TestGetKey_ResolvesNameThenFetchesByID(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/keys" {
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"signing-key","type":"RSA"}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", "signing-key")
	require.NoError(t, err)
	require.Equal(t, []string{"/api/v1/vaults/prod/keys", "/api/v1/vaults/prod/keys/" + rsaKeyID}, paths)
}

func TestGetKey_CarriesNoPrivateMaterialField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Even if a server were to send private material, it must not surface.
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"signing-key","type":"RSA",
			"value":"-----BEGIN PRIVATE KEY-----LEAKED-----END PRIVATE KEY-----"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED",
		"Key has no private-material field, so a stray server value is dropped")
	require.NotContains(t, string(encoded), "PRIVATE KEY")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestListKeys_|TestGetKey_' -v`
Expected: FAIL — `c.ListKeys undefined`, `c.GetKey undefined`, `undefined: PublicJWK`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/keys.go`:

```go
package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// PublicJWK holds a key's public components.
//
// All four are empty for an HSM-backed key, whose material never left the
// token. That is expected, not a failure.
type PublicJWK struct {
	N string `json:"n,omitempty"` // RSA modulus, base64url.
	E string `json:"e,omitempty"` // RSA public exponent, base64url.
	X string `json:"x,omitempty"` // EC x coordinate, base64url.
	Y string `json:"y,omitempty"` // EC y coordinate, base64url.
}

// IsEmpty reports whether no public components were returned, which is the
// normal case for an HSM-backed key.
func (j PublicJWK) IsEmpty() bool {
	return j.N == "" && j.E == "" && j.X == "" && j.Y == ""
}

// KeySummary is a key as it appears in a list.
//
// Like every type in this file it has no field for private material, and none
// may be added. api.KeyResponse makes the same guarantee.
type KeySummary struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Tags      []string   `json:"tags,omitempty"`
	Enabled   bool       `json:"enabled"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
}

// Key is a single key with its metadata and public components.
type Key struct {
	KeySummary
	Bits      int        `json:"bits,omitempty"`
	Curve     string     `json:"curve,omitempty"`
	PublicJWK PublicJWK  `json:"public_jwk"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// keyWire is the raw response shape (api/keys.go:70). It is decoded into the
// exported types so the server's field layout is never the public one.
type keyWire struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`
	Tags      []string   `json:"tags"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at"`
	NotBefore *time.Time `json:"not_before"`
	Bits      int        `json:"bits"`
	Curve     string     `json:"curve"`
	N         string     `json:"n"`
	E         string     `json:"e"`
	X         string     `json:"x"`
	Y         string     `json:"y"`
}

type keysListResponse struct {
	Keys []keyWire `json:"keys"`
}

func (w keyWire) summary() (KeySummary, error) {
	id, err := uuid.Parse(w.ID)
	if err != nil {
		return KeySummary{}, fmt.Errorf("vaultapi: key %q has an unparseable id: %w", w.Name, err)
	}
	return KeySummary{
		ID:        id,
		Name:      w.Name,
		Type:      w.Type,
		Tags:      w.Tags,
		Enabled:   w.Enabled,
		Revoked:   w.Revoked,
		CreatedAt: w.CreatedAt,
		ExpiresAt: w.ExpiresAt,
		NotBefore: w.NotBefore,
	}, nil
}

// ListKeys returns the keys in vault, capped at limit. The bool reports
// truncation. A limit of zero or less returns everything.
func (c *Client) ListKeys(ctx context.Context, vault string, limit int) ([]KeySummary, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to list keys")
	}

	var response keysListResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/keys", vault)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	truncated := limit > 0 && len(response.Keys) > limit
	wires := response.Keys
	if truncated {
		wires = wires[:limit]
	}

	summaries := make([]KeySummary, 0, len(wires))
	for _, wire := range wires {
		summary, err := wire.summary()
		if err != nil {
			return nil, false, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, truncated, nil
}

// GetKey fetches one key by name or id, including its public JWK components.
func (c *Client) GetKey(ctx context.Context, vault, name string) (*Key, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to get a key")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	var wire keyWire
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &wire); err != nil {
		return nil, err
	}

	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Key{
		KeySummary: summary,
		Bits:       wire.Bits,
		Curve:      wire.Curve,
		PublicJWK:  PublicJWK{N: wire.N, E: wire.E, X: wire.X, Y: wire.Y},
		UpdatedAt:  wire.UpdatedAt,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run 'TestListKeys_|TestGetKey_' -v`
Expected: PASS — all eight tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/keys.go internal/vaultapi/keys_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add ListKeys and GetKey

GetKey surfaces the public JWK components. An HSM-backed key returns none,
because its material never left the token, and that is treated as expected
rather than as an error. No type here has a field for private material, and a
test pins that a stray server-side value cannot surface through one."
```

---

### Task 2: `GetKeyVersions`

**Files:**
- Modify: `internal/vaultapi/keys.go`
- Modify: `internal/vaultapi/keys_test.go` (append)

**Interfaces:**
- Consumes: `Client.Do`, `Resolver.Resolve`, `PublicJWK` from Task 1.
- Produces:
  - `type KeyVersion struct { KeyID uuid.UUID; Version int; CreatedAt time.Time; PublicJWK PublicJWK }`
  - `func (c *Client) GetKeyVersions(ctx context.Context, vault, name string) ([]KeyVersion, error)`

**Route shape:** `GET /api/v1/vaults/{v}/keys/{id}/versions` returns an array of `KeyVersionResponse`, which embeds `model.KeyVersion` (`key_id`, `version`, `created_at`) and adds `n`/`e`/`x`/`y` (`api/keys.go:98-104`). Because the embed is inline, the JSON is flat.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/keys_test.go`:

```go
func TestGetKeyVersions_DecodesFlatEmbeddedShape(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// KeyVersionResponse embeds model.KeyVersion, so the JSON is flat.
		_, _ = w.Write([]byte(`[
			{"key_id":"` + rsaKeyID + `","version":1,"created_at":"2026-06-01T00:00:00Z","n":"old-n","e":"AQAB"},
			{"key_id":"` + rsaKeyID + `","version":2,"created_at":"2026-07-01T00:00:00Z","n":"new-n","e":"AQAB"}
		]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/versions", gotPath)
	require.Len(t, got, 2)
	require.Equal(t, 1, got[0].Version)
	require.Equal(t, "old-n", got[0].PublicJWK.N)
	require.Equal(t, 2, got[1].Version)
	require.Equal(t, "new-n", got[1].PublicJWK.N)
	require.Equal(t, uuid.MustParse(rsaKeyID), got[0].KeyID)
}

func TestGetKeyVersions_HSMVersionsHaveEmptyComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"key_id":"` + rsaKeyID + `","version":1,"created_at":"2026-06-01T00:00:00Z"}]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].PublicJWK.IsEmpty())
}

func TestGetKeyVersions_ResolvesNameFirst(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/keys" {
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		_, _ = w.Write([]byte(`[{"key_id":"` + rsaKeyID + `","version":1}]`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", "signing-key")
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/versions", paths[1])
}

func TestGetKeyVersions_EmptyHistoryIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestGetKeyVersions_CarriesNoPrivateMaterialField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"key_id":"` + rsaKeyID + `","version":1,"value":"LEAKED-PRIVATE"}]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED-PRIVATE")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestGetKeyVersions_ -v`
Expected: FAIL — `c.GetKeyVersions undefined`.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/vaultapi/keys.go`:

```go
// KeyVersion is one entry of a key's version history, with that version's
// public components.
//
// It has no field for private material. api.KeyVersionResponse states the
// same rule about the type it embeds: "there is deliberately no Value or PEM
// field here, and none may be added".
type KeyVersion struct {
	KeyID     uuid.UUID `json:"key_id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	PublicJWK PublicJWK `json:"public_jwk"`
}

// keyVersionWire is the flat response shape produced by
// KeyVersionResponse's inline embed of model.KeyVersion.
type keyVersionWire struct {
	KeyID     string    `json:"key_id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	N         string    `json:"n"`
	E         string    `json:"e"`
	X         string    `json:"x"`
	Y         string    `json:"y"`
}

// GetKeyVersions returns a key's version history with each version's public
// components. The route encodes its slice directly, so the response is a bare
// JSON array.
func (c *Client) GetKeyVersions(ctx context.Context, vault, name string) ([]KeyVersion, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to list key versions")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	var wires []keyVersionWire
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/versions", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &wires); err != nil {
		return nil, err
	}

	versions := make([]KeyVersion, 0, len(wires))
	for _, wire := range wires {
		keyID, err := uuid.Parse(wire.KeyID)
		if err != nil {
			// A version whose key id is unparseable is still useful; report
			// the version rather than failing the whole history.
			keyID = id
		}
		versions = append(versions, KeyVersion{
			KeyID:     keyID,
			Version:   wire.Version,
			CreatedAt: wire.CreatedAt,
			PublicJWK: PublicJWK{N: wire.N, E: wire.E, X: wire.X, Y: wire.Y},
		})
	}
	return versions, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestGetKeyVersions_ -v`
Expected: PASS — all five tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/keys.go internal/vaultapi/keys_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add GetKeyVersions

KeyVersionResponse embeds model.KeyVersion inline, so the JSON is flat and the
wire type mirrors that. Each version carries its own public components, empty
for HSM-backed keys."
```

---

### Task 3: `GetKeyRotationPolicy`

**Files:**
- Modify: `internal/vaultapi/keys.go`
- Modify: `internal/vaultapi/keys_test.go` (append)

**Interfaces:**
- Consumes: `Client.Do`, `Resolver.Resolve`.
- Produces — plan 14's `get_key` includes the policy, plan 22's `set_key_rotation_policy` reuses the type:
  - `type KeyRotationPolicy struct { KeyID uuid.UUID; RotateAfterDays, NotifyBeforeExpiryDays, ExpiryDays int; Enabled bool; LastRotatedAt *time.Time; NextRotationAt time.Time }`
  - `func (c *Client) GetKeyRotationPolicy(ctx context.Context, vault, name string) (*KeyRotationPolicy, error)` — returns `(nil, nil)` when no policy is set.

**Why `(nil, nil)` for "no policy":** most keys have no rotation policy, and that is an ordinary state, not a failure. Returning an error would force every caller to distinguish "absent" from "denied", which is exactly the distinction `common.LoadCurrentSession` already models this way in this codebase (`common/session.go:243`).

`model.KeyRotationPolicy` also carries `id`, `user_id` and `vault_id`. Those are internal identifiers with no meaning to an agent, so they are deliberately not surfaced.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/keys_test.go`:

```go
func TestGetKeyRotationPolicy_ReturnsThePolicy(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","key_id":"` + rsaKeyID + `",
			"user_id":"` + apiSecretID + `","vault_id":"` + signKeyID + `",
			"rotate_after_days":90,"notify_before_expiry_days":14,"expiry_days":365,
			"enabled":true,"next_rotation_at":"2026-11-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotationpolicy", gotPath)
	require.Equal(t, 90, got.RotateAfterDays)
	require.Equal(t, 14, got.NotifyBeforeExpiryDays)
	require.Equal(t, 365, got.ExpiryDays)
	require.True(t, got.Enabled)
	require.Equal(t, uuid.MustParse(rsaKeyID), got.KeyID)
}

func TestGetKeyRotationPolicy_AbsentPolicyIsNilNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err, "most keys have no rotation policy, which is an ordinary state")
	require.Nil(t, got)
}

func TestGetKeyRotationPolicy_ForbiddenIsStillAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", rsaKeyID)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr, "absent and denied must not be conflated")
	require.Equal(t, KindForbidden, apiErr.Kind)
}

func TestGetKeyRotationPolicy_OmitsInternalIdentifiers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","key_id":"` + rsaKeyID + `",
			"user_id":"` + apiSecretID + `","vault_id":"` + signKeyID + `","rotate_after_days":90}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), apiSecretID, "user_id has no meaning to an agent")
	require.NotContains(t, string(encoded), signKeyID, "vault_id has no meaning to an agent")
}

func TestGetKeyRotationPolicy_ResolvesNameFirst(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/keys" {
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"key_id":"` + rsaKeyID + `","rotate_after_days":30}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", "signing-key")
	require.NoError(t, err)
	require.Equal(t, 30, got.RotateAfterDays)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotationpolicy", paths[1])
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestGetKeyRotationPolicy_ -v`
Expected: FAIL — `c.GetKeyRotationPolicy undefined`.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/vaultapi/keys.go`, adding `"errors"` to the imports:

```go
// KeyRotationPolicy describes when a key rotates.
//
// model.KeyRotationPolicy also carries id, user_id and vault_id. Those are
// internal identifiers with no meaning to an agent, so they are deliberately
// not surfaced here.
type KeyRotationPolicy struct {
	KeyID                  uuid.UUID  `json:"key_id"`
	RotateAfterDays        int        `json:"rotate_after_days"`
	NotifyBeforeExpiryDays int        `json:"notify_before_expiry_days"`
	ExpiryDays             int        `json:"expiry_days"`
	Enabled                bool       `json:"enabled"`
	LastRotatedAt          *time.Time `json:"last_rotated_at,omitempty"`
	NextRotationAt         time.Time  `json:"next_rotation_at"`
}

// GetKeyRotationPolicy returns a key's rotation policy, or (nil, nil) when
// none is set.
//
// An absent policy is the ordinary case for most keys, so it is not an error.
// A denial still is: absent and forbidden must never be conflated, or an
// operator loses the signal that they lack a grant.
func (c *Client) GetKeyRotationPolicy(ctx context.Context, vault, name string) (*KeyRotationPolicy, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to get a key rotation policy")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	var wire struct {
		KeyID                  string     `json:"key_id"`
		RotateAfterDays        int        `json:"rotate_after_days"`
		NotifyBeforeExpiryDays int        `json:"notify_before_expiry_days"`
		ExpiryDays             int        `json:"expiry_days"`
		Enabled                bool       `json:"enabled"`
		LastRotatedAt          *time.Time `json:"last_rotated_at"`
		NextRotationAt         time.Time  `json:"next_rotation_at"`
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/rotationpolicy", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &wire); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Kind == KindNotFound {
			return nil, nil
		}
		return nil, err
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &KeyRotationPolicy{
		KeyID:                  keyID,
		RotateAfterDays:        wire.RotateAfterDays,
		NotifyBeforeExpiryDays: wire.NotifyBeforeExpiryDays,
		ExpiryDays:             wire.ExpiryDays,
		Enabled:                wire.Enabled,
		LastRotatedAt:          wire.LastRotatedAt,
		NextRotationAt:         wire.NextRotationAt,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/keys.go internal/vaultapi/keys_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add GetKeyRotationPolicy

An absent policy returns (nil, nil), since most keys have none and that is an
ordinary state rather than a failure. A 403 still errors: conflating absent
with denied would cost an operator the signal that they lack a grant. The
policy's internal id, user_id and vault_id are not surfaced -- they mean
nothing to an agent."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

Confirm the no-private-material guarantee holds across all three key types:

```bash
go test ./internal/vaultapi/ -run 'TestGetKey_CarriesNoPrivate|TestGetKeyVersions_CarriesNoPrivate' -v
```

## Notes for the next plan

Plan 07 covers certificates and vaults, following the same shape. Two
differences worth knowing before starting it:

- `api.CertificateResponse` (`api/certificates.go:68`) carries metadata only —
  no PEM, no chain — so certificates need no redacting type either.
- Vault routes are **not** vault-scoped, for the obvious reason: `GET
  /api/v1/vaults` lists them and `GET /api/v1/vaults/{name}` fetches one by
  name, not by UUID. `Resolver` is not involved for vaults at all.
