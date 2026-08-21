# Secrets Read Methods Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `ListSecrets`, `GetSecret` and `GetSecretVersions` to `internal/vaultapi`, with a `SecretValue` type that keeps plaintext out of logs and drops it on demand.

**Architecture:** Three read methods over vault-scoped routes, each addressing resources by name through plan 04's `Resolver`. `GetSecret` returns a `Secret` whose `Value` field is a `SecretValue` — a string wrapper whose `String`, `GoString` and `MarshalJSON` all redact, so the plaintext cannot reach a log line or a marshalled response by accident. Callers who genuinely need it call `Reveal()`.

**Tech Stack:** Go 1.25, `github.com/google/uuid`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — sections "Tool surface > Read tier" and "Production hardening > Memory hygiene".

**Plan-of-plans:** This is plan 05 of 31. Requires plans 01 and 04 committed. Sets the shape plans 06, 07 and 08 copy.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Vault-scoped routes only** — `/api/v1/vaults/{vault}/secrets`, never `/api/v1/secrets`.
- **Plaintext must never reach a log line or an accidental marshal.** Redaction is a property of the type, not of the caller's discipline.
- `vaultapi` must not import the MCP SDK or `internal/mcpserver`.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## A constraint the server imposes, stated plainly

`GET /api/v1/vaults/{v}/secrets/{id}` **always returns the plaintext value**. The handler sets `Value: secret.Value` unconditionally, under the comment "include value for get operation" (`api/secrets.go:462-465`). There is no query parameter to suppress it.

Two consequences, both of which this plan handles rather than hides:

1. **The value enters the MCP server process whether or not the operator enabled `allow_secret_values`.** Client-side redaction controls what reaches the *model*, which is the threat that matters, but it cannot stop the value crossing the wire. Anyone reasoning about this system should know that.
2. **Metadata-only reads cannot simply ask for less.** `ListSecrets` genuinely omits values (`api/secrets.go:414-424`), but it also omits `content_type`, `enabled`, `expires_at` and `not_before` — and expiry is exactly what an operator asks about. So `GetSecret` uses the get route and drops the value at the client boundary.

`SecretValue` exists because of this. The value arrives regardless, so the type makes discarding it the default and revealing it the deliberate act.

**Recommended follow-up, out of scope here:** add an `?include_value=false` query parameter to the get route so the value need not cross the wire at all. That is a change to an existing endpoint rather than a new one, but it is a server change and this plan's spec forbids those, so it should be proposed separately.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/secrets.go` (new) | `Secret`, `SecretSummary`, `SecretVersion`, `ListSecrets`, `GetSecret`, `GetSecretVersions` |
| `internal/vaultapi/secretvalue.go` (new) | `SecretValue` and its redacting behavior |
| `internal/vaultapi/secrets_test.go` (new) | Route shapes, name resolution, limit handling |
| `internal/vaultapi/secretvalue_test.go` (new) | Redaction on every formatting and marshalling path |

---

### Task 1: `SecretValue`, a plaintext type that redacts by default

**Files:**
- Create: `internal/vaultapi/secretvalue.go`
- Create: `internal/vaultapi/secretvalue_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces — plan 12's `redact.go` and plan 13's `get_secret` tool depend on these:
  - `type SecretValue string`
  - `func (v SecretValue) Reveal() string`
  - `func (v SecretValue) String() string` — always `"[REDACTED]"`.
  - `func (v SecretValue) GoString() string` — always `"[REDACTED]"`.
  - `func (v SecretValue) MarshalJSON() ([]byte, error)` — always `"[REDACTED]"`.
  - `func (v *SecretValue) Zero()` — satisfies the `cachekit.Zeroable` convention.

**Why all four formatting paths:** a value reaches a log through `%s` (`String`), through `%v` and `%#v` (`GoString`), and through a marshalled struct (`MarshalJSON`). Covering one and missing the others is how these leaks actually happen.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/secretvalue_test.go`:

```go
package vaultapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const plaintext = "hunter2-super-secret"

func TestSecretValue_RevealReturnsPlaintext(t *testing.T) {
	v := SecretValue(plaintext)
	require.Equal(t, plaintext, v.Reveal())
}

func TestSecretValue_StringRedacts(t *testing.T) {
	v := SecretValue(plaintext)
	require.Equal(t, "[REDACTED]", v.String())
	require.NotContains(t, fmt.Sprintf("%s", v), plaintext)
}

func TestSecretValue_VerbFormattingRedacts(t *testing.T) {
	v := SecretValue(plaintext)
	for _, format := range []string{"%s", "%v", "%q", "%#v", "%+v"} {
		rendered := fmt.Sprintf(format, v)
		require.NotContains(t, rendered, plaintext, "format %s leaked the value", format)
	}
}

func TestSecretValue_MarshalJSONRedacts(t *testing.T) {
	v := SecretValue(plaintext)
	encoded, err := json.Marshal(v)
	require.NoError(t, err)
	require.JSONEq(t, `"[REDACTED]"`, string(encoded))
}

func TestSecretValue_RedactsInsideAStruct(t *testing.T) {
	type payload struct {
		Name  string      `json:"name"`
		Value SecretValue `json:"value"`
	}
	encoded, err := json.Marshal(payload{Name: "db-password", Value: SecretValue(plaintext)})
	require.NoError(t, err)
	require.NotContains(t, string(encoded), plaintext,
		"a value must not leak when its containing struct is marshalled")
	require.Contains(t, string(encoded), "db-password")
}

func TestSecretValue_RedactsWhenLoggedViaPrintf(t *testing.T) {
	var sb strings.Builder
	v := SecretValue(plaintext)
	_, _ = fmt.Fprintf(&sb, "fetched secret value=%v extra=%#v", v, v)
	require.NotContains(t, sb.String(), plaintext)
	require.Equal(t, 2, strings.Count(sb.String(), "[REDACTED]"))
}

func TestSecretValue_ZeroClearsTheValue(t *testing.T) {
	v := SecretValue(plaintext)
	v.Zero()
	require.Empty(t, v.Reveal())
}

func TestSecretValue_EmptyRevealsEmpty(t *testing.T) {
	var v SecretValue
	require.Empty(t, v.Reveal())
	require.Equal(t, "[REDACTED]", v.String(),
		"an empty value still renders as redacted, so its emptiness is not disclosed")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestSecretValue_ -v`
Expected: FAIL — `undefined: SecretValue`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/secretvalue.go`:

```go
package vaultapi

// redactedPlaceholder is what a SecretValue renders as on every path except
// an explicit Reveal.
const redactedPlaceholder = "[REDACTED]"

// SecretValue holds a secret's plaintext.
//
// The server returns the value on every GET of a secret and offers no way to
// suppress it (api/secrets.go:462), so the plaintext arrives whether or not
// the caller wants it. This type therefore makes discarding it the default:
// String, GoString and MarshalJSON all redact, so a value cannot reach a log
// line or a marshalled response by accident. Reading it is the deliberate act
// of calling Reveal.
type SecretValue string

// Reveal returns the plaintext. Call it only where the value is genuinely
// needed, and never on a path that logs.
func (v SecretValue) Reveal() string { return string(v) }

// String renders the value as redacted, covering %s and %v.
func (v SecretValue) String() string { return redactedPlaceholder }

// GoString renders the value as redacted, covering %#v.
func (v SecretValue) GoString() string { return redactedPlaceholder }

// MarshalJSON renders the value as redacted, so a struct carrying one is safe
// to marshal.
func (v SecretValue) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedPlaceholder + `"`), nil
}

// Zero clears the value.
//
// Go strings are immutable and the runtime may have copied this one, so this
// cannot erase every copy. It drops this reference, bounding how long the
// plaintext stays reachable — the same guarantee cachekit.Zeroable provides.
func (v *SecretValue) Zero() { *v = "" }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestSecretValue_ -v`
Expected: PASS — all eight tests.

Note: `%q` on a type with a `String` method renders the quoted `String()` output, so `TestSecretValue_VerbFormattingRedacts` passes for `%q` too.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/secretvalue.go internal/vaultapi/secretvalue_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add SecretValue, which redacts on every path but Reveal

The get-secret route always returns plaintext and offers no way to suppress
it, so the value arrives whether or not a caller wants it. SecretValue makes
discarding it the default: String, GoString and MarshalJSON all redact, so a
value cannot reach a log line or a marshalled response by accident."
```

---

### Task 2: `ListSecrets` and `GetSecret`

**Files:**
- Create: `internal/vaultapi/secrets.go`
- Create: `internal/vaultapi/secrets_test.go`

**Interfaces:**
- Consumes: `Client.Do` (plan 01), `Resolver.Resolve` and `KindSecrets` (plan 04), `SecretValue` (Task 1).
- Produces — plan 13's tools depend on these:
  - `type SecretSummary struct { ID uuid.UUID; Name string; Tags []string; Version int; CreatedAt string }`
  - `type Secret struct { SecretSummary; Value SecretValue; ContentType string; Enabled bool; ExpiresAt, NotBefore *time.Time }`
  - `func (c *Client) ListSecrets(ctx context.Context, vault string, limit int) ([]SecretSummary, bool, error)` — the bool reports truncation.
  - `func (c *Client) GetSecret(ctx context.Context, vault, name string) (*Secret, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/secrets_test.go`:

```go
package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func newClientForTest(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)
	return c
}

func TestListSecrets_UsesVaultScopedRoute(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password","version":3,"tags":["prod"],"created_at":"2026-08-01T00:00:00Z"}
		],"total":1}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListSecrets(context.Background(), "prod", 50)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/secrets", gotPath,
		"the flat route resolves to the default vault and must never be used")
	require.False(t, truncated)
	require.Len(t, got, 1)
	require.Equal(t, "db-password", got[0].Name)
	require.Equal(t, uuid.MustParse(dbSecretID), got[0].ID)
	require.Equal(t, 3, got[0].Version)
	require.Equal(t, []string{"prod"}, got[0].Tags)
}

func TestListSecrets_TruncatesAtLimitAndReportsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[
			{"id":"` + dbSecretID + `","name":"a"},
			{"id":"` + apiSecretID + `","name":"b"},
			{"id":"` + signKeyID + `","name":"c"}
		],"total":3}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListSecrets(context.Background(), "prod", 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.True(t, truncated, "the caller must be able to tell the model the list was cut short")
}

func TestListSecrets_ZeroLimitReturnsEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[
			{"id":"` + dbSecretID + `","name":"a"},
			{"id":"` + apiSecretID + `","name":"b"}
		],"total":2}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListSecrets(context.Background(), "prod", 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.False(t, truncated)
}

func TestListSecrets_EmptyVaultIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[],"total":0}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListSecrets(context.Background(), "prod", 50)
	require.NoError(t, err)
	require.Empty(t, got)
	require.False(t, truncated)
}

func TestListSecrets_RequiresVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListSecrets(context.Background(), "", 50)
	require.ErrorContains(t, err, "vault is required")
}

func TestGetSecret_ResolvesNameThenFetchesByID(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/vaults/prod/secrets":
			_, _ = w.Write([]byte(`{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`))
		case "/api/v1/vaults/prod/secrets/" + dbSecretID:
			_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","name":"db-password","value":"` + plaintext + `",
				"version":3,"content_type":"text/plain","enabled":true,"created_at":"2026-08-01T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecret(context.Background(), "prod", "db-password")
	require.NoError(t, err)
	require.Equal(t, []string{"/api/v1/vaults/prod/secrets", "/api/v1/vaults/prod/secrets/" + dbSecretID}, paths)
	require.Equal(t, "db-password", got.Name)
	require.Equal(t, 3, got.Version)
	require.Equal(t, "text/plain", got.ContentType)
	require.True(t, got.Enabled)
}

func TestGetSecret_CapturesValueAsSecretValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","name":"db-password","value":"` + plaintext + `"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecret(context.Background(), "prod", dbSecretID)
	require.NoError(t, err)
	require.Equal(t, plaintext, got.Value.Reveal(), "the value must be readable when deliberately revealed")
	require.Equal(t, "[REDACTED]", got.Value.String())
}

func TestGetSecret_MarshallingTheResultNeverLeaksTheValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","name":"db-password","value":"` + plaintext + `"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecret(context.Background(), "prod", dbSecretID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), plaintext,
		"marshalling a Secret must never disclose its value")
}

func TestGetSecret_UnknownNameReportsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secrets":[],"total":0}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetSecret(context.Background(), "prod", "nope")
	require.ErrorContains(t, err, "no secrets named")
}
```

Add `"encoding/json"` to the test file's import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestListSecrets_|TestGetSecret_' -v`
Expected: FAIL — `c.ListSecrets undefined`, `c.GetSecret undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/secrets.go`:

```go
package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// SecretSummary is a secret as it appears in a list. The list route omits
// values (api/secrets.go:414), and this type has no field for one.
type SecretSummary struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Tags      []string  `json:"tags,omitempty"`
	Version   int       `json:"version"`
	CreatedAt string    `json:"created_at,omitempty"`
}

// Secret is a single secret with its metadata.
//
// Value is a SecretValue, so marshalling a Secret redacts it. The server
// returns the plaintext on every get and offers no way to suppress it, so the
// type is what keeps it from escaping.
type Secret struct {
	SecretSummary
	Value       SecretValue `json:"value"`
	ContentType string      `json:"content_type,omitempty"`
	Enabled     bool        `json:"enabled"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	NotBefore   *time.Time  `json:"not_before,omitempty"`
}

// secretsListResponse mirrors model.ListSecretsResponse (model/secret.go:257).
type secretsListResponse struct {
	Secrets []secretWire `json:"secrets"`
	Total   int          `json:"total"`
}

// secretWire is the raw response shape. It is decoded into the exported types
// so Value never exists as a bare string on an exported struct.
type secretWire struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Value       string     `json:"value"`
	Tags        []string   `json:"tags"`
	Version     int        `json:"version"`
	ContentType string     `json:"content_type"`
	CreatedAt   string     `json:"created_at"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at"`
	NotBefore   *time.Time `json:"not_before"`
}

func (w secretWire) summary() (SecretSummary, error) {
	id, err := uuid.Parse(w.ID)
	if err != nil {
		return SecretSummary{}, fmt.Errorf("vaultapi: secret %q has an unparseable id: %w", w.Name, err)
	}
	return SecretSummary{
		ID:        id,
		Name:      w.Name,
		Tags:      w.Tags,
		Version:   w.Version,
		CreatedAt: w.CreatedAt,
	}, nil
}

// ListSecrets returns the secrets in vault, capped at limit. The bool reports
// whether the list was truncated, so a caller can say so rather than silently
// presenting a partial view. A limit of zero or less returns everything.
func (c *Client) ListSecrets(ctx context.Context, vault string, limit int) ([]SecretSummary, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to list secrets")
	}

	var response secretsListResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/secrets", vault)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	truncated := limit > 0 && len(response.Secrets) > limit
	wires := response.Secrets
	if truncated {
		wires = wires[:limit]
	}

	summaries := make([]SecretSummary, 0, len(wires))
	for _, wire := range wires {
		summary, err := wire.summary()
		if err != nil {
			return nil, false, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, truncated, nil
}

// GetSecret fetches one secret by name or id.
//
// The response always carries the plaintext value; there is no server-side
// way to ask for metadata only. It lands in Secret.Value, which redacts on
// every path but Reveal.
func (c *Client) GetSecret(ctx context.Context, vault, name string) (*Secret, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to get a secret")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindSecrets, name)
	if err != nil {
		return nil, err
	}

	var wire secretWire
	path := fmt.Sprintf("/api/v1/vaults/%s/secrets/%s", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &wire); err != nil {
		return nil, err
	}

	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Secret{
		SecretSummary: summary,
		Value:         SecretValue(wire.Value),
		ContentType:   wire.ContentType,
		Enabled:       wire.Enabled,
		ExpiresAt:     wire.ExpiresAt,
		NotBefore:     wire.NotBefore,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run 'TestListSecrets_|TestGetSecret_' -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/secrets.go internal/vaultapi/secrets_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add ListSecrets and GetSecret

Both use vault-scoped routes; the flat route resolves to the default vault
and is never used. ListSecrets reports truncation so a caller can say the
list was cut short rather than present a partial view silently. GetSecret
lands the plaintext in a SecretValue, since the server returns it
unconditionally."
```

---

### Task 3: `GetSecretVersions`

**Files:**
- Modify: `internal/vaultapi/secrets.go`
- Modify: `internal/vaultapi/secrets_test.go` (append)

**Interfaces:**
- Consumes: `Client.Do`, `Resolver.Resolve`, `SecretSummary` from Tasks 1 and 2.
- Produces — plan 13's `get_secret` includes version history:
  - `type SecretVersion struct { Version int; CreatedAt string; Enabled bool }`
  - `func (c *Client) GetSecretVersions(ctx context.Context, vault, name string) ([]SecretVersion, error)`

**Route shape:** `GET /api/v1/vaults/{v}/secrets/{id}/versions` encodes the service's metadata slice directly — `json.NewEncoder(w).Encode(versions)` with `versions` from `GetSecretVersionsMetadata` (`api/secrets.go:106-112`). It is a **bare JSON array**, not an object with a wrapper key. Decode into a slice.

Version metadata carries no values, so no `SecretValue` is involved here.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/secrets_test.go`:

```go
func TestGetSecretVersions_DecodesABareArray(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// The handler encodes the slice directly, with no wrapper object.
		_, _ = w.Write([]byte(`[
			{"version":1,"created_at":"2026-06-01T00:00:00Z","enabled":false},
			{"version":2,"created_at":"2026-07-01T00:00:00Z","enabled":true}
		]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecretVersions(context.Background(), "prod", dbSecretID)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/secrets/"+dbSecretID+"/versions", gotPath)
	require.Len(t, got, 2)
	require.Equal(t, 1, got[0].Version)
	require.False(t, got[0].Enabled)
	require.Equal(t, 2, got[1].Version)
	require.True(t, got[1].Enabled)
}

func TestGetSecretVersions_ResolvesNameFirst(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/secrets" {
			_, _ = w.Write([]byte(`{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`))
			return
		}
		_, _ = w.Write([]byte(`[{"version":1,"created_at":"2026-06-01T00:00:00Z","enabled":true}]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecretVersions(context.Background(), "prod", "db-password")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "/api/v1/vaults/prod/secrets/"+dbSecretID+"/versions", paths[1])
}

func TestGetSecretVersions_EmptyHistoryIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecretVersions(context.Background(), "prod", dbSecretID)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestGetSecretVersions_CarriesNoValueField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Even if the server were to send one, it must not surface.
		_, _ = w.Write([]byte(`[{"version":1,"value":"` + plaintext + `","enabled":true}]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetSecretVersions(context.Background(), "prod", dbSecretID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), plaintext,
		"version metadata has no value field, so a stray server value is dropped")
}

func TestGetSecretVersions_RequiresVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetSecretVersions(context.Background(), "", "db-password")
	require.ErrorContains(t, err, "vault is required")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestGetSecretVersions_ -v`
Expected: FAIL — `c.GetSecretVersions undefined`.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/vaultapi/secrets.go`:

```go
// SecretVersion is one entry of a secret's version history.
//
// It has no value field on purpose. The versions route returns metadata only,
// and omitting the field means a stray server-side value can never surface
// through this type.
type SecretVersion struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at,omitempty"`
	Enabled   bool   `json:"enabled"`
}

// GetSecretVersions returns a secret's version history, newest last.
//
// The route encodes the metadata slice directly (api/secrets.go:112), so the
// response is a bare JSON array rather than a wrapper object.
func (c *Client) GetSecretVersions(ctx context.Context, vault, name string) ([]SecretVersion, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to list secret versions")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindSecrets, name)
	if err != nil {
		return nil, err
	}

	var versions []SecretVersion
	path := fmt.Sprintf("/api/v1/vaults/%s/secrets/%s/versions", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &versions); err != nil {
		return nil, err
	}
	return versions, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/secrets.go internal/vaultapi/secrets_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add GetSecretVersions

The versions route encodes its metadata slice directly, so the response is a
bare JSON array rather than a wrapper object. SecretVersion has no value
field, so a stray server-side value cannot surface through it."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

The redaction tests are the ones that matter here. Confirm no plaintext escapes
any formatting or marshalling path:

```bash
go test ./internal/vaultapi/ -run 'TestSecretValue_|TestGetSecret_Marshalling' -v
```

## Notes for the next plan

Plans 06, 07 and 08 copy this plan's shape against their own routes. What
carries over:

- Vault-scoped path, built with `fmt.Sprintf("/api/v1/vaults/%s/...", vault)`.
- A `...Wire` unexported decode type, converted into exported types, so the
  raw server shape is never the public one.
- `Resolver.Resolve` before any by-id fetch.
- `limit` handling with a truncation bool on every list method.
- An empty result is never an error.

What does **not** carry over: `SecretValue`. Keys, certificates, role
assignments and audit entries carry no plaintext secret, so they need no
redacting type.
