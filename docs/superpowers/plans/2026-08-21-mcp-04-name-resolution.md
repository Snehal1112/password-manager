# Name-to-UUID Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let every later `vaultapi` method address resources by name. `Resolver` maps a `(vault, kind, name)` triple to a UUID by listing the vault, caching results per invocation, and failing loudly rather than guessing when a name is ambiguous or absent.

**Architecture:** A `Resolver` owns a `map[cacheKey][]namedItem` populated by one list call per `(vault, kind)` pair. Resolution is a pure lookup over that snapshot. The cache is per-`Resolver`, and a fresh `Resolver` is created per MCP tool call, so a rename between calls is never served stale.

**Tech Stack:** Go 1.25, `github.com/google/uuid`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Vault scoping and name resolution".

**Plan-of-plans:** This is plan 04 of 31. Requires plan 01 committed. Independent of plans 02 and 03.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Vault-scoped routes only.** Resolution lists `/api/v1/vaults/{vault}/{kind}`, never the flat route.
- **Never guess.** Two resources sharing a name is an error naming both candidates, not a silent pick. An agent acting on the wrong secret is worse than an agent that stops and asks.
- A UUID passed where a name is expected is accepted as-is, so tools work with either.
- `vaultapi` must not import the MCP SDK or `internal/mcpserver`.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified list contracts

Each list route wraps its array under a different key. The resolver must handle all three:

| Kind | Route | Wrapper | Item ID field |
|---|---|---|---|
| secrets | `GET /api/v1/vaults/{v}/secrets` | `{"secrets": [...], "total": N}` (`model/secret.go:257`) | `id` (string) |
| keys | `GET /api/v1/vaults/{v}/keys` | `{"keys": [...]}` (`api/keys.go:107`) | `id` (uuid) |
| certificates | `GET /api/v1/vaults/{v}/certificates` | `{"certificates": [...]}` (`api/certificates.go:82`) | `id` |

Note that `model.SecretResponse` carries `Value string \`json:"value,omitempty"\`` (`model/secret.go:241`). The list handler never populates it, but the *type* permits it. `vaultapi` therefore defines its own narrow item type with no value field at all, so a future server change cannot start feeding values through the resolution path.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/resolve.go` (new) | `Kind`, `Resolver`, `Resolve`, list-and-cache, ambiguity and near-miss errors |
| `internal/vaultapi/resolve_test.go` (new) | Resolution, caching, ambiguity, not-found, UUID passthrough |

---

### Task 1: Resolve a name to a UUID with per-invocation caching

**Files:**
- Create: `internal/vaultapi/resolve.go`
- Create: `internal/vaultapi/resolve_test.go`

**Interfaces:**
- Consumes: `Client.Do` from plan 01.
- Produces — every domain plan (05-08, 18-20, 23, 26) uses these:
  - `type Kind string` with `KindSecrets`, `KindKeys`, `KindCertificates`.
  - `func NewResolver(c *Client) *Resolver`
  - `func (r *Resolver) Resolve(ctx context.Context, vault string, kind Kind, name string) (uuid.UUID, error)`
  - `func (c *Client) Resolver() *Resolver` — convenience constructor.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/resolve_test.go`:

```go
package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const (
	dbSecretID  = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	apiSecretID = "3f2504e0-4f89-11d3-9a0c-0305e82c3302"
	signKeyID   = "3f2504e0-4f89-11d3-9a0c-0305e82c3303"
)

// listServer serves canned list responses per path and counts requests.
func listServer(t *testing.T, bodies map[string]string) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	return srv, &calls
}

func newResolverForTest(t *testing.T, srv *httptest.Server) *Resolver {
	t.Helper()
	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)
	return c.Resolver()
}

func TestResolver_ResolvesSecretNameToID(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password","version":3},
			{"id":"` + apiSecretID + `","name":"api-key","version":1}
		],"total":2}`,
	})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got)
}

func TestResolver_ResolvesKeyFromItsOwnWrapperKey(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/keys": `{"keys":[{"id":"` + signKeyID + `","name":"signing-key","type":"RSA"}]}`,
	})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindKeys, "signing-key")
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(signKeyID), got)
}

func TestResolver_ResolvesCertificateFromItsOwnWrapperKey(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/certificates": `{"certificates":[{"id":"` + signKeyID + `","name":"tls-cert"}]}`,
	})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindCertificates, "tls-cert")
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(signKeyID), got)
}

func TestResolver_CachesListPerVaultAndKind(t *testing.T) {
	srv, calls := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password"},
			{"id":"` + apiSecretID + `","name":"api-key"}
		],"total":2}`,
	})
	defer srv.Close()

	r := newResolverForTest(t, srv)
	for i := 0; i < 4; i++ {
		_, err := r.Resolve(context.Background(), "prod", KindSecrets, "db-password")
		require.NoError(t, err)
		_, err = r.Resolve(context.Background(), "prod", KindSecrets, "api-key")
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, atomic.LoadInt32(calls), "one list call should serve every lookup")
}

func TestResolver_SeparateVaultsAreCachedSeparately(t *testing.T) {
	srv, calls := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets":    `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
		"/api/v1/vaults/staging/secrets": `{"secrets":[{"id":"` + apiSecretID + `","name":"db-password"}],"total":1}`,
	})
	defer srv.Close()

	r := newResolverForTest(t, srv)
	prod, err := r.Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.NoError(t, err)
	staging, err := r.Resolve(context.Background(), "staging", KindSecrets, "db-password")
	require.NoError(t, err)

	require.NotEqual(t, prod, staging, "the same name in two vaults must resolve independently")
	require.EqualValues(t, 2, atomic.LoadInt32(calls))
}

func TestResolver_AcceptsAUUIDWithoutListing(t *testing.T) {
	srv, calls := listServer(t, map[string]string{})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, dbSecretID)
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got)
	require.EqualValues(t, 0, atomic.LoadInt32(calls), "a UUID needs no list call")
}

func TestResolver_RejectsEmptyName(t *testing.T) {
	srv, _ := listServer(t, map[string]string{})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "")
	require.ErrorContains(t, err, "name is required")
}

func TestResolver_RejectsEmptyVault(t *testing.T) {
	srv, _ := listServer(t, map[string]string{})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "", KindSecrets, "db-password")
	require.ErrorContains(t, err, "vault is required")
}

func TestResolver_PropagatesListFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	_, err = c.Resolver().Resolve(context.Background(), "prod", KindSecrets, "db-password")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindForbidden, apiErr.Kind)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestResolver_ -v`
Expected: FAIL — `undefined: Resolver`, `undefined: KindSecrets`, `c.Resolver undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/resolve.go`:

```go
package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
)

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
func notFoundError(vault string, kind Kind, name string, items []namedItem) error {
	near := nearMisses(name, items)
	if len(near) == 0 {
		return fmt.Errorf("vaultapi: no %s named %q in vault %q", kind, name, vault)
	}
	return fmt.Errorf("vaultapi: no %s named %q in vault %q; did you mean %s?",
		kind, name, vault, strings.Join(quoteAll(near), ", "))
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestResolver_ -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/resolve.go internal/vaultapi/resolve_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): resolve resource names to UUIDs

Every route is UUID-keyed but a model reasons in names, so tools accept names
and resolve them here. One list call per vault and kind is cached for the
Resolver's lifetime, which is a single tool call -- short enough that a rename
is never served stale. The resolver defines its own narrow item type with no
value field, so a server change cannot feed secret values through this path."
```

---

### Task 2: Ambiguity and near-miss errors

**Files:**
- Modify: `internal/vaultapi/resolve_test.go` (append)
- Modify: `internal/vaultapi/resolve.go` only if a test reveals a gap

**Interfaces:**
- Consumes: `Resolver.Resolve` from Task 1.
- Produces: no new exported surface. Plans 13-15 surface these messages verbatim in MCP error results, so their wording is part of the contract.

**Why this is its own task:** Task 1's implementation already contains `notFoundError` and `ambiguousError`, but nothing yet proves they behave correctly. These are the paths an agent hits when it guesses a name, so they are the ones most likely to be exercised in practice and least likely to be exercised by hand.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/resolve_test.go`:

```go
func TestResolver_AmbiguousNameNamesEveryCandidate(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password"},
			{"id":"` + apiSecretID + `","name":"db-password"}
		],"total":2}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.Error(t, err)
	require.Contains(t, err.Error(), dbSecretID)
	require.Contains(t, err.Error(), apiSecretID)
	require.Contains(t, err.Error(), "address one by id")
}

func TestResolver_AmbiguityIsNeverSilentlyResolved(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/keys": `{"keys":[
			{"id":"` + dbSecretID + `","name":"signing-key"},
			{"id":"` + apiSecretID + `","name":"signing-key"}
		]}`,
	})
	defer srv.Close()

	got, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindKeys, "signing-key")
	require.Error(t, err, "a duplicate name must never resolve to an arbitrary pick")
	require.Equal(t, uuid.Nil, got)
}

func TestResolver_NotFoundSuggestsNearMisses(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-password"},
			{"id":"` + apiSecretID + `","name":"db-password-legacy"}
		],"total":2}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-passw")
	require.Error(t, err)
	require.Contains(t, err.Error(), "did you mean")
	require.Contains(t, err.Error(), "db-password")
}

func TestResolver_NotFoundIsCaseInsensitiveWhenSuggesting(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"DB-Password"}],"total":1}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.Error(t, err, "matching is exact, so a case difference is still not found")
	require.Contains(t, err.Error(), "DB-Password", "but the suggestion should surface the real name")
}

func TestResolver_NotFoundWithNoNearMissOmitsSuggestion(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "totally-unrelated")
	require.Error(t, err)
	require.Contains(t, err.Error(), `no secrets named "totally-unrelated"`)
	require.NotContains(t, err.Error(), "did you mean")
}

func TestResolver_NotFoundCapsSuggestionsAtThree(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"db-a"},
			{"id":"` + apiSecretID + `","name":"db-b"},
			{"id":"` + signKeyID + `","name":"db-c"},
			{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3304","name":"db-d"},
			{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3305","name":"db-e"}
		],"total":5}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db")
	require.Error(t, err)
	require.Equal(t, 3, strings.Count(err.Error(), `"db-`),
		"suggestions must be capped so an error stays readable in a model's context")
}

func TestResolver_ErrorNamesTheVault(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/staging/secrets": `{"secrets":[],"total":0}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "staging", KindSecrets, "db-password")
	require.ErrorContains(t, err, `vault "staging"`,
		"the vault must be named so an agent working across vaults can tell where it looked")
}

func TestResolver_EmptyListIsNotFoundNotAnError(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[],"total":0}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-password")
	require.ErrorContains(t, err, "no secrets named")

	var apiErr *APIError
	require.NotErrorAs(t, err, &apiErr, "an empty vault is not an API failure")
}
```

Add `"strings"` to the test file's import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestResolver_Ambigu|TestResolver_NotFound|TestResolver_Error|TestResolver_Empty' -v`
Expected: Most pass against Task 1's implementation. `TestResolver_NotFoundCapsSuggestionsAtThree` is the one likeliest to fail, since `nearMisses` sorts before truncating and the assertion counts occurrences of `"db-`. If any fail, fix `resolve.go` — do not weaken the assertions.

- [ ] **Step 3: Write minimal implementation**

If every test passes, no change is needed and this step is a no-op — record that in the commit message.

If `TestResolver_NotFoundCapsSuggestionsAtThree` fails because suggestions are not capped before joining, confirm `nearMisses` truncates *after* sorting:

```go
	sort.Strings(near)
	if len(near) > 3 {
		near = near[:3]
	}
	return near
```

If `TestResolver_EmptyListIsNotFoundNotAnError` fails because an empty array decodes as a nil slice and takes a different branch, note that `len(nil) == 0` already routes to `notFoundError`, so no change should be required.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/resolve.go internal/vaultapi/resolve_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "test(vaultapi): pin resolution failure messages

Ambiguity and not-found are the paths an agent hits when it guesses a name, so
their wording is contract: plans 13-15 surface these messages verbatim. A
duplicate name must never resolve to an arbitrary pick, suggestions are capped
at three to keep errors readable in a model's context, and the vault is always
named so an agent working across vaults can tell where it looked."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

Confirm the whole package is still coherent after four plans:

```bash
go test ./internal/vaultapi/ -race -count=2
```

## Notes for the next plan

Plans 05-08 add the read methods per domain. Each one calls
`Resolver.Resolve` to turn a name into the UUID its route needs, then
`Client.Do` to fetch. Plan 05 sets the shape the other three copy.

Group A is complete at this point: a `Client` that authenticates two ways,
retries safely, returns typed body-free errors, and addresses resources by
name.
