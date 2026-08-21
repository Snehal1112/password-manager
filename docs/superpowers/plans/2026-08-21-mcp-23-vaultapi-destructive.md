# vaultapi Destructive and Recovery Methods Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `DeleteItem`, `PurgeItem`, `PurgeVault`, `RecoverDeleted` and `DeleteRoleAssignment` — every operation that removes something, plus the one that undoes a removal.

**Architecture:** Plan 18's shape, with one genuinely new piece: a **deleted-item resolver**. A soft-deleted item is absent from the live listing, so `Resolver.Resolve` cannot find it — purge and recover must resolve names against the deleted list instead.

**Tech Stack:** Go 1.25, `github.com/google/uuid`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Destructive tier".

**Plan-of-plans:** This is plan 23 of 31, opening Group G. Requires plans 01, 04, 08 and 19 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Vault-scoped routes only.**
- **Mutations are never retried.** This matters more here than anywhere else: a retried purge that already succeeded would return a confusing 404 for an operation that did work.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified route contracts

| Method | Route | Response |
|---|---|---|
| Soft-delete item | `DELETE /api/v1/vaults/{v}/{kind}/{id}` | `{"status":"OK"}` (`ReturnStatusOK`, `api/api.go:192`) |
| Purge item | `DELETE /api/v1/vaults/{v}/deleted/{kind}/{id}/purge` | `{"status":"OK"}` |
| Recover item | `POST /api/v1/vaults/{v}/deleted/{kind}/{id}/restore` | `{"message":"…","id":"…"}` (`api/soft_delete.go:84`) |
| Purge vault | `DELETE /api/v1/vaults/{v}/purge` | `{"status":"OK"}` |
| Revoke role | `DELETE /api/v1/vaults/{v}/role-assignments/{assignment_id}` | `{"status":"OK"}` |

Every one returns HTTP 200 with a small JSON body, not 204. `Client.Do` with a nil `out` handles all of them.

## The deleted-item resolver

`Resolver.Resolve` lists *live* items. A soft-deleted secret is gone from that listing by definition, so resolving `"old-password"` for a purge would return `ErrResourceNotFound` even though the item exists and is purgeable.

Purge and recover therefore resolve against `ListDeleted`. This is not a variation on the existing resolver — it queries a different route with a different wrapper key — so it gets its own function rather than a flag on `Resolve`, which would make the existing one's contract ambiguous.

Both resolvers keep the same rules: a UUID passes through untouched, an ambiguous name errors with its candidates, and a miss returns `ErrResourceNotFound`.

## Purge protection is the server's business

A vault or item with purge protection enabled cannot be purged before its retention period elapses. This client does not check that: whether protection applies is server state, and pre-empting it would mean duplicating a rule that can change. A protected purge returns a server error, which surfaces with its own message.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/resolve_deleted.go` (new) | `ResolveDeleted` |
| `internal/vaultapi/destructive.go` (new) | `DeleteItem`, `PurgeItem`, `PurgeVault`, `DeleteRoleAssignment` |
| `internal/vaultapi/recover.go` (new) | `RecoverDeleted` |
| `internal/vaultapi/*_test.go` (new) | One per file |

---

### Task 1: `ResolveDeleted`

**Files:**
- Create: `internal/vaultapi/resolve_deleted.go`
- Create: `internal/vaultapi/resolve_deleted_test.go`

**Interfaces:**
- Consumes: `Client.ListDeleted` (plan 08), `Kind`, `ErrResourceNotFound` (plans 04, 19).
- Produces — Tasks 2 and 3 both use it:
  - `func (c *Client) ResolveDeleted(ctx context.Context, vault string, kind Kind, name string) (uuid.UUID, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/resolve_deleted_test.go`:

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

// deletedListServer serves a deleted-items listing and counts requests.
func deletedListServer(t *testing.T, path, body string) (*httptest.Server, *int32) {
	t.Helper()

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestResolveDeleted_FindsASoftDeletedItem(t *testing.T) {
	srv, _ := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets",
		`{"deleted_secrets":[{"id":"`+dbSecretID+`","name":"old-password"}],"total":1}`)

	got, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "old-password")
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got)
}

func TestResolveDeleted_UsesTheDeletedRouteNotTheLiveOne(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"old"}],"total":1}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "old")
	require.NoError(t, err)
	require.Equal(t, []string{"/api/v1/vaults/prod/deleted/secrets"}, paths,
		"a soft-deleted item is absent from the live listing, so that route cannot find it")
}

func TestResolveDeleted_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind Kind
		path string
		body string
	}{
		{KindSecrets, "/api/v1/vaults/prod/deleted/secrets",
			`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`},
		{KindKeys, "/api/v1/vaults/prod/deleted/keys",
			`{"deleted_keys":[{"id":"` + rsaKeyID + `","name":"gone"}],"total":1}`},
		{KindCertificates, "/api/v1/vaults/prod/deleted/certificates",
			`{"deleted_certificates":[{"id":"` + tlsCertID + `","name":"gone"}],"total":1}`},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			srv, _ := deletedListServer(t, tc.path, tc.body)
			got, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", tc.kind, "gone")
			require.NoError(t, err)
			require.NotEqual(t, uuid.Nil, got)
		})
	}
}

func TestResolveDeleted_AcceptsAUUIDWithoutListing(t *testing.T) {
	srv, calls := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets", `{"deleted_secrets":[],"total":0}`)

	got, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, dbSecretID)
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse(dbSecretID), got)
	require.EqualValues(t, 0, atomic.LoadInt32(calls))
}

func TestResolveDeleted_MissIsErrResourceNotFound(t *testing.T) {
	srv, _ := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets", `{"deleted_secrets":[],"total":0}`)

	_, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "nope")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Contains(t, err.Error(), "deleted",
		"the message must say it searched the deleted items, not the live ones")
}

func TestResolveDeleted_AmbiguousNamesEveryCandidate(t *testing.T) {
	srv, _ := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets",
		`{"deleted_secrets":[{"id":"`+dbSecretID+`","name":"dup"},
		  {"id":"`+apiSecretID+`","name":"dup"}],"total":2}`)

	_, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "dup")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrResourceNotFound)
	require.Contains(t, err.Error(), dbSecretID)
	require.Contains(t, err.Error(), apiSecretID,
		"purging the wrong item is irreversible, so ambiguity must never be guessed")
}

func TestResolveDeleted_RequiresVaultAndName(t *testing.T) {
	srv, _ := deletedListServer(t, "/api/v1/vaults/prod/deleted/secrets", `{"deleted_secrets":[],"total":0}`)
	c := newClientForTest(t, srv)

	_, err := c.ResolveDeleted(context.Background(), "", KindSecrets, "x")
	require.ErrorContains(t, err, "vault is required")

	_, err = c.ResolveDeleted(context.Background(), "prod", KindSecrets, "")
	require.ErrorContains(t, err, "name is required")
}

func TestResolveDeleted_ForbiddenIsNotAMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).ResolveDeleted(context.Background(), "prod", KindSecrets, "x")
	require.NotErrorIs(t, err, ErrResourceNotFound)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindForbidden, apiErr.Kind)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestResolveDeleted_ -v`
Expected: FAIL — `c.ResolveDeleted undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/resolve_deleted.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestResolveDeleted_ -v`
Expected: PASS — all eight tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/resolve_deleted.go internal/vaultapi/resolve_deleted_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add ResolveDeleted for soft-deleted items

Resolver.Resolve lists live items, and a soft-deleted item is absent from that
listing by definition -- resolving a name for a purge through it would report
'not found' for an item that exists and is purgeable.

This queries a different route with a different wrapper key, so it is a
separate function rather than a flag on Resolve, which would leave that
function's contract ambiguous. It lists without a limit: a resolution must see
every candidate or it could miss a duplicate, and purging the wrong item
cannot be undone."
```

---

### Task 2: `DeleteItem` and `RecoverDeleted`

**Files:**
- Create: `internal/vaultapi/destructive.go`
- Create: `internal/vaultapi/recover.go`
- Create: `internal/vaultapi/destructive_test.go`

**Interfaces:**
- Consumes: `Client.Do`, `Resolver.Resolve`, `ResolveDeleted`.
- Produces — plan 24's `recover_deleted` and plan 25's `delete_item` call these:
  - `func (c *Client) DeleteItem(ctx context.Context, vault string, kind Kind, name string) error`
  - `func (c *Client) RecoverDeleted(ctx context.Context, vault string, kind Kind, name string) error`

**Which resolver each uses is the point of this task.** `DeleteItem` acts on a live item, so it uses `Resolve`. `RecoverDeleted` acts on a deleted one, so it uses `ResolveDeleted`. Getting this backwards produces a "not found" error for an operation that would have worked, which is a confusing failure to debug from the outside.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/destructive_test.go`:

```go
package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// mutationProbe records a destructive call and the paths leading to it.
type mutationProbe struct {
	paths   []string
	method  string
	target  string
	calls   int
}

// destructiveServer serves listings and records the non-GET call.
func destructiveServer(t *testing.T, routes map[string]string, status int) (*httptest.Server, *mutationProbe) {
	t.Helper()

	probe := &mutationProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probe.paths = append(probe.paths, r.URL.Path)

		if r.Method == http.MethodGet {
			body, ok := routes[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}

		probe.calls++
		probe.method, probe.target = r.Method, r.URL.Path

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"OK"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, probe
}

func TestDeleteItem_ResolvesAgainstTheLiveListing(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", KindSecrets, "db-password")
	require.NoError(t, err)

	require.Equal(t, http.MethodDelete, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/secrets/"+dbSecretID, probe.target)
	require.Contains(t, probe.paths, "/api/v1/vaults/prod/secrets",
		"a live item is resolved through the live listing")
}

func TestDeleteItem_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind     Kind
		listPath string
		listBody string
		id       string
	}{
		{KindSecrets, "/api/v1/vaults/prod/secrets",
			`{"secrets":[{"id":"` + dbSecretID + `","name":"doomed"}],"total":1}`, dbSecretID},
		{KindKeys, "/api/v1/vaults/prod/keys",
			`{"keys":[{"id":"` + rsaKeyID + `","name":"doomed"}]}`, rsaKeyID},
		{KindCertificates, "/api/v1/vaults/prod/certificates",
			`{"certificates":[{"id":"` + tlsCertID + `","name":"doomed"}]}`, tlsCertID},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			srv, probe := destructiveServer(t, map[string]string{tc.listPath: tc.listBody}, http.StatusOK)

			err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", tc.kind, "doomed")
			require.NoError(t, err)
			require.Equal(t, "/api/v1/vaults/prod/"+string(tc.kind)+"/"+tc.id, probe.target)
		})
	}
}

func TestDeleteItem_UnknownNameMakesNoCall(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[],"total":0}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", KindSecrets, "nope")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Zero(t, probe.calls)
}

func TestDeleteItem_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
	}, http.StatusInternalServerError)

	err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", KindSecrets, "db-password")
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestDeleteItem_RejectsAnUnknownKind(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{}, http.StatusOK)

	err := newClientForTest(t, srv).DeleteItem(context.Background(), "prod", Kind("vaults"), "x")
	require.ErrorContains(t, err, "unsupported")
	require.Zero(t, probe.calls)
}

func TestRecoverDeleted_ResolvesAgainstTheDeletedListing(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"old-password"}],"total":1}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).RecoverDeleted(context.Background(), "prod", KindSecrets, "old-password")
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/deleted/secrets/"+dbSecretID+"/restore", probe.target)
	require.Contains(t, probe.paths, "/api/v1/vaults/prod/deleted/secrets",
		"a deleted item is invisible to the live listing, so recovery must resolve against the deleted one")
	require.NotContains(t, probe.paths, "/api/v1/vaults/prod/secrets")
}

func TestRecoverDeleted_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind Kind
		path string
		body string
		id   string
	}{
		{KindSecrets, "/api/v1/vaults/prod/deleted/secrets",
			`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`, dbSecretID},
		{KindKeys, "/api/v1/vaults/prod/deleted/keys",
			`{"deleted_keys":[{"id":"` + rsaKeyID + `","name":"gone"}],"total":1}`, rsaKeyID},
		{KindCertificates, "/api/v1/vaults/prod/deleted/certificates",
			`{"deleted_certificates":[{"id":"` + tlsCertID + `","name":"gone"}],"total":1}`, tlsCertID},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			srv, probe := destructiveServer(t, map[string]string{tc.path: tc.body}, http.StatusOK)

			err := newClientForTest(t, srv).RecoverDeleted(context.Background(), "prod", tc.kind, "gone")
			require.NoError(t, err)
			require.Equal(t,
				"/api/v1/vaults/prod/deleted/"+string(tc.kind)+"/"+tc.id+"/restore", probe.target)
		})
	}
}

func TestRecoverDeleted_UnknownNamePointsAtListDeleted(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[],"total":0}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).RecoverDeleted(context.Background(), "prod", KindSecrets, "nope")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Contains(t, err.Error(), "list_deleted")
	require.Zero(t, probe.calls)
}

func TestRecoverDeleted_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`,
	}, http.StatusInternalServerError)

	err := newClientForTest(t, srv).RecoverDeleted(context.Background(), "prod", KindSecrets, "gone")
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestDeleteItem_|TestRecoverDeleted_' -v`
Expected: FAIL — `c.DeleteItem undefined`, `c.RecoverDeleted undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/destructive.go`:

```go
package vaultapi

import (
	"context"
	"fmt"
	"net/http"
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
```

Create `internal/vaultapi/recover.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run 'TestDeleteItem_|TestRecoverDeleted_' -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/destructive.go internal/vaultapi/recover.go internal/vaultapi/destructive_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add DeleteItem and RecoverDeleted

Each uses the resolver that matches its subject: DeleteItem acts on a live
item and resolves through the live listing, RecoverDeleted acts on a deleted
one and resolves through the deleted listing. Getting that backwards produces
'not found' for an operation that would have worked, which is a confusing
failure to diagnose from outside.

A recovery miss points the caller at list_deleted, which is where the
recoverable names actually are."
```

---

### Task 3: `PurgeItem`, `PurgeVault` and `DeleteRoleAssignment`

**Files:**
- Modify: `internal/vaultapi/destructive.go`
- Modify: `internal/vaultapi/destructive_test.go` (append)

**Interfaces:**
- Consumes: `Client.Do`, `ResolveDeleted`.
- Produces — plan 25's tools call these:
  - `func (c *Client) PurgeItem(ctx context.Context, vault string, kind Kind, name string) error`
  - `func (c *Client) PurgeVault(ctx context.Context, vault string) error`
  - `func (c *Client) DeleteRoleAssignment(ctx context.Context, vault, assignmentID string) error`

**Three notes:**

- **`PurgeItem` resolves through the deleted listing**, like recovery — an item must already be soft-deleted before it can be purged.
- **`PurgeVault` takes a name directly.** A vault's name is its identifier, so no resolution applies, exactly as in plan 07.
- **`DeleteRoleAssignment` takes an assignment ID, not a principal.** The route is keyed by assignment, and one principal can hold several roles in a vault. Accepting a principal name would require picking among them — a guess this client must not make. Callers get the ID from `list_role_assignments` or from `grant_vault_role`'s result.

**Purge protection stays the server's call.** A protected item or vault fails server-side with its own message; this client does not attempt to predict it.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/destructive_test.go`:

```go
func TestPurgeItem_ResolvesAgainstTheDeletedListing(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"old-password"}],"total":1}`,
	}, http.StatusOK)

	err := newClientForTest(t, srv).PurgeItem(context.Background(), "prod", KindSecrets, "old-password")
	require.NoError(t, err)

	require.Equal(t, http.MethodDelete, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/deleted/secrets/"+dbSecretID+"/purge", probe.target)
	require.NotContains(t, probe.paths, "/api/v1/vaults/prod/secrets",
		"only an already-deleted item can be purged")
}

func TestPurgeItem_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind Kind
		path string
		body string
		id   string
	}{
		{KindSecrets, "/api/v1/vaults/prod/deleted/secrets",
			`{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`, dbSecretID},
		{KindKeys, "/api/v1/vaults/prod/deleted/keys",
			`{"deleted_keys":[{"id":"` + rsaKeyID + `","name":"gone"}],"total":1}`, rsaKeyID},
		{KindCertificates, "/api/v1/vaults/prod/deleted/certificates",
			`{"deleted_certificates":[{"id":"` + tlsCertID + `","name":"gone"}],"total":1}`, tlsCertID},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			srv, probe := destructiveServer(t, map[string]string{tc.path: tc.body}, http.StatusOK)

			err := newClientForTest(t, srv).PurgeItem(context.Background(), "prod", tc.kind, "gone")
			require.NoError(t, err)
			require.Equal(t,
				"/api/v1/vaults/prod/deleted/"+string(tc.kind)+"/"+tc.id+"/purge", probe.target)
		})
	}
}

func TestPurgeItem_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`,
	}, http.StatusInternalServerError)

	err := newClientForTest(t, srv).PurgeItem(context.Background(), "prod", KindSecrets, "gone")
	require.Error(t, err)
	require.Equal(t, 1, probe.calls,
		"a retried purge that already succeeded would report 404 for an operation that worked")
}

func TestPurgeItem_ProtectionRefusalIsSurfacedNotPredicted(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{
		"/api/v1/vaults/prod/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretID + `","name":"gone"}],"total":1}`,
	}, http.StatusForbidden)

	err := newClientForTest(t, srv).PurgeItem(context.Background(), "prod", KindSecrets, "gone")
	require.Error(t, err)
	require.Equal(t, 1, probe.calls,
		"whether purge protection applies is server state; the client must not pre-empt it")
}

func TestPurgeVault_TakesTheNameDirectly(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{}, http.StatusOK)

	err := newClientForTest(t, srv).PurgeVault(context.Background(), "prod")
	require.NoError(t, err)

	require.Equal(t, http.MethodDelete, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/purge", probe.target)
	require.Equal(t, 1, len(probe.paths), "a vault's name is its identifier; no resolution applies")
}

func TestPurgeVault_RequiresAName(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{}, http.StatusOK)

	err := newClientForTest(t, srv).PurgeVault(context.Background(), "")
	require.ErrorContains(t, err, "vault is required")
	require.Zero(t, probe.calls)
}

func TestPurgeVault_ForbiddenNamesThePurgeOperatorRole(t *testing.T) {
	srv, _ := destructiveServer(t, map[string]string{}, http.StatusForbidden)

	err := newClientForTest(t, srv).PurgeVault(context.Background(), "prod")

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindForbidden, apiErr.Kind)
	require.Contains(t, apiErr.Hint, "purge",
		"the hint should reflect that this is a purge, which needs its own grant")
}

func TestDeleteRoleAssignment_TargetsTheAssignmentID(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{}, http.StatusOK)

	err := newClientForTest(t, srv).DeleteRoleAssignment(context.Background(), "prod", assignmentID)
	require.NoError(t, err)

	require.Equal(t, http.MethodDelete, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/role-assignments/"+assignmentID, probe.target)
}

func TestDeleteRoleAssignment_RejectsANonUUID(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{}, http.StatusOK)

	// One principal can hold several roles in a vault, so a principal name
	// would be ambiguous. The route is keyed by assignment.
	err := newClientForTest(t, srv).DeleteRoleAssignment(context.Background(), "prod", "alice")
	require.ErrorContains(t, err, "assignment id")
	require.Zero(t, probe.calls)
}

func TestDeleteRoleAssignment_RequiresVaultAndID(t *testing.T) {
	srv, probe := destructiveServer(t, map[string]string{}, http.StatusOK)
	c := newClientForTest(t, srv)

	err := c.DeleteRoleAssignment(context.Background(), "", assignmentID)
	require.ErrorContains(t, err, "vault is required")

	err = c.DeleteRoleAssignment(context.Background(), "prod", "")
	require.ErrorContains(t, err, "assignment id")

	require.Zero(t, probe.calls)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestPurgeItem_|TestPurgeVault_|TestDeleteRoleAssignment_' -v`
Expected: FAIL — the three methods are undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/vaultapi/destructive.go`, adding `"github.com/google/uuid"` to the imports:

```go
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
```

`TestPurgeVault_ForbiddenNamesThePurgeOperatorRole` depends on plan 01's `resourceAndVerb`, which maps a `DELETE` ending in `/purge` to the `purge` verb. If the assertion fails, check that mapping rather than the test.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/destructive.go internal/vaultapi/destructive_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add PurgeItem, PurgeVault and DeleteRoleAssignment

PurgeItem resolves through the deleted listing, since only an already-deleted
item can be purged. Purge protection is left to the server: whether it applies
is server state, and pre-empting it would duplicate a rule that can change.

DeleteRoleAssignment takes an assignment id rather than a principal. The route
is keyed by assignment and one principal can hold several roles in a vault, so
accepting a name would mean choosing among them -- a guess this client must
not make. The error says exactly that, and where to get the id."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

`vaultapi` is feature-complete except for crypto after this plan. Confirm the
resolver split, which is the thing most likely to be got wrong:

```bash
go test ./internal/vaultapi/ -run 'ResolvesAgainstTheLiveListing|ResolvesAgainstTheDeletedListing' -v
```

Confirm every mutation across plans 18-23 is single-attempt:

```bash
go test ./internal/vaultapi/ -run 'IsAttemptedExactlyOnce' -v
```

Expected: nine tests now.

## Notes for the next plan

Plan 24 adds the confirmation mechanism and the `recover_deleted` tool. It must
come before plan 25, which depends on the confirmation helper.

**One thing plan 25 must not get wrong:** `revoke_vault_role` takes an
assignment id. Its description has to say so and point at
`list_role_assignments`, or a model asked to "revoke alice's access" will pass
`"alice"` and get an error it can only resolve by guessing what to do next.
