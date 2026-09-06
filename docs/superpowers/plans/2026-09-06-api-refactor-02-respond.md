# API Refactor 02 — `respond.go` Response Primitives

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ~78 hand-rolled `Content-Type` + `json.NewEncoder(w).Encode(...)` + `//nolint` triples with two generic helpers.

**Architecture:** Two generic functions in a new `api/respond.go`. `writeJSON[T]` for the 200 path, `writeJSONStatus[T]` for the 34 sites that call `w.WriteHeader(...)` first. Adoption is a mechanical, behavior-identical substitution — byte-for-byte identical output, because the helpers do exactly what the inlined code did in exactly the same order.

**Tech Stack:** Go 1.25 generics, `encoding/json`, `net/http`.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0. Generics available.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Do not modify any `_test.go` file in this plan.** The 21,976-line suite passing untouched is the proof this refactor is behavior-preserving.
- Gate: `./scripts/verify-api-refactor.sh` must pass before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Add the response primitives

**Files:**
- Create: `api/respond.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func writeJSON[T any](w http.ResponseWriter, v T)`
  - `func writeJSONStatus[T any](w http.ResponseWriter, status int, v T)`

  Both are used by every later plan in the chain.

- [ ] **Step 1: Write the file**

Create `api/respond.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
)

// writeJSON writes v as a JSON response body with a 200 status.
//
// It replaces the Content-Type-set-then-encode pair that was repeated at
// roughly seventy-eight sites in this package, and with it the per-site
// //nolint:errcheck,gosec directive. The encode error is deliberately
// discarded, exactly as every call site already discarded it: the status line
// and headers are already on the wire by the time Encode can fail, so there is
// no way left to report the failure to the client.
func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck,gosec
}

// writeJSONStatus writes v as a JSON response body with an explicit status.
//
// The header must be set before WriteHeader, because WriteHeader commits the
// header map; a Content-Type set afterwards is silently dropped. That ordering
// is why this is a separate helper rather than a status argument on writeJSON.
func writeJSONStatus[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck,gosec
}
```

- [ ] **Step 2: Confirm it compiles and the suite is still green**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
./scripts/verify-api-refactor.sh
```
Expected: `PASS: ... coverage 86.0%`.

Note: adding an unused function does not fail `go vet` or the build in Go for package-level functions, so this passing is expected, not surprising.

- [ ] **Step 3: Commit**

```bash
git add api/respond.go
git commit -S -m "refactor(api): add generic JSON response helpers"
```

---

### Task 2: Adopt `writeJSON` at the 200-status sites

**Files:**
- Modify: `api/access_policies.go`, `api/api.go`, `api/audit.go`, `api/backup_item.go`, `api/certificate_policy.go`, `api/certificates.go`, `api/config.go`, `api/context.go`, `api/health.go`, `api/jwks.go`, `api/key_rotation_policy.go`, `api/keys.go`, `api/oauth2.go`, `api/oidc.go`, `api/oidc_cli.go`, `api/role_assignments.go`, `api/secrets.go`, `api/soft_delete.go`, `api/users.go`, `api/vault_provisioning_grants.go`

**Interfaces:**
- Consumes: `writeJSON[T]` from Task 1.
- Produces: no new symbols. Removes ~44 duplicated pairs.

- [ ] **Step 1: Find every convertible site**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -n -B2 'json.NewEncoder(w).Encode' $(ls *.go | grep -v _test)
```

Convert **only** sites matching this exact two-line shape:

```go
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(<expr>) //nolint:errcheck,gosec
```

**Do not convert:**
- Sites with a `w.WriteHeader(...)` between them — those are Task 3.
- Any site that writes raw bytes rather than encoding a value. `api/secrets.go` has export/import paths that stream a file body; leave those alone entirely.

- [ ] **Step 2: Apply the substitution**

The transformation, in both directions, for a concrete pair. Before (`api/soft_delete.go`, `recoverSecret`):

```go
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Secret recovered successfully", "id": secretID.String()}) //nolint:errcheck,gosec
```

After:

```go
	writeJSON(w, map[string]any{"message": "Secret recovered successfully", "id": secretID.String()})
```

And a typed one. Before (`api/keys.go`, `wrapKey`):

```go
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(WrapKeyResponse{ //nolint:errcheck,gosec
		WrappedKey: base64.StdEncoding.EncodeToString(result.WrappedKey),
		Algorithm:  result.Algorithm,
		Version:    result.Version,
	})
```

After:

```go
	writeJSON(w, WrapKeyResponse{
		WrappedKey: base64.StdEncoding.EncodeToString(result.WrappedKey),
		Algorithm:  result.Algorithm,
		Version:    result.Version,
	})
```

Type inference supplies `T` at every site, so never write `writeJSON[Foo](...)` explicitly.

`api/api.go`'s `ReturnStatusOK` becomes:

```go
// ReturnStatusOK writes a standard {"status":"OK"} response.
func ReturnStatusOK(w http.ResponseWriter) {
	writeJSON(w, map[string]string{"status": "OK"})
}
```

- [ ] **Step 3: Drop now-unused imports and gate**

After converting a file, its `encoding/json` import may be unused. `go build` will say so. Remove only imports the compiler reports as unused; do not remove `encoding/json` from files that still decode request bodies.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/ && ./scripts/verify-api-refactor.sh
```
Expected: `gofmt -l` prints nothing, gate prints `PASS ... coverage 86.0%`.

Confirm no test file moved:
```bash
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: `OK: no test files touched`.

Then commit:
```bash
git add api/
git commit -S -m "refactor(api): route 200-status JSON responses through writeJSON"
```

---

### Task 3: Adopt `writeJSONStatus` at the explicit-status sites

**Files:**
- Modify: `api/access_policies.go:131`, `api/api.go:204`, `api/certificate_policy.go:82`, `api/certificates.go:239`, `api/config.go:19`, `api/context.go:163,177,221`, `api/health.go:121,139,148,160,181`, `api/jwks.go:28,36`, `api/key_rotation_policy.go:91`, `api/keys.go:454,534`, `api/oauth2.go:105,167,225`, `api/role_assignments.go:114`, `api/users.go:135,433`, `api/vault_provisioning_grants.go:124`, `api/vault.go:115`, `api/secrets.go:225,316,406,744`

**Interfaces:**
- Consumes: `writeJSONStatus[T]` from Task 1.
- Produces: no new symbols. Removes ~34 duplicated triples.

Line numbers above are from the pre-refactor tree and will have shifted after Task 2. Locate sites by pattern, not by line.

- [ ] **Step 1: Find them**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -n -A3 'w.WriteHeader(' $(ls *.go | grep -v _test)
```

Convert only the three-line shape:

```go
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(<status>)
json.NewEncoder(w).Encode(<expr>) //nolint:errcheck,gosec
```

**Leave alone** the `WriteHeader` calls with no following encode — they are bodiless responses. Specifically these stay untouched: `api/vault.go:318,350`, `api/vault_provisioning_grants.go:152`, `api/vault_webhook.go:156` (all `http.StatusNoContent`).

- [ ] **Step 2: Apply the substitution**

Before (`api/keys.go`, `createKey`):

```go
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(buildKeyResponse(key, jwk)) //nolint:errcheck,gosec
```

After:

```go
	writeJSONStatus(w, http.StatusCreated, buildKeyResponse(key, jwk))
```

Before (`api/context.go`, `writeError`):

```go
func writeError(w http.ResponseWriter, c *Context) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c.Err.StatusCode)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec
		"id":             c.Err.ID,
		"message":        c.Err.Message,
		"detailed_error": c.Err.DetailedError,
		"status_code":    c.Err.StatusCode,
		"request_id":     c.RequestID,
	})
}
```

After:

```go
func writeError(w http.ResponseWriter, c *Context) {
	writeJSONStatus(w, c.Err.StatusCode, map[string]any{
		"id":             c.Err.ID,
		"message":        c.Err.Message,
		"detailed_error": c.Err.DetailedError,
		"status_code":    c.Err.StatusCode,
		"request_id":     c.RequestID,
	})
}
```

`api/api.go`'s `Handle404` becomes:

```go
// Handle404 returns a structured JSON 404 response for unmatched routes.
func Handle404(w http.ResponseWriter, r *http.Request) {
	writeJSONStatus(w, http.StatusNotFound, map[string]any{
		"id":          "api.not_found",
		"message":     "Not found",
		"status_code": http.StatusNotFound,
	})
}
```

- [ ] **Step 3: Verify no raw encode sites remain, then gate and commit**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -rn 'json.NewEncoder(w).Encode' $(ls *.go | grep -v _test)
```
Expected: exactly two hits, both inside `api/respond.go`. Anything else is a site you missed — go back and convert it, or record in the commit body why it must stay inlined.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
./scripts/verify-api-refactor.sh
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: `gofmt -l` silent, gate `PASS ... coverage 86.0%`, and `OK: no test files touched`.

Commit:
```bash
git add api/
git commit -S -m "refactor(api): route explicit-status JSON responses through writeJSONStatus"
```

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-03-request.md` next.**
