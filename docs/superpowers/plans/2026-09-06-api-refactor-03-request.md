# API Refactor 03 — `request.go` Request Primitives

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse 51 UUID-parse blocks, 20 body decodes, and 8 base64 decodes into three helpers that produce byte-identical error responses.

**Architecture:** One new `api/request.go` holding `decodeBody[T]`, `resourceID` and `b64Field`. Each returns a `(value, ok)` pair and sets `c.Err` itself on failure, matching what every current call site does by hand. `resourceID` is deliberately not generic — UUID is the only type any site parses, and a `parseParam[T]` would be speculative.

**Tech Stack:** Go 1.25 generics, `encoding/json`, `encoding/base64`, `github.com/google/uuid`.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0. Generics available.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Do not modify any `_test.go` file in this plan.**
- Error messages must stay verbatim. Tests assert on them; a reworded message is a regression even though it compiles.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Add the request primitives

**Files:**
- Create: `api/request.go`

**Interfaces:**
- Consumes: `Context.SetInvalidParam` (existing, `api/context.go:94`).
- Produces:
  - `func decodeBody[T any](c *Context, r *http.Request) (T, bool)`
  - `func resourceID(c *Context, raw, param string) (uuid.UUID, bool)`
  - `func b64Field(c *Context, value, name string) ([]byte, bool)`

  Plans 04, 06 and 07 all build on these.

- [ ] **Step 1: Write the file**

Create `api/request.go`:

```go
package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// decodeBody decodes the request body into a T.
//
// On failure it sets the same 400 the twenty hand-rolled call sites set, so
// the response is unchanged. The zero T is returned alongside false; callers
// must check ok rather than inspecting the value.
func decodeBody[T any](c *Context, r *http.Request) (T, bool) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		c.SetInvalidParam("request body")
		return v, false
	}
	return v, true
}

// resourceID parses a path parameter as a UUID.
//
// param is the parameter's wire name ("key_id", "secret_id", ...) and is what
// reaches the client in the error, so it must match what the call site used
// before. It is a separate argument rather than being derived from raw because
// raw is the value, not the name.
//
// This is deliberately not generic over the parsed type: every one of the
// fifty-one call sites parses a UUID, and a type-parameterized version would
// add a constraint nothing needs.
func resourceID(c *Context, raw, param string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	if err != nil {
		c.SetInvalidParam(param)
		return uuid.Nil, false
	}
	return id, true
}

// b64Field decodes a standard-encoding base64 request field.
//
// name is the field's wire name, and the message is built to match the eight
// existing sites verbatim: "<name>: must be valid base64".
func b64Field(c *Context, value, name string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		c.SetInvalidParam(name + ": must be valid base64")
		return nil, false
	}
	return decoded, true
}
```

- [ ] **Step 2: Gate**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/ && ./scripts/verify-api-refactor.sh
```
Expected: `gofmt -l` silent, `PASS ... coverage 86.0%`.

- [ ] **Step 3: Commit**

```bash
git add api/request.go
git commit -S -m "refactor(api): add request decode and parse helpers"
```

---

### Task 2: Adopt `resourceID` at the 51 UUID-parse sites

**Files:**
- Modify: `api/access_policies.go` (4), `api/backup_item.go` (3), `api/certificate_policy.go` (3), `api/certificates.go` (3), `api/key_rotation_policy.go` (3), `api/keys.go` (12), `api/oauth2.go` (3), `api/role_assignments.go` (2), `api/secrets.go` (6), `api/soft_delete.go` (7), `api/users.go` (3), `api/vault_provisioning_grants.go` (2)

**Interfaces:**
- Consumes: `resourceID` from Task 1.
- Produces: no new symbols. Removes 51 five-line blocks.

- [ ] **Step 1: Find them**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -n -A4 'uuid.Parse(c.Params' $(ls *.go | grep -v _test)
```

- [ ] **Step 2: Apply the substitution**

Before (`api/soft_delete.go`, `recoverKey`):

```go
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}
```

After:

```go
	keyID, ok := resourceID(c, c.Params.KeyID, "key_id")
	if !ok {
		return
	}
```

Two things to watch:

1. **The parameter-name string must be copied from the site you are replacing**, not guessed from the field name. Most are the obvious snake_case form, but verify each one — a changed string is a changed 400 body and tests assert on it.
2. **Shadowing.** Some handlers reuse `err` further down and some already have an `ok` in scope from `scopeFromRequest`. Where `ok` is taken, name the second one for its subject, e.g.:

```go
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}
```

Do not silently reuse an outer `ok` with `=` instead of `:=`; that compiles and reads fine but discards the earlier value.

- [ ] **Step 3: Gate and commit**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -rn 'uuid.Parse(c.Params' $(ls *.go | grep -v _test)
```
Expected: no output.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
./scripts/verify-api-refactor.sh
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: `gofmt -l` silent, `PASS ... coverage 86.0%`, `OK: no test files touched`.

```bash
git add api/
git commit -S -m "refactor(api): parse path UUIDs through resourceID"
```

---

### Task 3: Adopt `decodeBody` and `b64Field`

**Files:**
- Modify: `api/access_policies.go` (2 decodes), `api/audit.go` (1), `api/backup_item.go` (3), `api/certificates.go` (2), `api/keys.go` (9 decodes, 8 base64), `api/oauth2.go` (1), `api/oidc_cli.go` (1), `api/vault_provisioning_grants.go` (1)

**Interfaces:**
- Consumes: `decodeBody[T]` and `b64Field` from Task 1.
- Produces: no new symbols. Removes 20 decode blocks and 8 base64 blocks.

- [ ] **Step 1: Convert the body decodes**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -n -B2 -A4 'json.NewDecoder(r.Body).Decode' $(ls *.go | grep -v _test)
```

Before (`api/keys.go`, `wrapKey`):

```go
	var req WrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
```

After:

```go
	req, ok := decodeBody[WrapKeyRequest](c, r)
	if !ok {
		return
	}
```

The explicit type argument **is** required here — unlike `writeJSON`, there is no value to infer `T` from. Apply the same shadowing care as Task 2 where `ok` is already in scope.

Two sites need attention rather than a blind substitution:
- Any site whose current error message is **not** `"request body"`. Check each before converting; if one differs, leave it inlined and note it in the commit body rather than changing the message.
- Any site that reads `r.Body` more than once, or reads it as raw bytes for an import/upload path. `api/backup_item.go` and `api/oidc_cli.go` should each be read in full before converting.

- [ ] **Step 2: Convert the base64 decodes**

Run:
```bash
grep -n -B1 -A4 'base64.StdEncoding.DecodeString' $(ls *.go | grep -v _test)
```

Before (`api/keys.go`, `signKey`):

```go
	data, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		c.SetInvalidParam("value: must be valid base64")
		return
	}
```

After:

```go
	data, ok := b64Field(c, req.Value, "value")
	if !ok {
		return
	}
```

`decryptKey`'s nonce is conditional and keeps its guard:

```go
	var nonce []byte
	if req.Nonce != "" {
		var ok bool
		nonce, ok = b64Field(c, req.Nonce, "nonce")
		if !ok {
			return
		}
	}
```

Leave `base64.StdEncoding.EncodeToString` calls alone — this task only touches decoding.

- [ ] **Step 3: Gate and commit**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
./scripts/verify-api-refactor.sh
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: `gofmt -l` silent, `PASS ... coverage 86.0%`, `OK: no test files touched`.

```bash
git add api/
git commit -S -m "refactor(api): decode request bodies and base64 fields through helpers"
```

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-04-service-accessor.md` next.**
