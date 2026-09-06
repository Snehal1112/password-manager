# API Refactor 07 — Generic Soft-Delete Triple

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse nine longhand soft-delete handlers (list, recover, purge × secrets, keys, certificates) into one generic resource description instantiated three times.

**Architecture:** `deletedResource[T]` describes one resource type; three handler factories hang off it. The per-type response projection stays a function field rather than being unified, because the three list responses expose different fields and those shapes are a wire contract.

**Tech Stack:** Go 1.25 generics.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0. Generics available.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Do not modify any `_test.go` file in this plan.**
- **Two different step orders exist in this file and both must be preserved.** Read the warning in Task 1 Step 1 before writing any code.
- `getDeletedKey` is **not** part of this plan. It is left exactly as it is; plan 09 fixes it.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Add the generic resource description and its three factories

**Files:**
- Modify: `api/soft_delete.go` (add above the existing handlers; leave them in place for now)

**Interfaces:**
- Consumes: `resourceID` (plan 03), `svc[T]` (plan 04), `writeJSON[T]` (plan 02), `vaultIDFromRequest` / `userIDFromClaims` / `scopeFromRequest` (`api/context.go`, `api/soft_delete.go`), `ReturnStatusOK` (`api/api.go`).
- Produces:
  - `type deletedOps[T any] struct`
  - `type deletedResource[T any] struct`
  - `func (res deletedResource[T]) listHandler() func(*Context, http.ResponseWriter, *http.Request)`
  - `func (res deletedResource[T]) recoverHandler() func(*Context, http.ResponseWriter, *http.Request)`
  - `func (res deletedResource[T]) purgeHandler() func(*Context, http.ResponseWriter, *http.Request)`

- [ ] **Step 1: Understand the two orderings before writing anything**

This is the one thing that makes this plan non-mechanical. The current handlers do **not** share a step order:

- **The list handlers** (`listDeletedSecrets`, `listDeletedKeys`, `listDeletedCertificates`) call `vaultIDFromRequest` **first**, then `userIDFromClaims`, then build the scope inline with `model.NewVaultScope(vaultID, userID)`.
- **`scopeFromRequest`** does the opposite: `userIDFromClaims` first, then `vaultIDFromRequest`.

So the list handlers **must not** be switched to `scopeFromRequest`. A request carrying both an unparseable vault and an unparseable user claim would get `"vault"` today and `"user_id"` after such a switch. Keep the explicit two-step.

- **The recover and purge handlers** resolve the **service before the scope**: parse id, resolve service, build scope, invoke. That order is also preserved below.

- [ ] **Step 2: Write the description and the list factory**

Add to `api/soft_delete.go`:

```go
// deletedOps binds one domain service's three soft-delete methods.
//
// The three services spell these differently (ListDeletedSecrets, RecoverKey,
// PurgeCertificate, ...), so they are bound as method values here rather than
// being reached through a shared interface the services do not implement.
type deletedOps[T any] struct {
	List    func(context.Context, model.Scope) ([]T, error)
	Recover func(context.Context, uuid.UUID, model.Scope) error
	Purge   func(context.Context, uuid.UUID, model.Scope) error
}

// deletedResource describes one resource type's soft-delete surface.
//
// Item stays a per-type function rather than being unified: the three list
// responses deliberately expose different fields (secrets carry version, keys
// carry type, certificates carry neither), and those shapes are a wire
// contract that must not drift as a side effect of sharing code.
type deletedResource[T any] struct {
	IDParam    string // "key_id", the wire name in a 400.
	ListKey    string // "deleted_keys", the response envelope key.
	RecoverMsg string // "Key recovered successfully".

	ID       func(*ApiParams) string
	Ops      func(*Context) (deletedOps[T], bool)
	Item     func(T) any
	WriteErr func(*Context, error)
}

// listHandler lists the resolved vault's soft-deleted items.
//
// The vault is read before the user claim, matching the handlers this
// replaces. That order decides which 400 a request with both malformed, so it
// is behavior rather than style — see scopeFromRequest, which orders them the
// other way and is therefore deliberately not used here.
func (res deletedResource[T]) listHandler() func(*Context, http.ResponseWriter, *http.Request) {
	return func(c *Context, w http.ResponseWriter, r *http.Request) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}

		userID, ok := userIDFromClaims(c)
		if !ok {
			return
		}

		ops, ok := res.Ops(c)
		if !ok {
			return
		}

		items, err := ops.List(r.Context(), model.NewVaultScope(vaultID, userID))
		if err != nil {
			c.SetInternalError(err)
			return
		}

		// An empty result must encode as [] rather than null, which is what the
		// nil-slice guard in the handlers this replaces was for.
		projected := make([]any, 0, len(items))
		for _, item := range items {
			projected = append(projected, res.Item(item))
		}

		writeJSON(w, map[string]any{res.ListKey: projected, "total": len(projected)})
	}
}
```

- [ ] **Step 3: Write the recover and purge factories, then gate and commit**

```go
// recoverHandler restores one soft-deleted item by id.
//
// The service is resolved before the scope, matching the handlers this
// replaces.
func (res deletedResource[T]) recoverHandler() func(*Context, http.ResponseWriter, *http.Request) {
	return func(c *Context, w http.ResponseWriter, r *http.Request) {
		id, ok := resourceID(c, res.ID(c.Params), res.IDParam)
		if !ok {
			return
		}

		ops, ok := res.Ops(c)
		if !ok {
			return
		}

		scope, ok := scopeFromRequest(c, r)
		if !ok {
			return
		}

		if err := ops.Recover(r.Context(), id, scope); err != nil {
			res.WriteErr(c, err)
			return
		}

		writeJSON(w, map[string]any{"message": res.RecoverMsg, "id": id.String()})
	}
}

// purgeHandler permanently deletes one soft-deleted item by id.
func (res deletedResource[T]) purgeHandler() func(*Context, http.ResponseWriter, *http.Request) {
	return func(c *Context, w http.ResponseWriter, r *http.Request) {
		id, ok := resourceID(c, res.ID(c.Params), res.IDParam)
		if !ok {
			return
		}

		ops, ok := res.Ops(c)
		if !ok {
			return
		}

		scope, ok := scopeFromRequest(c, r)
		if !ok {
			return
		}

		if err := ops.Purge(r.Context(), id, scope); err != nil {
			res.WriteErr(c, err)
			return
		}

		ReturnStatusOK(w)
	}
}
```

Add `"context"` to the file's imports.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/ && ./scripts/verify-api-refactor.sh
```
Expected: `gofmt -l` silent, `PASS ... coverage 86.0%`.

```bash
git add api/soft_delete.go
git commit -S -m "refactor(api): add generic soft-delete resource description"
```

---

### Task 2: Instantiate the three resources

**Files:**
- Modify: `api/soft_delete.go` (replace the nine handlers)

**Interfaces:**
- Consumes: `deletedResource[T]` from Task 1.
- Produces: `listDeletedSecrets`, `recoverSecret`, `purgeSecret`, `listDeletedKeys`, `recoverKey`, `purgeKey`, `listDeletedCertificates`, `recoverCertificate`, `purgeCertificate` — same nine names, now `var`s of function type, so `registerVaultScopedDeletedRoutes` needs no change.

- [ ] **Step 1: Add the three descriptions**

All three services return **value** slices — `[]model.Secret`, `[]model.Key`,
`[]model.Certificate` — not pointer slices. The type arguments below reflect
that; verify with the grep in the next paragraph before writing them.

```go
var deletedSecrets = deletedResource[model.Secret]{
	IDParam:    "secret_id",
	ListKey:    "deleted_secrets",
	RecoverMsg: "Secret recovered successfully",
	ID:         func(p *ApiParams) string { return p.SecretID },
	Ops: func(c *Context) (deletedOps[model.Secret], bool) {
		s, ok := svc(c, container.ServiceContainerInterface.GetSecretService)
		if !ok {
			return deletedOps[model.Secret]{}, false
		}
		return deletedOps[model.Secret]{
			List:    s.ListDeletedSecrets,
			Recover: s.RecoverSecret,
			Purge:   s.PurgeSecret,
		}, true
	},
	Item: func(s model.Secret) any {
		return map[string]any{
			"id":         s.ID.String(),
			"name":       s.Name,
			"version":    s.Version,
			"deleted_at": s.DeletedAt,
			"created_at": s.CreatedAt,
		}
	},
	WriteErr: writeSecretError,
}

var deletedKeys = deletedResource[model.Key]{
	IDParam:    "key_id",
	ListKey:    "deleted_keys",
	RecoverMsg: "Key recovered successfully",
	ID:         func(p *ApiParams) string { return p.KeyID },
	Ops: func(c *Context) (deletedOps[model.Key], bool) {
		s, ok := svc(c, container.ServiceContainerInterface.GetKeyService)
		if !ok {
			return deletedOps[model.Key]{}, false
		}
		return deletedOps[model.Key]{
			List:    s.ListDeletedKeys,
			Recover: s.RecoverKey,
			Purge:   s.PurgeKey,
		}, true
	},
	Item: func(k model.Key) any {
		return deletedKeyItem{
			ID:              k.ID.String(),
			Name:            k.Name,
			Type:            k.Type,
			DeletedAt:       k.DeletedAt,
			PurgeProtection: k.PurgeProtection,
		}
	},
	WriteErr: writeKeyError,
}

var deletedCertificates = deletedResource[model.Certificate]{
	IDParam:    "certificate_id",
	ListKey:    "deleted_certificates",
	RecoverMsg: "Certificate recovered successfully",
	ID:         func(p *ApiParams) string { return p.CertificateID },
	Ops: func(c *Context) (deletedOps[model.Certificate], bool) {
		s, ok := svc(c, container.ServiceContainerInterface.GetCertificateService)
		if !ok {
			return deletedOps[model.Certificate]{}, false
		}
		return deletedOps[model.Certificate]{
			List:    s.ListDeletedCertificates,
			Recover: s.RecoverCertificate,
			Purge:   s.PurgeCertificate,
		}, true
	},
	Item: func(cert model.Certificate) any {
		return deletedCertItem{
			ID:              cert.ID.String(),
			Name:            cert.Name,
			DeletedAt:       cert.DeletedAt,
			PurgeProtection: cert.PurgeProtection,
		}
	},
	WriteErr: writeCertificateError,
}
```

The two item structs were declared inside their handlers; lift them to package level so `Item` can return them. Field tags copied verbatim so the wire shape is unchanged:

```go
// deletedKeyItem is one row of the deleted-keys listing.
type deletedKeyItem struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	DeletedAt       any    `json:"deleted_at"`
	PurgeProtection bool   `json:"purge_protection"`
}

// deletedCertItem is one row of the deleted-certificates listing.
type deletedCertItem struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	DeletedAt       any    `json:"deleted_at"`
	PurgeProtection bool   `json:"purge_protection"`
}
```

**Confirm the element types before writing this.** Run:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
grep -rn 'ListDeletedSecrets(ctx context.Context\|ListDeletedKeys(ctx context.Context\|ListDeletedCertificates(ctx context.Context' internal/services/*/[a-z]*_service.go | grep -v _test
```
Expected, as of `4dc0285`: all three return value slices —
`([]model.Secret, error)`, `([]model.Key, error)`, `([]model.Certificate, error)`.
If any has since become a pointer slice, adjust that resource's type argument
and its `Item` parameter to match.

Note the retry wrappers (`internal/services/retry/retry_*_service.go`) carry the
same signatures, which is what lets the method values bind regardless of whether
the container handed back a wrapped or unwrapped service.

- [ ] **Step 2: Replace the nine handlers**

Delete `listDeletedSecrets`, `recoverSecret`, `purgeSecret`, `listDeletedKeys`, `recoverKey`, `purgeKey`, `listDeletedCertificates`, `recoverCertificate` and `purgeCertificate`, and add:

```go
var (
	listDeletedSecrets = deletedSecrets.listHandler()
	recoverSecret      = deletedSecrets.recoverHandler()
	purgeSecret        = deletedSecrets.purgeHandler()

	listDeletedKeys = deletedKeys.listHandler()
	recoverKey      = deletedKeys.recoverHandler()
	purgeKey        = deletedKeys.purgeHandler()

	listDeletedCertificates = deletedCertificates.listHandler()
	recoverCertificate      = deletedCertificates.recoverHandler()
	purgeCertificate        = deletedCertificates.purgeHandler()
)
```

Leave `getDeletedKey` and `userIDFromClaims` exactly where they are.

- [ ] **Step 3: Gate and commit**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
go test ./api/... -count=1 -run 'Deleted|Recover|Purge|SoftDelete' -v 2>&1 | tail -40
./scripts/verify-api-refactor.sh
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: targeted run passes, gate `PASS ... coverage 86.0%`, `OK: no test files touched`.

The suites that matter most here are `api/soft_delete_test.go`, `api/soft_delete_extended_test.go` and `api/soft_delete_scope_test.go` — the last one pins that an uninitialised scope fails closed.

```bash
git add api/soft_delete.go
git commit -S -m "refactor(api): express the soft-delete triple through one description"
```

---

### Task 3: Confirm the wire shape is byte-identical

**Files:**
- Modify: none (verification only)

**Interfaces:**
- Consumes: the instantiations from Task 2.
- Produces: a recorded confirmation in the commit body.

This task exists because Task 2 changed how the list envelope is built — from a `var deleted []map[string]any` with a nil-guard to a `make([]any, 0, n)` — and that is exactly the kind of change that can flip `[]` to `null` on an empty listing.

- [ ] **Step 1: Prove the empty listing still encodes as `[]`**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go test ./api/... -count=1 -run 'Deleted' -v 2>&1 | grep -i 'empty\|null\|\[\]' | head -20
```

If no existing test covers the empty case, verify by hand with a throwaway program rather than adding a test file (plans 02-08 add no tests):

```bash
cat > /tmp/shape_check.go <<'EOF'
package main

import (
	"encoding/json"
	"os"
)

func main() {
	projected := make([]any, 0, 0)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"deleted_keys": projected, "total": len(projected)})
}
EOF
go run /tmp/shape_check.go
rm /tmp/shape_check.go
```
Expected: `{"deleted_keys":[],"total":0}` — an empty array, not `null`.

- [ ] **Step 2: Confirm the route set is unchanged**

The nine handlers became `var`s; if any name drifted, a route would now register a different function or fail to compile.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go test ./api/... -count=1 -run 'Route|Contract|OpenAPI|Inventory' -v 2>&1 | tail -20
```
Expected: all pass. These are the structural nets — `route_contract_test.go`, `openapi_drift_test.go`, `route_inventory_test.go`.

- [ ] **Step 3: Record the result**

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
wc -l soft_delete.go
```
The file was 414 lines at baseline. Record the new number:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
git commit -S --allow-empty -m "chore(api): confirm soft-delete wire shape unchanged

Empty listings still encode as [] rather than null, and the route
contract, OpenAPI drift and route inventory suites all pass."
```

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-08-error-mappers.md` next.**
