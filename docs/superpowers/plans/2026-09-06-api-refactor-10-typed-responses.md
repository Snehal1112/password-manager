# API Refactor 10 — Typed Response Bodies

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the remaining `map[string]any` response bodies with named structs, so they carry a compile-time contract and become visible to the OpenAPI drift test.

**Architecture:** Behavior-changing, and the riskiest plan in the chain — a struct encodes fields in declaration order and honours `omitempty`, whereas a map encodes in sorted key order and always emits every key. Every conversion must be checked against a real response body, not assumed.

**Tech Stack:** Go 1.25, `encoding/json`.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Field order and presence are the wire contract.** `map[string]any` encodes keys in sorted order and never omits one. A struct encodes in declaration order and omits any field tagged `omitempty` that is empty. Declare fields in **alphabetical order** to match the map they replace, and use `omitempty` **only** where the map genuinely never carried the key.
- Convert only response bodies. Leave `map[string]any` used as a request payload, a filter, or an internal value alone.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Inventory and triage the map bodies

**Files:**
- Modify: none (analysis only)

**Interfaces:**
- Consumes: the whole `api/` package post-plan-09.
- Produces: a triage list used by Tasks 2 and 3.

- [ ] **Step 1: Find them**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -n 'map\[string\]any{' $(ls *.go | grep -v _test)
```

At the `4dc0285` baseline there were 21 across `access_policies.go` (2),
`api.go` (1), `audit.go` (1), `config.go` (1), `context.go` (3), `jwks.go` (1),
`oauth2.go` (2), `soft_delete.go` (9), `users.go` (1). Plans 02-09 will have
moved some; the grep is the authority.

- [ ] **Step 2: Triage each into one of three buckets**

For each hit, decide:

- **Convert.** A resource response body with a stable set of keys. Most of them.
- **Keep, and record why.** Two categories genuinely belong as maps:
  - `writeError` and the two inline auth failures in `context.go`, plus
    `Handle404` in `api.go`. These are the error envelope, shared by every
    route, and are already pinned by tests that assert on exact keys. Converting
    them touches every error assertion in the suite for no contract gain.
  - Anything whose key set varies at runtime.
- **Defer.** Anything where the conversion is not obviously safe. Record it for
  the final report rather than guessing.

Write the triage into a scratch file so Tasks 2 and 3 can work from it:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
grep -n 'map\[string\]any{' api/*.go | grep -v _test > /tmp/map-bodies.txt
cat /tmp/map-bodies.txt
```

- [ ] **Step 3: Capture the current wire shape for every "convert" site**

This is what makes the conversion verifiable rather than hopeful. For each site
you plan to convert, find the test that exercises it and record the exact JSON
it asserts:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go test ./api/... -count=1 -v 2>&1 | grep -o '{"[^"]*":[^}]*}' | sort -u | head -50
```

If a site has no test asserting its body, **do not convert it in this plan.**
Move it to the "defer" bucket. A conversion with no oracle is exactly the
change that silently breaks a client.

---

### Task 2: Convert the soft-delete and resource bodies

**Files:**
- Modify: `api/soft_delete.go`, plus whichever of `api/access_policies.go`, `api/audit.go`, `api/users.go`, `api/oauth2.go` survived triage as "convert"

**Interfaces:**
- Consumes: the triage list from Task 1.
- Produces: named response structs, one per converted body. Name them for the
  response, not the handler — `deletedListResponse`, `recoveredResponse`, and so on.

- [ ] **Step 1: Convert the soft-delete envelopes**

`soft_delete.go` holds the largest cluster. The list envelope and the recover
envelope are each built in three places through the generic description from
plan 07, so converting them is two structs, not six.

In `api/soft_delete.go`:

```go
// deletedListResponse is the envelope for a deleted-items listing.
//
// Fields are declared in the alphabetical order the map[string]any it replaces
// encoded them in, so the JSON byte order is unchanged. Neither field is
// omitempty: an empty listing must still carry both keys.
type deletedListResponse struct {
	Items []any `json:"-"`
	Total int   `json:"total"`
}
```

That does not work directly, because the envelope's first key is dynamic
(`deleted_secrets` / `deleted_keys` / `deleted_certificates`). Two honest options:

1. **Keep this one envelope as a map** and record it in the "keep" bucket. The
   key name is data, not schema, so a struct cannot express it without three
   near-identical types.
2. **Declare three types**, one per resource, each with its own concrete key.

Prefer option 2 — three small explicit types beat one dynamic map, and it is what
brings the listing under the OpenAPI drift test:

```go
// deletedSecretsResponse is the GET /deleted/secrets envelope.
type deletedSecretsResponse struct {
	DeletedSecrets []any `json:"deleted_secrets"`
	Total          int   `json:"total"`
}

// deletedKeysResponse is the GET /deleted/keys envelope.
type deletedKeysResponse struct {
	DeletedKeys []any `json:"deleted_keys"`
	Total       int   `json:"total"`
}

// deletedCertificatesResponse is the GET /deleted/certificates envelope.
type deletedCertificatesResponse struct {
	DeletedCertificates []any `json:"deleted_certificates"`
	Total               int   `json:"total"`
}
```

This means `deletedResource[T]` needs an `Envelope func([]any) any` field
replacing its `ListKey string` field, with each of the three resources supplying
its own constructor. Update `listHandler` to call it:

```go
		writeJSON(w, res.Envelope(projected))
```

And in each resource description, e.g. for keys:

```go
	Envelope: func(items []any) any {
		return deletedKeysResponse{DeletedKeys: items, Total: len(items)}
	},
```

Delete the now-unused `ListKey` field.

- [ ] **Step 2: Convert the recover envelope**

The recover body is identical in shape across all three resources, so one type serves:

```go
// recoveredResponse is the envelope returned by a successful restore.
//
// Field order matches the alphabetical key order of the map it replaces.
type recoveredResponse struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}
```

In `recoverHandler`:

```go
		writeJSON(w, recoveredResponse{ID: id.String(), Message: res.RecoverMsg})
```

Note the declaration order: `id` before `message`, because `json.Marshal` of a
`map[string]any` sorts keys and `"id"` sorts before `"message"`. Getting this
backwards changes the response bytes.

- [ ] **Step 3: Verify byte order, gate, commit**

Prove the encoding is unchanged rather than assuming:

```bash
cat > /tmp/order_check.go <<'EOF'
package main

import (
	"encoding/json"
	"os"
)

type recoveredResponse struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(map[string]any{"message": "Key recovered successfully", "id": "abc"})
	enc.Encode(recoveredResponse{ID: "abc", Message: "Key recovered successfully"})
}
EOF
go run /tmp/order_check.go
rm /tmp/order_check.go
```
Expected: **two identical lines.** If they differ, the field order is wrong — fix it before committing.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
go test ./api/... -count=1 -run 'Deleted|Recover|Purge' -v 2>&1 | tail -30
./scripts/verify-api-refactor.sh
```
Expected: all pass.

```bash
git add api/soft_delete.go
git commit -S -m "refactor(api): give the soft-delete responses named types"
```

---

### Task 3: Convert the remaining bodies and record what stayed a map

**Files:**
- Modify: the remaining "convert" sites from the Task 1 triage
- Modify: `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md` (append the outcome)

**Interfaces:**
- Consumes: the triage list.
- Produces: named response types for the remaining sites, and a written record of every site deliberately left as a map.

- [ ] **Step 1: Convert the rest**

Work through the "convert" bucket one file at a time, committing per file, applying
the same two rules each time: alphabetical field order, and `omitempty` only where
the map never carried the key.

After each file:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go test ./api/... -count=1 2>&1 | tail -5
```

If a test fails on a body assertion, the field order or an `omitempty` is wrong.
Fix the struct — do **not** relax the test. The test is describing the contract
the client depends on.

- [ ] **Step 2: Confirm the drift test now sees more**

The point of this plan is contract visibility, so verify it materialised:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go test ./api/... -count=1 -run 'OpenAPI' -v 2>&1 | tail -20
grep -c 'map\[string\]any{' api/*.go | grep -v _test | awk -F: '{s+=$2} END {print "remaining map bodies:", s}'
```
Expected: the OpenAPI suite passes, and the remaining count is materially below
the 21 at baseline.

- [ ] **Step 3: Record what stayed, and why**

Append to the spec at
`docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`:

```markdown
## Outcome: response bodies left as maps

The following response bodies were deliberately not converted to structs, with
the reason for each. An unexplained map here would read as an oversight, so any
future addition to this list should carry its reason too.

- `api/context.go` `writeError`, and the two inline auth failures in
  `ApiSessionRequired` — the shared error envelope. Every error assertion in the
  suite pins its keys already, so a struct adds no contract and would touch the
  whole suite.
- `api/api.go` `Handle404` — same envelope, same reasoning.
- [any further sites, each with its own reason]
```

Replace the bracketed line with what the triage actually left. If nothing else
remained, delete that line rather than leaving a placeholder.

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
./scripts/verify-api-refactor.sh
git add api/ docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md
git commit -S -m "refactor(api): give the remaining response bodies named types"
```

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-11-cleanup-and-close.md` next.**
