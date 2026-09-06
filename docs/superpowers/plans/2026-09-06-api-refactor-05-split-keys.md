# API Refactor 05 — Split `keys.go`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Break the 1,193-line `api/keys.go` into four focused files. Pure relocation — not one character of any function body changes.

**Architecture:** All four files stay in `package api`, so no symbol becomes qualified and no import path anywhere else in the repo changes. This is separated from plan 06 on purpose: a file split produces a large, noisy diff, and burying the `cryptoOp` rewrite inside it would hide the one diff that most needs careful reading.

**Tech Stack:** Go 1.25.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Do not modify any `_test.go` file in this plan.**
- **No function body may change.** Move text; do not edit it. If a move seems to require an edit, stop — that is a signal the split boundary is wrong.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

Line numbers below are from the pre-refactor tree at `4dc0285` and have shifted after plans 02-04. Locate declarations by name, not by line.

---

### Task 1: Extract the wire types into `keys_types.go`

**Files:**
- Create: `api/keys_types.go`
- Modify: `api/keys.go` (remove the moved declarations)

**Interfaces:**
- Consumes: nothing.
- Produces: no new symbols. The eighteen exported types keep their exact names, fields and json tags:
  `CreateKeyRequest`, `ImportKeyRequest`, `UpdateKeyRequest`, `KeyResponse`, `KeyVersionResponse`, `KeyListResponse`, `WrapKeyRequest`, `WrapKeyResponse`, `UnwrapKeyRequest`, `UnwrapKeyResponse`, `SignKeyRequest`, `SignKeyResponse`, `VerifyKeyRequest`, `VerifyKeyResponse`, `EncryptKeyRequest`, `EncryptKeyResponse`, `DecryptKeyRequest`, `DecryptKeyResponse`.

- [ ] **Step 1: Create the file with the license header and the eighteen types**

`api/keys_types.go` starts with the same copyright block that heads `api/keys.go` (lines 1-21 of the original — copy it verbatim), then:

```go
package api

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)
```

Then move, **verbatim including every doc comment**, the eighteen type declarations from `api/keys.go` — everything from `type CreateKeyRequest struct {` through the closing brace of `type DecryptKeyResponse struct {`.

`encoding/json` is needed for `ImportKeyRequest.JWK json.RawMessage`; `time` for the `*time.Time` fields; `uuid` for `KeyResponse.ID`; `model` for `KeyVersionResponse`'s embedded `model.KeyVersion`.

- [ ] **Step 2: Remove them from `keys.go` and fix its imports**

Delete the same eighteen declarations from `api/keys.go`. Then run `go build ./...` and remove whichever imports it now reports as unused.

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
git add api/keys.go api/keys_types.go
git commit -S -m "refactor(api): move key wire types into keys_types.go"
```

---

### Task 2: Extract the crypto operations into `keys_crypto.go`

**Files:**
- Create: `api/keys_crypto.go`
- Modify: `api/keys.go` (remove the moved handlers)

**Interfaces:**
- Consumes: `writeKeyError` (`api/errors_key.go`), plus the plan 02-04 primitives already adopted inside these handlers.
- Produces: no new symbols. Plan 06 rewrites the six handlers this file now holds: `wrapKey`, `unwrapKey`, `signKey`, `verifyKey`, `encryptKey`, `decryptKey`.

- [ ] **Step 1: Create the file**

`api/keys_crypto.go`:

```go
package api

import (
	"encoding/base64"
	"net/http"

	"rocketvault/internal/container"
	"rocketvault/internal/crypto"
	keyservices "rocketvault/internal/services/keys"
)
```

Then move, verbatim including doc comments, the six handlers `wrapKey`, `unwrapKey`, `signKey`, `verifyKey`, `encryptKey` and `decryptKey` out of `api/keys.go`.

Adjust that import block to whatever `go build` actually requires — the exact set depends on how plans 02-04 rewrote these bodies. Add nothing the compiler does not ask for.

- [ ] **Step 2: Remove them from `keys.go` and fix its imports**

Delete the six handlers from `api/keys.go`, then `go build ./...` and drop the imports it reports as unused.

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
git add api/keys.go api/keys_crypto.go
git commit -S -m "refactor(api): move key crypto handlers into keys_crypto.go"
```

---

### Task 3: Extract versions and rotation into `keys_versions.go`, then confirm the split

**Files:**
- Create: `api/keys_versions.go`
- Modify: `api/keys.go`

**Interfaces:**
- Consumes: `keyJWK` and `buildKeyResponse`, which **stay in `api/keys.go`** — both are shared by the CRUD handlers and by `getKeyVersion`, and `package api` makes them reachable from any file in the package.
- Produces: no new symbols. `rotateKey`, `listKeyVersions`, `getKeyVersion` relocate.

- [ ] **Step 1: Create the file**

`api/keys_versions.go`:

```go
package api

import (
	"net/http"

	"rocketvault/internal/container"
)
```

Move `rotateKey`, `listKeyVersions` and `getKeyVersion` verbatim out of `api/keys.go`. Again, let `go build` dictate the final import set.

- [ ] **Step 2: Remove them from `keys.go` and check the result**

Delete the three handlers from `api/keys.go`, drop unused imports, then measure:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
wc -l keys.go keys_types.go keys_crypto.go keys_versions.go
```

`api/keys.go` should now hold only `keyJWK`, `buildKeyResponse`, `InitKeys`, `registerKeyRoutes`, and the five CRUD handlers `createKey`, `importKey`, `listKeys`, `getKey`, `updateKey`, `deleteKey`. Expect it well under 500 lines. No file should exceed roughly 600.

- [ ] **Step 3: Prove nothing but whitespace and location changed, then commit**

The split is only correct if the set of declarations in the package is unchanged. Verify:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -h "^func \|^type " keys.go keys_types.go keys_crypto.go keys_versions.go | sort > /tmp/after.txt
git show 4dc0285:api/keys.go | grep "^func \|^type " | sort > /tmp/before.txt
diff /tmp/before.txt /tmp/after.txt && echo "IDENTICAL DECLARATION SET"
```
Expected: `IDENTICAL DECLARATION SET`.

If `diff` reports differences, they can only be legitimate where plans 02-04 changed a signature. Review each one; an unexplained difference means a declaration was dropped or renamed during the move.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
./scripts/verify-api-refactor.sh
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: `gofmt -l` silent, `PASS ... coverage 86.0%`, `OK: no test files touched`.

```bash
git add api/keys.go api/keys_versions.go
git commit -S -m "refactor(api): move key version handlers into keys_versions.go"
```

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-06-crypto-op.md` next.**
