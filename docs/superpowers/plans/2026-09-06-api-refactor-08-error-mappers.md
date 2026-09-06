# API Refactor 08 — Shared Error-Mapper Cases

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the cases the three `writeXError` mappers share into one place, so they stay in lockstep by construction rather than by convention.

**Architecture:** A small ordered slice of `(matcher, responder)` pairs, consulted after the domain-specific cases and before the 500 fallback. Deliberately modest — the three mappers genuinely differ and unifying them further would obscure real distinctions. This is the last of the behavior-preserving plans.

**Tech Stack:** Go 1.25, `errors.Is`.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Do not modify any `_test.go` file in this plan.** This is the final plan under that rule; plans 09-11 change behavior and may touch tests.
- **Case order is behavior.** `errors.Is` chains are evaluated top to bottom and a wrapped error can match more than one case. Moving a case past another can change the status code.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Establish which cases are genuinely shared

**Files:**
- Modify: none (analysis only)

**Interfaces:**
- Consumes: `api/errors_secret.go`, `api/errors_key.go`, `api/errors_certificate.go`.
- Produces: a decision, recorded in the next task's commit, about which cases move.

- [ ] **Step 1: Read all three mappers side by side**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
cat errors_secret.go errors_key.go errors_certificate.go
```

- [ ] **Step 2: Confirm the shared set**

From the baseline tree, exactly one case is byte-identical across all three:

```go
case errors.Is(err, model.ErrGlobalPurgeProtectionEnabled):
    c.SetPermissionError(err.Error())
```

A second case is *structurally* parallel but **not** identical — each names its own sentinel and its own noun:

```go
// errors_secret.go
case errors.Is(err, model.ErrSecretPurgeProtected):
    c.SetPermissionError("secret has purge protection enabled (directly or via its vault)")
// errors_key.go
case errors.Is(err, model.ErrKeyPurgeProtected):
    c.SetPermissionError("key has purge protection enabled (directly or via its vault)")
// errors_certificate.go
case errors.Is(err, model.ErrCertPurgeProtected):
    c.SetPermissionError("certificate has purge protection enabled (directly or via its vault)")
```

Verify this is still true after plans 02-07 rather than trusting the description:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -n 'ErrGlobalPurgeProtectionEnabled\|PurgeProtected' errors_secret.go errors_key.go errors_certificate.go
```

- [ ] **Step 3: Decide the scope of the change**

Move **only** the `ErrGlobalPurgeProtectionEnabled` case into shared code, plus a parameterized helper for the per-domain purge-protection message.

Do **not** attempt to unify the lifecycle-denied or not-found cases. They look parallel but each names a different sentinel from a different package, and folding them into a table would trade three readable switches for one indirection that a reader has to unpick to answer "what status does a missing key return".

If the analysis in Step 2 contradicts what is written here, follow the code and note the divergence in the Task 2 commit body.

---

### Task 2: Extract the shared case

**Files:**
- Create: `api/errors_common.go`
- Modify: `api/errors_secret.go`, `api/errors_key.go`, `api/errors_certificate.go`

**Interfaces:**
- Consumes: `Context.SetPermissionError`.
- Produces:
  - `func writeCommonResourceError(c *Context, err error) bool`
  - `func purgeProtectedMessage(noun string) string`

- [ ] **Step 1: Write the shared file**

Create `api/errors_common.go`:

```go
package api

import (
	"errors"

	"rocketvault/model"
)

// writeCommonResourceError handles the error cases every resource mapper
// shares, and reports whether it handled one.
//
// It is called from each writeXError after that mapper's own domain cases and
// before its 500 fallback. Order matters: an errors.Is chain is evaluated top
// to bottom and a wrapped error can satisfy more than one case, so moving this
// call would change which status some errors get.
//
// Only genuinely identical cases belong here. The per-domain not-found and
// lifecycle cases look parallel but each names a different sentinel, and
// folding them in would replace three readable switches with an indirection.
func writeCommonResourceError(c *Context, err error) bool {
	switch {
	case errors.Is(err, model.ErrGlobalPurgeProtectionEnabled):
		// The message is the sentinel's own text, which names the instance-wide
		// switch rather than the item, so an operator can tell "this item is
		// protected" from "purging is switched off globally".
		c.SetPermissionError(err.Error())
		return true
	default:
		return false
	}
}

// purgeProtectedMessage builds the per-item purge-protection message.
//
// The three mappers each hand-wrote this sentence with their own noun. One
// builder keeps them from drifting apart a word at a time.
func purgeProtectedMessage(noun string) string {
	return noun + " has purge protection enabled (directly or via its vault)"
}
```

- [ ] **Step 2: Rewire the three mappers**

In each of `errors_secret.go`, `errors_key.go`, `errors_certificate.go`:

1. Replace the per-domain purge-protection message with the builder. For `errors_key.go`:

```go
	case errors.Is(err, model.ErrKeyPurgeProtected):
		c.SetPermissionError(purgeProtectedMessage("key"))
```

Use `"secret"` and `"certificate"` for the other two. The resulting strings must be identical to what was there before — verify by eye against Task 1 Step 2.

2. Delete the `ErrGlobalPurgeProtectionEnabled` case from each switch and change the `default` to consult the shared mapper. For `errors_key.go`:

```go
	default:
		if writeCommonResourceError(c, err) {
			return
		}
		c.SetInternalError(err)
	}
```

Keep every other case exactly where it is, in the same order.

- [ ] **Step 3: Gate and commit**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/
go test ./api/... -count=1 -run 'Purge|Protect|Error' -v 2>&1 | tail -30
./scripts/verify-api-refactor.sh
git status --porcelain api/ | grep '_test.go' && echo "STOP: a test changed" || echo "OK: no test files touched"
```
Expected: targeted run passes, gate `PASS ... coverage 86.0%`, `OK: no test files touched`.

```bash
git add api/errors_common.go api/errors_secret.go api/errors_key.go api/errors_certificate.go
git commit -S -m "refactor(api): share the purge-protection error cases across mappers"
```

---

### Task 3: Close out the behavior-preserving phase

**Files:**
- Modify: none (measurement and reporting only)

**Interfaces:**
- Consumes: everything from plans 02-08.
- Produces: a recorded summary the final plan reuses.

- [ ] **Step 1: Confirm zero test files were touched across the whole phase**

This is the single most important check in the chain. Run:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
git diff --name-only 4dc0285..HEAD -- 'api/*_test.go'
```
Expected: **no output.**

Any file listed means a behavior change slipped into a plan that promised none. Do not proceed to plan 09. Report the file and stop.

- [ ] **Step 2: Measure the reduction**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
echo "current:  $(wc -l $(ls *.go | grep -v _test) | tail -1)"
echo "baseline: 7214 (at 4dc0285)"
echo
echo "files over 600 lines:"
wc -l $(ls *.go | grep -v _test) | sort -rn | awk '$1 > 600 && $2 != "total"'
```
Expected: a clear reduction from 7,214, and no file over 600 lines. If `keys.go` or another file is still over 600, note it — plan 11 records it as remaining work rather than papering over it.

- [ ] **Step 3: Record the phase summary**

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
git commit -S --allow-empty -m "chore(api): close the behavior-preserving refactor phase

Plans 02-08 complete. Zero test files modified across the phase, which
is what makes the suite a valid oracle for these changes. Build, vet,
full test suite green; api/ coverage at or above the 86.0% baseline.

Plans 09-11 change behavior and may modify tests."
```

Fill in the measured line count from Step 2 before committing.

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-09-deleted-key-lookup.md` next.**
