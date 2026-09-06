# API Refactor 04 — Generic Service Accessor

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace six copy-pasted service accessors and 31 nil-guards with one generic `svc[T]` returning a checked `(value, ok)` pair.

**Architecture:** `App.ServiceContainer` is already typed as `container.ServiceContainerInterface` (`app/app.go:44`), so a getter function parameterizes cleanly. The generic version preserves the existing failure behavior exactly — `SetInternalError(nil)`, a 500 — and only changes the call shape from "compare to nil" to "check ok", which the compiler enforces.

**Tech Stack:** Go 1.25 generics.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0. Generics available.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **Do not modify any `_test.go` file in this plan.**
- The failure path must stay `c.SetInternalError(nil)` — a 500 with an empty detail. Tests assert on that shape.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Add `svc[T]` alongside the existing accessors

**Files:**
- Modify: `api/context.go` (add below the existing accessors at lines 231-277; leave them in place for now)

**Interfaces:**
- Consumes: `app.App.ServiceContainer` of type `container.ServiceContainerInterface`.
- Produces: `func svc[T any](c *Context, get func(container.ServiceContainerInterface) T) (T, bool)`

- [ ] **Step 1: Add the function and its import**

Add `"rocketvault/internal/container"` to the import block in `api/context.go`, then append:

```go
// svc resolves a service from the request's container.
//
// It replaces six accessors that were each the same six lines, and it changes
// the call shape from a nil comparison to a checked ok. That matters: a nil
// comparison is easy to omit and compiles fine when omitted, whereas ignoring
// the second return here leaves the caller with a zero value it must still
// reason about.
//
// The failure behavior is unchanged from the accessors it replaces: a missing
// App or container sets a 500 with no detail and returns false.
func svc[T any](c *Context, get func(container.ServiceContainerInterface) T) (T, bool) {
	var zero T
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return zero, false
	}
	return get(c.App.ServiceContainer), true
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
git add api/context.go
git commit -S -m "refactor(api): add generic service accessor"
```

---

### Task 2: Migrate the 31 call sites

**Files:**
- Modify: `api/audit.go` (5), `api/certificates.go` (5), `api/certificate_policy.go` (3), `api/key_rotation_policy.go` (3), `api/keys.go` (15), `api/oidc.go` (2), `api/secrets.go` (11), `api/soft_delete.go` (10), `api/users.go` (10), `api/vault.go` (6), `api/vault_webhook.go` (4)

The per-file counts above are `grep -c 'Svc == nil'` plus accessor calls; treat them as a guide, and let the final grep in Step 3 be the authority.

**Interfaces:**
- Consumes: `svc[T]` from Task 1.
- Produces: no new symbols.

- [ ] **Step 1: Find every accessor call**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -n -A3 'c\.\(secretSvc\|keySvc\|cryptoSvc\|userSvc\|certSvc\|authSvc\)()' $(ls *.go | grep -v _test)
```

- [ ] **Step 2: Apply the substitution**

The getter for each of the six:

| Old accessor | Getter expression |
|---|---|
| `c.secretSvc()` | `container.ServiceContainerInterface.GetSecretService` |
| `c.keySvc()` | `container.ServiceContainerInterface.GetKeyService` |
| `c.cryptoSvc()` | `container.ServiceContainerInterface.GetCryptoService` |
| `c.userSvc()` | `container.ServiceContainerInterface.GetUserService` |
| `c.certSvc()` | `container.ServiceContainerInterface.GetCertificateService` |
| `c.authSvc()` | `container.ServiceContainerInterface.GetAuthenticationService` |

Those are method expressions: `container.ServiceContainerInterface.GetSecretService` has type `func(container.ServiceContainerInterface) secretServices.SecretService`, which is exactly the parameter `svc` wants. No closure is needed.

Before (`api/soft_delete.go`, `recoverSecret`):

```go
	secretSvc := c.secretSvc()
	if secretSvc == nil {
		return
	}
```

After:

```go
	secretSvc, ok := svc(c, container.ServiceContainerInterface.GetSecretService)
	if !ok {
		return
	}
```

Add `"rocketvault/internal/container"` to each file's imports as you convert it.

Apply the same shadowing care as plan 03: where `ok` is already bound, name the new one for its subject, e.g. `secretSvc, svcOK := ...`.

- [ ] **Step 3: Delete the six old accessors, gate, commit**

Once no call sites remain, delete the six methods from `api/context.go` (the `secretSvc`, `keySvc`, `cryptoSvc`, `userSvc`, `certSvc` and `authSvc` blocks, formerly lines 231-277), and drop the service imports that become unused. The compiler will name them.

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
grep -rn 'c\.\(secretSvc\|keySvc\|cryptoSvc\|userSvc\|certSvc\|authSvc\)()' $(ls *.go | grep -v _test)
```
Expected: no output.

If a `_test.go` file calls one of these accessors, **stop**. The accessors are unexported, so a test may legitimately use them. In that case keep the old accessor as a one-line delegation to `svc` rather than deleting it, and say so in the commit body — do not edit the test.

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
git commit -S -m "refactor(api): resolve services through the generic accessor"
```

---

### Task 3: Confirm the package shrank and record progress

**Files:**
- Modify: none (measurement only)

**Interfaces:**
- Consumes: the three preceding plans' work.
- Produces: a line count recorded in the commit body, so plan 11's final report has a mid-point to compare against.

- [ ] **Step 1: Measure**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
wc -l $(ls *.go | grep -v _test) | tail -1
```

Baseline before plan 02 was **7,214** lines. Expect roughly 6,200-6,600 now. If the number went **up**, something was added rather than replaced — investigate before continuing.

- [ ] **Step 2: Confirm the primitives are actually being used**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor/api
for f in writeJSON writeJSONStatus decodeBody resourceID b64Field svc; do
    printf "%-16s %s\n" "$f" "$(grep -c "\b$f(" $(ls *.go | grep -v _test) | awk -F: '{s+=$2} END {print s}')"
done
```
Expected: every one non-zero. A zero means that plan's adoption task did not actually land.

- [ ] **Step 3: Record it**

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
git commit -S --allow-empty -m "chore(api): checkpoint after request/response primitive adoption

Non-test api/ line count after plans 02-04, down from the 7,214-line
baseline at 4dc0285. Recorded so plan 11 can report the total reduction."
```

Replace the body with the number you actually measured before committing.

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-05-split-keys.md` next.**
