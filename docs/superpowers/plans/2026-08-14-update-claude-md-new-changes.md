# Update CLAUDE.md for Post-2026-08-11 Changes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `CLAUDE.md` up to date with the 101 commits landed since its "Last Updated: 2026-08-11" line, none of which touched the file. Six subsystems are undocumented or now factually wrong: the CLI vault-authorization retrofit, four new Azure built-in roles + the vault purge endpoint, OIDC external identity provider support, HSM-backed AES (`oct`) key support, vault-scoped soft-delete for keys/certificates, and the new Go-based docs pipeline.

**Architecture:** Each task adds a self-contained block of new content to `CLAUDE.md` at one natural insertion point, verified against the actual source before being written. This plan does **not** touch, reorganize, or delete any of the file's existing content (that cleanup was explicitly scoped out) — every task is additive except Task 5's one-line correction to a "known deferral" note that is now factually false because the deferred work shipped.

**Tech Stack:** Markdown; verification via `grep`/`go doc`/reading Go source directly (there is no test suite for documentation — each task's "verify" step is a source-of-truth check, not a unit test).

**Spec:** None — derived directly from `git log --oneline --since=2026-08-11` and the corresponding commits/diffs, read live for this plan.

## Global Constraints

- Do not modify, reorder, or delete any existing `CLAUDE.md` content except the single line named in Task 5. This was an explicit user decision — the file's known staleness/bloat elsewhere is out of scope for this pass.
- Every insertion uses an exact-text anchor (old_string/new_string), not a line number — tasks may be executed out of order or line numbers may have drifted since this plan was written, and exact-text anchors are robust to that; line numbers below are for locating the anchor while reading, not for tooling.
- Every fact in every task must be re-verified against current source immediately before writing (`grep`/`go doc` command given in each task's Step 1) — do not trust this plan's own prose as the source of truth, trust the command's output at execution time, since the codebase may have moved further since this plan was written.
- This is a shared working tree (a concurrent Claude Code session may be active in another Herdr pane in this same repo) — run `git status --porcelain CLAUDE.md` immediately before each task's edit to confirm no external change landed since the plan was written, and immediately after each commit to confirm the commit is what's actually on disk.

---

### Task 1: Document the CLI vault-authorization retrofit

**Files:**
- Modify: `CLAUDE.md` (insert after the existing `### Authorization (\`internal/services/authorization/\`)` bullet list, before the `### 🔐 Authorization Scope` heading)

**Interfaces:**
- Consumes: `cmd/vaultcli.ResolveVaultID(ctx, cmd, sc) (uuid.UUID, error)`, `cmd/vaultcli.RequireDataAction(ctx, cmd, sc, principalID, action model.DataAction, op model.PolicyOperation) (uuid.UUID, error)` — both already implemented, `cmd/vaultcli/vault.go:18,40`.
- Produces: no code change — pure documentation addition.

- [ ] **Step 1: Verify the facts against source**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
grep -n "^func " cmd/vaultcli/vault.go
grep -rln "vaultcli.RequireDataAction" cmd/vaults cmd/vault-access cmd/secrets cmd/keys cmd/certificates
```

Expected: the first command shows `ResolveVaultID` and `RequireDataAction`; the second lists at least one file under each of the five command directories, confirming all five resource-command families call through this package (not just secrets/keys as an older plan draft might imply).

- [ ] **Step 2: Insert the new subsection**

In `CLAUDE.md`, find:

```markdown
### Authorization (`internal/services/authorization/`)
- **RBACService**: global role permissions for vault and user management only
- **AccessPolicyService**: explicit-deny override, evaluated before role grants
- **RoleAssignmentService**: per-vault Azure role grants and the `HasDataAction` authorization decision
- Vault data-plane routes are deny-by-default: see `docs/release-notes/v4.0.0-azure-rbac.md`

### 🔐 Authorization Scope (`model/scope.go`)
```

Replace with:

```markdown
### Authorization (`internal/services/authorization/`)
- **RBACService**: global role permissions for vault and user management only
- **AccessPolicyService**: explicit-deny override, evaluated before role grants
- **RoleAssignmentService**: per-vault Azure role grants and the `HasDataAction` authorization decision
- Vault data-plane routes are deny-by-default: see `docs/release-notes/v4.0.0-azure-rbac.md`

### CLI Authorization (`cmd/vaultcli/`)

HTTP requests get their per-vault authorization check for free from `PolicyMiddleware`. CLI commands call the service layer directly and bypass that middleware entirely, so every resource command (`vaults`, `vault-access`, `secrets`, `keys`, `certificates`) must reproduce the same check itself by calling `vaultcli.RequireDataAction` (which internally re-runs the identical two-stage check: `AccessPolicyService`'s explicit-deny override, then the deny-by-default role-assignment check) after resolving the target vault via `vaultcli.ResolveVaultID`. A new CLI command that skips this call bypasses authorization entirely — there is no other enforcement point on the CLI path.

### 🔐 Authorization Scope (`model/scope.go`)
```

- [ ] **Step 3: Re-read the inserted section for consistency**

Run: `grep -n "CLI Authorization" CLAUDE.md`

Expected: one match, immediately followed by the `### 🔐 Authorization Scope` heading — confirms the insertion landed in the right place and didn't duplicate.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude-md): document the CLI vault-authorization retrofit"
```

---

### Task 2: Document the four new Azure roles, the purge endpoint, and Data Access Administrator delegation

**Files:**
- Modify: `CLAUDE.md` (insert immediately after Task 1's new "CLI Authorization" subsection, before `### 🔐 Authorization Scope`)

**Interfaces:**
- Consumes: `model.RoleKeyVaultPurgeOperator`, `model.RoleKeyVaultCertificateUser`, `model.RoleKeyVaultCryptoServiceEncryptionUser`, `model.RoleKeyVaultDataAccessAdministrator` (`model/azure_roles.go`), `DELETE /api/v1/vaults/{vault_name}/purge` (`api/vault.go:43`).
- Produces: no code change — pure documentation addition.

- [ ] **Step 1: Verify the facts against source**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
grep -n "RoleKeyVaultPurgeOperator\|RoleKeyVaultCertificateUser\|RoleKeyVaultCryptoServiceEncryptionUser\|RoleKeyVaultDataAccessAdministrator" model/azure_roles.go
grep -n "purge" api/vault.go
grep -rn "DataAccessAdministrator" internal/services/authorization/*.go | grep -i "grant\|revoke"
```

Expected: the four role constants exist with their display-name strings; `api/vault.go` shows the `DELETE .../purge` route; the third command confirms `Data Access Administrator` is checked in the grant/revoke role-assignment path (not just listed as a role name with no special handling).

- [ ] **Step 2: Insert the new content**

Immediately after Task 1's inserted "CLI Authorization" section (and still before `### 🔐 Authorization Scope`), insert:

```markdown
### Azure Role Additions (since 2026-08-11)

Four built-in roles were added beyond the original seven: `Key Vault Purge Operator`, `Key Vault Certificate User`, `Key Vault Crypto Service Encryption User`, and `Key Vault Data Access Administrator` (`model/azure_roles.go`). `Key Vault Data Access Administrator` is the one role that can manage *other* role assignments — grant and revoke — without also holding data-plane access itself; every other role's permissions are described in `.claude/azure-keyvault-parity.md`. Vaults also gained a real purge endpoint, `DELETE /api/v1/vaults/{vault_name}/purge`, gated on `Key Vault Purge Operator` or the global admin role.
```

- [ ] **Step 3: Re-read for consistency**

Run: `grep -n "Azure Role Additions" CLAUDE.md`

Expected: one match, positioned after "CLI Authorization" and before "Authorization Scope".

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude-md): document the four new Azure roles and vault purge endpoint"
```

---

### Task 3: Document OIDC external identity provider support

**Files:**
- Modify: `CLAUDE.md` (insert after the existing `### Authentication Services (\`internal/services/auth/\`)` bullet list, before `### User Management`)

**Interfaces:**
- Consumes: `internal/services/auth.OIDCService`, `internal/services/auth.NewOIDCService(ctx, cfg) (OIDCService, error)`, `UserService.FindOrCreateExternalUser`, `AuthenticationService.IssueSessionForUser` — all already implemented (confirmed present in an earlier session of this same conversation: `internal/services/auth/oidc_service.go`, `api/oidc.go:27-28`).
- Produces: no code change — pure documentation addition.

- [ ] **Step 1: Verify the facts against source**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
ls internal/services/auth/oidc_service.go
grep -n "oidcLoginHandler\|oidcCallbackHandler\|/oidc/login\|/oidc/callback" api/oidc.go
grep -n "^  enabled:" .rocketvault.yaml | head -1
grep -n "oidc:" .rocketvault.yaml
```

Expected: `oidc_service.go` exists; `api/oidc.go` registers `GET /oidc/login` and `GET /oidc/callback`; `.rocketvault.yaml` has an `oidc:` block with `enabled: false` by default.

- [ ] **Step 2: Insert the new subsection**

In `CLAUDE.md`, find:

```markdown
### Authentication Services (`internal/services/auth/`)
- **PasswordService**: Password hashing and validation only
- **TOTPService**: TOTP generation and validation only
- **JWTService**: JWT token creation and validation only
- **AuthenticationService**: Orchestrates complete auth workflow

### User Management (`internal/services/users/`)
```

Replace with:

```markdown
### Authentication Services (`internal/services/auth/`)
- **PasswordService**: Password hashing and validation only
- **TOTPService**: TOTP generation and validation only
- **JWTService**: JWT token creation and validation only
- **AuthenticationService**: Orchestrates complete auth workflow
- **OIDCService**: OIDC authorization-code-flow login, additive to local username/password/TOTP — never replaces it. Gated by `oidc.enabled` in `.rocketvault.yaml` (default `false`); when disabled, `GET /oidc/login` and `GET /oidc/callback` (`api/oidc.go`) return 503 rather than the server attempting a network call to the issuer at startup. On successful callback, `UserService.FindOrCreateExternalUser` looks up or creates a `model.User` (default role: least-privilege `user`), and `AuthenticationService.IssueSessionForUser` issues the same JWT/session pair local login uses — there is no separate OIDC token-issuance path to drift out of sync.

### User Management (`internal/services/users/`)
```

- [ ] **Step 3: Re-read for consistency**

Run: `grep -n "OIDCService" CLAUDE.md`

Expected: one match, inside the Authentication Services bullet list.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude-md): document OIDC external identity provider support"
```

---

### Task 4: Document HSM-backed AES (`oct`) key support

**Files:**
- Modify: `CLAUDE.md` (insert after the existing `### Key Management (\`internal/services/keys/\`) - NEW ✨` bullet, before `### Certificate Management`)

**Interfaces:**
- Consumes: `crypto.KeyProvider.GenerateAESKey(ctx, bits) (string, error)`, `crypto.ErrOctKeysRequireHSM`, `KeyService.CreateOctKey` — all already implemented (confirmed present in an earlier session of this same conversation).
- Produces: no code change — pure documentation addition.

- [ ] **Step 1: Verify the facts against source**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
grep -n "ErrOctKeysRequireHSM" internal/crypto/software_provider.go
grep -n "func.*CreateOctKey" internal/services/keys/key_service.go
grep -n '"OCT"' api/keys.go
```

Expected: `ErrOctKeysRequireHSM` defined in the software provider (returned unconditionally — symmetric keys are HSM-only); `CreateOctKey` implemented on `keyService`; `"OCT"` accepted as a `type` value in the `createKey` handler.

- [ ] **Step 2: Insert the new content**

In `CLAUDE.md`, find:

```markdown
### Key Management (`internal/services/keys/`) - NEW ✨
- **KeyService**: RSA/ECDSA key generation, access control, CRUD operations

### Certificate Management (`internal/services/certificates/`) - NEW ✨
```

Replace with:

```markdown
### Key Management (`internal/services/keys/`) - NEW ✨
- **KeyService**: RSA/ECDSA key generation, access control, CRUD operations
- Symmetric AES (`oct`) keys are **HSM-only** by design, matching Azure (Managed HSM never allows symmetric key creation on Standard/Premium vaults, and RocketVault's software provider mirrors that restriction). `KeyService.CreateOctKey` → `crypto.KeyProvider.GenerateAESKey` always fails with `crypto.ErrOctKeysRequireHSM` unless `hsm.enabled: true`; the PKCS#11 provider implements AES-KW wrap/unwrap for real. `POST /keys` accepts `"type": "OCT"` with `"bits"` of 128/192/256.

### Certificate Management (`internal/services/certificates/`) - NEW ✨
```

- [ ] **Step 3: Re-read for consistency**

Run: `grep -n "ErrOctKeysRequireHSM" CLAUDE.md`

Expected: one match, inside the Key Management bullet list.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude-md): document HSM-backed AES (oct) key support"
```

---

### Task 5: Document vault-scoped soft-delete for keys/certs, correct the now-false "known deferral" note

**Files:**
- Modify: `CLAUDE.md` — two edits: (a) correct the `.claude/multi-vault.md` pointer's deferral bullet, (b) add a soft-delete note to the Certificate Management bullet list.

**Interfaces:**
- Consumes: `KeyService.ListDeletedKeys/RecoverKey/PurgeKey`, `CertificateService.ListDeletedCertificates/RecoverCertificate/PurgeCertificate` — all already implemented (confirmed present in an earlier session of this same conversation).
- Produces: no code change — pure documentation addition/correction.

- [ ] **Step 1: Verify the facts against source**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
grep -n "ListDeletedKeys\|ListDeletedCertificates" internal/services/keys/key_service.go internal/services/certificates/certificate_service.go
grep -n "vault_name.*deleted/keys\|vault_name.*deleted/certificates" api/soft_delete.go
grep -rln "vaultcli.RequireDataAction" cmd/keys cmd/certificates
```

Expected: both `ListDeletedKeys` and `ListDeletedCertificates` exist on their respective service interfaces; `api/soft_delete.go` registers vault-scoped deleted-list/restore/purge routes for both keys and certificates (not just secrets); both `cmd/keys` and `cmd/certificates` call `vaultcli.RequireDataAction` (confirms `--vault` CLI wiring, already documented separately in the "Authorization Architecture" work from an earlier session — Step 1 here is only re-confirming it's still true).

- [ ] **Step 2a: Correct the stale deferral note**

In `CLAUDE.md`, find:

```markdown
### 🏛️ [Multi-Vault Architecture](.claude/multi-vault.md)
- Vault as a routing + context-scoping layer (Azure Key Vault parity)
- Vault-scoped resources, per-vault access policies, default-vault migration
- Known deferrals (secondary subsystems, keys/certs CLI, subdomain addressing)
```

Replace with:

```markdown
### 🏛️ [Multi-Vault Architecture](.claude/multi-vault.md)
- Vault as a routing + context-scoping layer (Azure Key Vault parity)
- Vault-scoped resources, per-vault access policies, default-vault migration
- Keys/certs CLI `--vault` wiring and vault-scoped soft-delete (list/restore/purge) shipped since this doc was last updated — see `.claude/multi-vault.md` for what, if anything, is still deferred
```

- [ ] **Step 2b: Add the soft-delete note to Certificate Management**

In `CLAUDE.md`, find:

```markdown
### Certificate Management (`internal/services/certificates/`) - NEW ✨
- **CertificateService**: Certificate lifecycle management, CA validation
```

Replace with:

```markdown
### Certificate Management (`internal/services/certificates/`) - NEW ✨
- **CertificateService**: Certificate lifecycle management, CA validation
- Soft-delete (list/restore/purge) is vault-scoped for both keys and certificates, mirroring the pre-existing secrets soft-delete pattern (`internal/services/secrets/secret_service.go`'s `ListDeletedSecrets`/`RecoverSecret`/`PurgeSecret`) — see `KeyService.ListDeletedKeys`/`RecoverKey`/`PurgeKey` and the `CertificateService` equivalents.
```

- [ ] **Step 3: Re-read for consistency**

Run:
```bash
grep -n "Known deferrals\|Keys/certs CLI" CLAUDE.md
grep -n "vault-scoped for both keys and certificates" CLAUDE.md
```

Expected: the first command's old "Known deferrals (secondary subsystems, keys/certs CLI..." text is gone, replaced by the new line; the second command finds the new Certificate Management bullet.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude-md): document vault-scoped soft-delete for keys/certs, correct stale deferral note"
```

---

### Task 6: Document the docs.sh build command

**Files:**
- Modify: `CLAUDE.md` (insert into the existing `### Testing` code block's sibling area under `## Build and Run` — add a new `### Documentation` subsection after `### Testing`, before `### Linting`)

**Interfaces:**
- Consumes: `scripts/docs.sh` (build/package/serve entrypoint for `scripts/docsgen`, its own Go module — already shipped, confirmed by this task's Step 1).
- Produces: no code change — pure documentation addition.

- [ ] **Step 1: Verify the facts against source**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
ls -la scripts/docs.sh
head -20 scripts/docs.sh
```

Expected: `scripts/docs.sh` exists and is executable; its header/usage text confirms `build`/`package`/`serve` subcommands wrapping `go run` against `scripts/docsgen`.

- [ ] **Step 2: Insert the new subsection**

In `CLAUDE.md`, find:

```markdown
### Testing
```bash
# Run all tests
go test ./...

# Run CLI test suite specifically
go test ./cmd/... -v

# Run with coverage
go test ./cmd/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Linting
```

Replace with:

```markdown
### Testing
```bash
# Run all tests
go test ./...

# Run CLI test suite specifically
go test ./cmd/... -v

# Run with coverage
go test ./cmd/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Documentation

`scripts/docs.sh` builds and serves the HTML docs site (`docs/admin-manual.html` and its linked markdown, rendered via `scripts/docsgen`, its own Go module — no Python step, unlike before 2026-08-13).

```bash
./scripts/docs.sh build     # render markdown -> styled HTML
./scripts/docs.sh package   # build + tar.gz/zip with checksums
./scripts/docs.sh serve     # local preview server
```

### Linting
```

- [ ] **Step 3: Re-read for consistency**

Run: `grep -n "### Documentation" CLAUDE.md`

Expected: one match, between "### Testing" and "### Linting" under "## Build and Run".

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude-md): document the scripts/docs.sh build pipeline"
```

---

## Self-Review Notes (from plan authoring)

- **Spec coverage**: all six subsystems identified from the `git log --since=2026-08-11` survey are covered — CLI authorization retrofit (Task 1), new Azure roles + purge endpoint (Task 2), OIDC (Task 3), HSM AES keys (Task 4), vault-scoped soft-delete for keys/certs (Task 5), docs pipeline (Task 6). Not covered, deliberately: the `RenewCertificate` signature change (internal refactor, not reflected anywhere in current `CLAUDE.md` prose, so there's no existing claim to correct and no natural insertion point without inventing a new section — out of scope for an additive-only pass) and the unreachable-CLI-roles-branch removal (pure internal refactor, no architectural or usage implication).
- **Placeholder scan**: no TBD/TODO — every insertion is complete, verified text.
- **Type/name consistency**: cross-checked `vaultcli.RequireDataAction`/`ResolveVaultID` (Task 1), `model.RoleKeyVault*` constants (Task 2), `OIDCService`/`FindOrCreateExternalUser`/`IssueSessionForUser` (Task 3), `CreateOctKey`/`GenerateAESKey`/`ErrOctKeysRequireHSM` (Task 4), and `ListDeletedKeys`/`ListDeletedCertificates` (Task 5) all match the exact names already confirmed against source earlier in this session — no renamed/invented symbols.
