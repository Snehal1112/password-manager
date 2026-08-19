# Vault-Scoped Item Backup Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the ownership check in `ItemBackupService.BackupSecret`/`BackupKey`/`BackupCertificate` with a vault-scoped read, so a Crypto User (or Secrets User, or Certificates Officer) who holds the RBAC backup action can back up an item in a vault they are authorized for without owning it — and so no caller can back up an item outside the vault their request was authorized against.

**Architecture:** Backup is made to mirror restore. `RestoreSecret`/`RestoreKey`/`RestoreCertificate` already take the request's authorized `vaultID` and write into it (commit `c5bf97d`, "restore into the authorized vault, not the blob's embedded vault"). The three `Backup*` methods take the same parameter and read with `model.NewVaultScope(vaultID, userID)` instead of `model.NewAdminScope(userID)` plus a hand-rolled `UserID != userID` comparison. The repository's scope predicate becomes the single enforcement point, matching every other read path in the codebase.

**Tech Stack:** Go 1.24, `model.Scope` value object, Gorilla Mux, testify.

**Spec:** No separate design doc. The source finding is `.claude/azure-keyvault-parity.md` §2, the `Backup / Restore` row (line 48): *"`ItemBackupService.BackupKey` gates on `key.UserID == caller` on top of `ActionKeysBackup`, so a Crypto User who does not own the key is refused."* The **Plan-time corrections** section below records two ways the current parity text and the naive reading of that finding are both wrong.

## Plan-time corrections

**C1 — The route-registration half of the parity row is already fixed; do not "fix" it again.** Line 48 also claims backup/restore is *"registered on the flat routes only (`api/backup_item.go` `InitBackupItem` attaches to `BaseRoutes.Keys`, never to the vault-scoped subrouter, so `/vaults/{name}/keys/{id}/backup` 404s)"*. That is stale. `api/backup_item.go:21-27` registers all six routes on `BaseRoutes.VaultScoped` as well, added by commit `03badab` ("fix(backup): register item backup/restore on the vault-scoped router"). No task in this plan touches route registration; Task 5 corrects the doc.

**C2 — Deleting the ownership check on its own opens a cross-vault read.** The check is the *only* thing constraining which item a caller can name. The read above it uses `model.NewAdminScope(userID)`, which carries no predicate at all — `item_backup.go:56-58` says so explicitly: *"The read itself is unchecked (admin scope); the explicit ownership check below is the actual gate."* `PolicyMiddleware` authorizes the request against the vault in the route (the `default` vault for a flat route), but nothing then confirms the *named item* lives in that vault. Remove the ownership check and leave the admin scope in place, and a caller holding `ActionKeysBackup` in the `default` vault could back up any key in any vault by ID. The check must be **replaced** with a vault scope, not deleted.

**C3 — The key version query filters by the caller's user ID, and would silently truncate a non-owner's backup.** `KeyRepository.ListVersionRecords` joins `WHERE kv.key_id = ? AND k.user_id = ?` (`internal/repositories/key_repository.go:836`). `BackupKey` currently passes the *caller's* ID (`item_backup.go:106`), which is safe today only because the ownership check guarantees caller == owner. Once a non-owner can back up, that query returns zero rows and the blob loses the key's archived versions with no error — reintroducing exactly the history-loss bug the 2026-08-19 key-version work closed (§ B26). `BackupKey` must pass `key.UserID`, read from the key it just fetched, not the caller's ID.

## Global Constraints

- **Fail closed.** Every `Backup*` read uses `model.NewVaultScope(vaultID, userID)`. `model.NewAdminScope` must not appear in `internal/backup/item_backup.go` after this work.
- **No new authorization tier.** The RBAC action check (`ActionSecretsBackup` / `ActionKeysBackup` / `ActionCertificatesBackup`) stays where it is, in `PolicyMiddleware`. This plan adds the *data* scope that middleware check has always assumed.
- **Composite `model.Scope` literals are banned** outside `model/scope_test.go` — enforced by the `scope-gate` CI job. Always build scopes with `model.NewVaultScope(...)`.
- **A cross-vault or non-existent item is a 404, not a 403.** The scoped read returns no row, matching how `ErrKeyNotFound` is surfaced on every other key route (`api/errors_key.go:26-27`). Do not add a new "forbidden" signal to replace the one being removed.
- **The blob format does not change.** `backupEnvelope` (`item_backup.go:46-51`) and its base64url encoding stay byte-identical, so blobs taken before this change still restore.
- **`vaultID` comes from the request, never from the caller.** Handlers use `vaultIDFromRequest(r)`, the same helper the three restore handlers already use (`api/backup_item.go:123, 194, 265`).
- **Go 1.24, existing dependencies only.**

## File structure

| File | Responsibility |
|---|---|
| `internal/backup/item_backup.go` (modify) | Three `Backup*` signatures gain `vaultID`; scope swap; `ListVersionRecords` owner fix; `ErrForbidden` removed |
| `api/backup_item.go` (modify) | Three backup handlers resolve `vaultIDFromRequest`; dead `ErrForbidden` branches removed |
| `internal/backup/item_backup_test.go` (modify) | Secret and shared-stub updates, scope-recording assertion |
| `internal/backup/backup_edge_test.go` (modify) | Key and certificate updates |
| `api/backup_item_test.go` (modify) | Four direct `Backup*` call sites at lines 453, 554, 847, 1036 |
| `.claude/azure-keyvault-parity.md` (modify) | §2 row + Summary bullet |
| `.claude/known-bugs.md` (modify) | New entry |

Tasks 1-3 take one resource type each so the build and test suite are green at every commit.

---

### Task 1: Vault-scope `BackupKey`

**Files:**
- Modify: `internal/backup/item_backup.go:94-111` (`BackupKey`)
- Modify: `api/backup_item.go:150-179` (`backupKeyHandler`)
- Modify: `internal/backup/backup_edge_test.go` (`TestBackupKeyForbidden` at line 114, `TestBackupKeyRepoError` at 134, `TestRestoreKeySuccess` at ~140, and every other `svc.BackupKey(` call)
- Modify: `api/backup_item_test.go:847`

**Interfaces:**
- Consumes: `model.NewVaultScope(vaultID, userID uuid.UUID) model.Scope`; `KeyRepositoryInterface.Read(ctx, id, scope) (*model.Key, error)`; `KeyRepositoryInterface.ListVersionRecords(ctx, keyID, userID) ([]model.KeyVersionRecord, error)`; `api.vaultIDFromRequest(r *http.Request) (uuid.UUID, error)`.
- Produces: `ItemBackupService.BackupKey(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error)`. Tasks 2 and 3 mirror this parameter order exactly: `(ctx, id, userID, vaultID)`.

- [ ] **Step 1: Write the failing test**

In `internal/backup/backup_edge_test.go`, replace `TestBackupKeyForbidden` (line 114) with the two tests below. The first pins the new capability; the second pins the scope that replaces the ownership check.

This needs the shared `stubKeyRepo` (defined in `internal/backup/item_backup_test.go`, same test package) to record the scope it is read with. Add one field and one line there first:

```go
// In item_backup_test.go, on the stubKeyRepo struct:
type stubKeyRepo struct {
	keys     map[uuid.UUID]*model.Key
	versions map[uuid.UUID]map[int]string
	// LastReadScope records the scope of the most recent Read. The stub itself
	// ignores scope (it is an in-memory map), so the scope the service passes
	// is asserted directly — the real predicate lives in KeyRepository's SQL.
	LastReadScope model.Scope
}
```

and record it as the first statement of that stub's `Read` method:

```go
	r.LastReadScope = scope
```

Then, in `backup_edge_test.go`:

```go
func TestBackupKeyNonOwnerInSameVaultSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	kr := newStubKeyRepo()
	require.NoError(t, kr.Create(ctx, &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID,
		Name: "k", Value: "v", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := backup.NewItemBackupService(nil, kr, nil)

	// A Crypto User authorized in this vault who does not own the key must be
	// able to back it up. Authorization is the RBAC action check in
	// PolicyMiddleware plus the vault scope, not key ownership.
	blob, err := svc.BackupKey(ctx, keyID, callerID, vaultID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
}

func TestBackupKeyReadsWithVaultScope(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	kr := newStubKeyRepo()
	require.NoError(t, kr.Create(ctx, &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID,
		Name: "k", Value: "v", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := backup.NewItemBackupService(nil, kr, nil)

	_, err := svc.BackupKey(ctx, keyID, callerID, vaultID)
	require.NoError(t, err)

	// The scope is the whole gate now: an admin scope carries no predicate and
	// would let a caller name a key in any vault.
	require.Equal(t, model.NewVaultScope(vaultID, callerID), kr.LastReadScope)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/backup/ -run 'TestBackupKeyNonOwnerInSameVaultSucceeds|TestBackupKeyReadsWithVaultScope' -v`

Expected: **build failure**, `not enough arguments in call to svc.BackupKey` (three supplied, four expected once the signature changes — before the change it is the reverse: `too many arguments`). Either way the package does not compile, which is the failing state.

- [ ] **Step 3: Rewrite `BackupKey`**

Replace `internal/backup/item_backup.go:94-111`:

```go
// BackupKey creates a base64url-encoded backup blob for the given key.
//
// vaultID is the vault the caller's request was authorized against, never a
// vault taken from user input — the same rule RestoreKey follows. The scoped
// read is the entire authorization gate: an unscoped read plus an ownership
// comparison (the previous design) refused a Crypto User who legitimately held
// ActionKeysBackup without owning the key, while still letting any caller name
// a key in a vault they were never authorized for.
func (s *ItemBackupService) BackupKey(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	key, err := s.keyRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup key: %w", err)
	}

	// Version records are filtered by the key's owner, not the caller:
	// ListVersionRecords joins on k.user_id, so passing a non-owning caller's
	// ID returns zero rows and silently drops the key's rotation history from
	// the blob.
	versions, err := s.keyRepo.ListVersionRecords(ctx, id, key.UserID)
	if err != nil {
		return "", fmt.Errorf("backup key: list versions: %w", err)
	}
	return encodeBlob("key", id.String(), key, versions)
}
```

- [ ] **Step 4: Update the handler**

Replace `api/backup_item.go:150-179` (`backupKeyHandler`). It gains the same `vaultIDFromRequest` block `restoreKeyHandler` already has at line 194:

```go
// backupKeyHandler creates a backup blob for a key and returns it.
func backupKeyHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	// A key outside the authorized vault does not resolve under the scoped
	// read, so it reports as not-found — the same shape every other scoped key
	// route uses for an out-of-scope ID.
	blob, err := svc.BackupKey(r.Context(), keyID, userID, vaultID)
	if err != nil {
		c.SetNotFound("key")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"blob": blob}) //nolint:errcheck,gosec
}
```

- [ ] **Step 5: Update the remaining `BackupKey` call sites**

Find them: `grep -rn "BackupKey(" internal/backup/ api/ | grep -v item_backup.go`

Each existing call gains a fourth argument. Where the test creates a key with no `VaultID`, pass `uuid.Nil` and give the key `VaultID: uuid.Nil` so the stub still returns it. For example, `TestBackupKeyRepoError` (line 134) becomes:

```go
	_, err := svc.BackupKey(context.Background(), uuid.New(), uuid.New(), uuid.New())
```

and `TestRestoreKeySuccess`'s backup line becomes:

```go
	blob, err := svc.BackupKey(ctx, keyID, ownerID, uuid.Nil)
```

`api/backup_item_test.go:847` becomes:

```go
	blob, err := svc.BackupKey(context.Background(), keyID, userID, uuid.Nil)
```

Delete `TestBackupKeyForbidden` outright — the behavior it pins is the behavior being removed, and Task 1's two new tests replace it.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/backup/ ./api/ -run 'Backup|Restore' -v 2>&1 | tail -30`
Expected: PASS, with `TestBackupKeyNonOwnerInSameVaultSucceeds` and `TestBackupKeyReadsWithVaultScope` among them and no `TestBackupKeyForbidden`.

Run: `go build ./...`
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add internal/backup/item_backup.go api/backup_item.go internal/backup/backup_edge_test.go internal/backup/item_backup_test.go api/backup_item_test.go
git commit -m "fix(backup): authorize key backup by vault scope instead of ownership"
```

---

### Task 2: Vault-scope `BackupSecret`

**Files:**
- Modify: `internal/backup/item_backup.go:53-66` (`BackupSecret`)
- Modify: `api/backup_item.go:79-108` (`backupSecretHandler`)
- Modify: `internal/backup/item_backup_test.go` (`TestBackupSecretForbidden` at line 202, plus every `svc.BackupSecret(` call), `internal/backup/backup_edge_test.go` (line 193, 314, 336)
- Modify: `api/backup_item_test.go:453, 554`

**Interfaces:**
- Consumes: `SecretRepositoryInterface.Read(ctx, id, scope) (*model.Secret, error)`; `model.NewVaultScope`.
- Produces: `ItemBackupService.BackupSecret(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error)`.

- [ ] **Step 1: Write the failing test**

Add a `LastReadScope model.Scope` field to `stubSecretRepo` (in `internal/backup/item_backup_test.go`) and record it as the first statement of its `Read` method, exactly as Task 1 did for `stubKeyRepo`. Then replace `TestBackupSecretForbidden` (line 202) with:

```go
func TestBackupSecretNonOwnerInSameVaultSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID:      secretID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "shared",
		Value:   "value",
		Version: 1,
		Enabled: true,
	}))

	svc := backup.NewItemBackupService(repo, nil, nil)

	// A Secrets Officer authorized in this vault who does not own the secret
	// must be able to back it up.
	blob, err := svc.BackupSecret(ctx, secretID, callerID, vaultID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
	require.Equal(t, model.NewVaultScope(vaultID, callerID), repo.LastReadScope)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/backup/ -run TestBackupSecretNonOwnerInSameVaultSucceeds -v`
Expected: **build failure**, `too many arguments in call to svc.BackupSecret`.

- [ ] **Step 3: Rewrite `BackupSecret`**

Replace `internal/backup/item_backup.go:53-66`:

```go
// BackupSecret creates a base64url-encoded backup blob for the given secret.
//
// vaultID is the vault the caller's request was authorized against. See
// BackupKey for why the scoped read replaces the previous unscoped read plus
// ownership comparison.
func (s *ItemBackupService) BackupSecret(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	secret, err := s.secretRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup secret: %w", err)
	}
	return encodeBlob("secret", id.String(), secret, nil)
}
```

- [ ] **Step 4: Update the handler**

In `api/backup_item.go`, `backupSecretHandler` (line 79): insert the `vaultIDFromRequest` block after the `getUserID` block, and replace the call and its error branch:

```go
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	blob, err := svc.BackupSecret(r.Context(), secretID, userID, vaultID)
	if err != nil {
		c.SetNotFound("secret")
		return
	}
```

- [ ] **Step 5: Update the remaining call sites**

Find them: `grep -rn "BackupSecret(" internal/backup/ api/ | grep -v item_backup.go`

Append a fourth argument to each. Where the fixture has no vault, use `uuid.Nil` and set `VaultID: uuid.Nil` on the fixture. `api/backup_item_test.go:453` and `:554` become:

```go
	blob, err := svc.BackupSecret(context.Background(), secretID, userID, uuid.Nil)
```

```go
	blob, err := blobSvc.BackupSecret(context.Background(), secretID, userID, uuid.Nil)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go build ./... && go test ./internal/backup/ ./api/ 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/backup/item_backup.go api/backup_item.go internal/backup/item_backup_test.go internal/backup/backup_edge_test.go api/backup_item_test.go
git commit -m "fix(backup): authorize secret backup by vault scope instead of ownership"
```

---

### Task 3: Vault-scope `BackupCertificate`

**Files:**
- Modify: `internal/backup/item_backup.go:141-154` (`BackupCertificate`)
- Modify: `api/backup_item.go:220-250` (`backupCertificateHandler`)
- Modify: `internal/backup/backup_edge_test.go` (`TestBackupCertificateForbidden` at line 222, plus calls at 217, 249, 267, 304)
- Modify: `api/backup_item_test.go:1036`

**Interfaces:**
- Consumes: `CertificateRepositoryInterface.Read(ctx, id, scope) (*model.Certificate, error)`; `model.NewVaultScope`.
- Produces: `ItemBackupService.BackupCertificate(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error)`.

- [ ] **Step 1: Write the failing test**

Add a `LastReadScope model.Scope` field to the certificate stub repo and record it in its `Read`, as in Tasks 1 and 2. Then replace `TestBackupCertificateForbidden` (line 222) with:

```go
func TestBackupCertificateNonOwnerInSameVaultSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	certID := uuid.New()

	// stubCertRepo has no Create; TestBackupCertificateSuccess (line 203)
	// populates its map directly, and this mirrors that.
	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: ownerID, VaultID: vaultID, Name: "my-cert",
	}

	svc := backup.NewItemBackupService(nil, nil, cr)

	blob, err := svc.BackupCertificate(ctx, certID, callerID, vaultID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
	require.Equal(t, model.NewVaultScope(vaultID, callerID), cr.LastReadScope)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/backup/ -run TestBackupCertificateNonOwnerInSameVaultSucceeds -v`
Expected: **build failure**, `too many arguments in call to svc.BackupCertificate`.

- [ ] **Step 3: Rewrite `BackupCertificate`**

Replace `internal/backup/item_backup.go:141-154`:

```go
// BackupCertificate creates a base64url-encoded backup blob for the given
// certificate.
//
// vaultID is the vault the caller's request was authorized against. See
// BackupKey for why the scoped read replaces the previous unscoped read plus
// ownership comparison.
func (s *ItemBackupService) BackupCertificate(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	cert, err := s.certRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup certificate: %w", err)
	}
	return encodeBlob("certificate", id.String(), cert, nil)
}
```

- [ ] **Step 4: Update the handler**

In `api/backup_item.go`, `backupCertificateHandler` (line 220): insert the `vaultIDFromRequest` block after `getUserID`, then:

```go
	blob, err := svc.BackupCertificate(r.Context(), certID, userID, vaultID)
	if err != nil {
		c.SetNotFound("certificate")
		return
	}
```

- [ ] **Step 5: Update the remaining call sites**

Find them: `grep -rn "BackupCertificate(" internal/backup/ api/ | grep -v item_backup.go`

Append a fourth argument to each (`uuid.Nil` where the fixture has no vault, with `VaultID: uuid.Nil` on the fixture). `api/backup_item_test.go:1036` becomes:

```go
	blob, err := svc.BackupCertificate(context.Background(), certID, userID, uuid.Nil)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go build ./... && go test ./internal/backup/ ./api/ 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/backup/item_backup.go api/backup_item.go internal/backup/backup_edge_test.go api/backup_item_test.go
git commit -m "fix(backup): authorize certificate backup by vault scope instead of ownership"
```

---

### Task 4: Remove the now-unreachable `ErrForbidden`

**Files:**
- Modify: `internal/backup/item_backup.go:16-17` (the var)
- Modify: `api/backup_item.go:98, 136, 169, 207, 240, 278` (six branches)

**Interfaces:**
- Consumes: nothing new.
- Produces: removal of the exported `backup.ErrForbidden` symbol. Nothing outside `internal/backup` and `api/backup_item.go` references it — verified with `grep -rn "ErrForbidden" --include="*.go" .`, which returns only those two files plus their tests.

- [ ] **Step 1: Confirm nothing produces it any more**

Run: `grep -rn "ErrForbidden" --include="*.go" .`

Expected after Tasks 1-3: the `var` declaration in `item_backup.go:17`, six `errors.Is(err, backup.ErrForbidden)` branches in `api/backup_item.go`, and any test references — and **no** `return "", ErrForbidden` anywhere. The three restore methods never returned it either, so all six branches are dead.

If any `return ... ErrForbidden` remains, a Task 1-3 step was missed; go back rather than continuing.

- [ ] **Step 2: Delete the variable**

Remove lines 16-17 of `internal/backup/item_backup.go`:

```go
// ErrForbidden is returned when a user attempts to access a resource they do not own.
var ErrForbidden = errors.New("forbidden")
```

`errors` is still imported for `ErrInvalidBlob` on the next line, so leave the import block alone.

- [ ] **Step 3: Delete the six dead branches**

In `api/backup_item.go`, the three backup handlers already lost theirs in Tasks 1-3. Each of the three **restore** handlers still has a `case errors.Is(err, backup.ErrForbidden): c.SetPermissionError("cannot restore: forbidden")` arm — that arm was never reachable, since no `Restore*` method ever returned `ErrForbidden`. Remove it from `restoreSecretHandler` (line 136), `restoreKeyHandler` (line 207), and `restoreCertificateHandler` (line 278), leaving each switch as:

```go
		switch {
		case errors.Is(err, backup.ErrInvalidBlob):
			c.SetInvalidParam("blob")
		default:
			c.SetInternalError(err)
		}
```

- [ ] **Step 4: Remove test references**

Run: `grep -rn "ErrForbidden\|\"forbidden\"" internal/backup/*_test.go api/backup_item_test.go`

Delete any assertion that a `Backup*` or `Restore*` call returns "forbidden". Tasks 1-3 already removed the three `*Forbidden` tests; this catches any stragglers.

- [ ] **Step 5: Run the full suite**

Run: `go build ./... && go vet ./internal/backup/ ./api/ && go test ./... 2>&1 | grep -v "^ok" | head -20`
Expected: no build errors, no vet findings, no test failures.

- [ ] **Step 6: Commit**

```bash
git add internal/backup/item_backup.go api/backup_item.go internal/backup/item_backup_test.go internal/backup/backup_edge_test.go api/backup_item_test.go
git commit -m "refactor(backup): drop the unreachable ErrForbidden path"
```

---

### Task 5: Correct the parity doc and record the change

**Files:**
- Modify: `.claude/azure-keyvault-parity.md` (§2 `Backup / Restore` row at line 48; §2 Summary bullet at lines 468-489)
- Modify: `.claude/known-bugs.md` (append a new numbered entry)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Replace the §2 row**

In `.claude/azure-keyvault-parity.md`, replace the `Backup / Restore` row (line 48) with:

```
| Backup / Restore | ✅ | ✅ `POST /keys/{id}/backup`, `/keys/restore`, registered on both the flat and vault-scoped routers (`api/backup_item.go` `InitBackupItem`). Authorization is the RBAC data action in `PolicyMiddleware` plus a `model.NewVaultScope` read in `ItemBackupService` — a Crypto User with `ActionKeysBackup` can back up any key in a vault they are authorized for, and cannot name a key outside it. Key backups carry `key_versions` history, so a rotated key survives a backup/restore cycle with its archived versions intact | ✅ |
```

- [ ] **Step 2: Add the dated correction note**

Append to §2's note block:

```
*Corrected 2026-08-19 (fifth pass): the "Backup / Restore" row above carried two
claims that were each wrong in a different direction. **(1)** Stale: it said
backup/restore was "registered on the flat routes only ... so
`/vaults/{name}/keys/{id}/backup` 404s". Commit `03badab` had already attached
all six routes to `BaseRoutes.VaultScoped`; `api/backup_item.go:21-27` shows the
registration. **(2)** Real, and now fixed: `BackupKey` gated on
`key.UserID == caller` on top of `ActionKeysBackup`, refusing a Crypto User who
legitimately held the action without owning the key — and the same gate existed
in `BackupSecret` and `BackupCertificate`, which the row never mentioned. All
three now read with `model.NewVaultScope(vaultID, userID)` instead of an
unscoped admin read plus an ownership comparison. That swap also closed a
latent cross-vault read the ownership check had been incidentally covering; see
`.claude/known-bugs.md` § B29.*
```

- [ ] **Step 3: Update the Summary bullet**

In the `**Partial (🟡):**` section's `Key operations beyond CRUD` bullet, replace *"Key backup/restore is still registered on the flat routes only (404s on the vault-scoped path) and is still additionally owner-gated on top of the RBAC check, but a backed-up and restored key now keeps its `key_versions` history instead of silently losing it (also part of the 2026-08-19 fix)."* with:

```
  Key backup/restore is fully at parity: registered on both route shapes,
  authorized by the RBAC data action plus a vault scope rather than item
  ownership, and carrying `key_versions` history across a backup/restore
  cycle.
```

- [ ] **Step 4: Add a known-bugs entry**

Append to `.claude/known-bugs.md`, using the next free section number:

```markdown
## B29 — Item backup gated on ownership, and unscoped underneath it

**Status:** Fixed 2026-08-19.

**Symptom (the visible half):** a caller holding `ActionKeysBackup` in a vault
could not back up a key in that vault unless they also owned it.
`ItemBackupService.BackupKey` returned `ErrForbidden` → HTTP 403. The same gate
existed in `BackupSecret` and `BackupCertificate`. Azure's Crypto User grants
`keys/backup/action` with no ownership concept at all, so this was a real
parity gap for every non-owner role.

**Symptom (the hidden half):** the read beneath that gate used
`model.NewAdminScope(userID)`, which carries no predicate — the code said so:
*"The read itself is unchecked (admin scope); the explicit ownership check
below is the actual gate."* `PolicyMiddleware` authorizes the *request* against
the route's vault, but nothing confirmed the named *item* lived in it. The
ownership check was therefore the only thing preventing a caller authorized in
the `default` vault from backing up an item in another vault by ID. Deleting
the check to fix the visible half — the obvious reading of the parity finding —
would have opened that path.

**Fix:** all three `Backup*` methods take the request's authorized `vaultID`
(resolved by `vaultIDFromRequest`, exactly as the three `Restore*` methods
already did since `c5bf97d`) and read with `model.NewVaultScope(vaultID,
userID)`. The repository's scope predicate is now the single enforcement point.
An out-of-scope ID reports 404, matching every other scoped resource route.

**Bundled fix:** `BackupKey` passed the *caller's* ID to
`KeyRepository.ListVersionRecords`, whose query joins `k.user_id = ?`. That was
safe only while caller == owner was guaranteed. Once a non-owner can back up, it
would have returned zero rows and dropped the key's rotation history from the
blob with no error — silently reintroducing the history loss § B26 closed. It
now passes `key.UserID` from the key it just read.

**Also removed:** `backup.ErrForbidden` and its six `errors.Is` branches in
`api/backup_item.go`. Nothing produced it after this change, and the three
restore-handler branches had never been reachable — no `Restore*` method ever
returned it.

**Pinned by:** `TestBackupKeyNonOwnerInSameVaultSucceeds`,
`TestBackupKeyReadsWithVaultScope`,
`TestBackupSecretNonOwnerInSameVaultSucceeds`,
`TestBackupCertificateNonOwnerInSameVaultSucceeds`
(`internal/backup/backup_edge_test.go`, `internal/backup/item_backup_test.go`).
```

- [ ] **Step 5: Commit**

```bash
git add .claude/azure-keyvault-parity.md .claude/known-bugs.md
git commit -m "docs: record the vault-scoped backup fix and correct the stale route claim"
```
