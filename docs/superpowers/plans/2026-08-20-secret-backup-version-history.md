# Secret Backup Version History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `POST /secrets/{id}/backup` carry a secret's version history and `POST /secrets/restore` replay it, so a backup/restore cycle stops silently discarding every prior version — matching what key backup has done since 2026-08-19.

**Architecture:** The machinery already exists on both ends: `SecretVersionRepositoryInterface.GetVersions` / `.CreateVersion` (`internal/repositories/versioning_repository.go:22-23`). What is missing is wiring. `ItemBackupService` gains the version repository as a fourth dependency, the blob envelope gains an additive `secret_versions` field, and `RestoreSecret` replays rows under the new secret's ID — exactly the shape `RestoreKey` already uses (`internal/backup/item_backup.go:133-137`).

**Tech Stack:** Go 1.24, `database/sql` over SQLite (dev) / PostgreSQL (prod), testify.

**Spec:** No separate design doc. The finding comes from the 2026-08-19 whole-branch review of `docs/superpowers/plans/2026-08-19-item-backup-vault-scoped-authz.md`: *"`BackupSecret` passes `nil` versions; Azure's secret backup restores all versions. The asymmetry is newly conspicuous now that the key path is explicit about it, and it is the same class of silent-loss bug that B26 closed for keys."* Design decisions are stated inline below.

## The defect

`BackupSecret` (`internal/backup/item_backup.go:60`) ends:

```go
	return encodeBlob("secret", id.String(), secret, nil)
```

That `nil` is the whole bug. `model.Secret` carries a `Version int` column — the *current* version number — but the historical values live in the `secret_versions` table, which the blob never touches. Back up a secret with ten versions, restore it, and you get one version with no error and no warning. This is the same failure `.claude/known-bugs.md` § B26 closed for keys, where a rotated key's archived material was silently lost across a backup/restore cycle.

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Envelope field | New `secret_versions` field, `omitempty`, alongside the existing `versions` (keys) | Additive and `omitempty`, so every blob taken before this change still decodes with a nil slice — the exact back-compat property the key `versions` field was added with, and already pinned by `TestRestoreKey_OldFormatBlob_NoVersionsField`. Reusing the key field for secrets would break that test's blob and conflate two different record types. |
| `encodeBlob`/`decodeBlob` signature | Replace the trailing `[]model.KeyVersionRecord` with a small `blobVersions` struct carrying both slices | The alternative — a fifth positional parameter — gives `encodeBlob(rt, rid, data, keyVersions, secretVersions)`, where every secret call passes `nil` in slot four and every key call passes `nil` in slot five. A named struct keeps one call shape and leaves room for certificates later without another signature churn. |
| Version IDs on restore | Mint a fresh `uuid.New()` per replayed row | `secret_versions.id` is a `PRIMARY KEY` (`internal/db/db.go:564`). Reusing the blob's IDs collides the moment the original secret still exists — which is the common case, since restore creates a *new* secret rather than overwriting. `RestoreKey` sidesteps this only because `key_versions` has no independent ID column. |
| Version ownership on restore | Rewrite `SecretID` to the new secret and `UserID` to the restoring caller | Mirrors `RestoreSecret`'s existing treatment of the parent row (`item_backup.go:78-80`), and `secret_versions.user_id` carries a real FK to `users(id)` (`db.go:572`), enforced on PostgreSQL. Carrying the blob's original `UserID` would reference a user that may not exist in the target deployment. |
| Where versions are read | `SecretVersionRepositoryInterface`, injected into `ItemBackupService` | Keeps `ItemBackupService`'s existing shape: it holds repositories, not services. The version repo takes no scope by design — the caller has already authorized the parent secret. |
| Certificates | Out of scope | Certificates have no version table at all. Adding one is a feature, not a gap in backup. |

## Global Constraints

- **Backward compatibility is non-negotiable.** A blob produced before this change must restore exactly as it does today. `TestRestoreKey_OldFormatBlob_NoVersionsField` must pass untouched, and an equivalent assertion must exist for secrets.
- **The `versions` JSON field keeps its name and type.** Key backups are unaffected by this plan; do not rename, retype, or reorder that field.
- **A secret backup blob now carries every historical secret value.** `model.SecretVersion.Value` is the master-key-encrypted value, so the blob becomes exactly as sensitive as a key backup blob. `model.KeyVersionRecord` already carries a warning comment about this (`model/key.go:64-72`); `model.SecretVersion` must gain the equivalent. Do not skip this — it is the reason the type is safe to serialize at all.
- **No authorization change.** `BackupSecret` reads with `model.NewVaultScope(vaultID, userID)`; version rows are fetched by secret ID after that read authorizes the parent. Do not add a scope parameter to the version repository.
- **No new HTTP routes, no route changes, no CLI changes.**
- **Go 1.24, existing dependencies only.**

## File structure

| File | Responsibility |
|---|---|
| `model/secret.go` (modify) | Warning comment on `SecretVersion` about blob sensitivity |
| `internal/backup/item_backup.go` (modify) | `blobVersions` type, envelope field, `encodeBlob`/`decodeBlob`, `ItemBackupService` dependency, `BackupSecret`, `RestoreSecret` |
| `internal/container/service_container.go:573` (modify) | Pass `c.versionRepository` into the constructor |
| `internal/backup/item_backup_test.go`, `backup_edge_test.go` (modify) | Constructor call sites; new round-trip tests |
| `api/backup_item_test.go` (modify) | Constructor call sites |
| `.claude/azure-keyvault-parity.md`, `.claude/known-bugs.md` (modify) | §1 row + new entry |

---

### Task 1: Generalize the blob envelope to carry two kinds of version record

**Files:**
- Modify: `internal/backup/item_backup.go` — `backupEnvelope` (`:43-48`), `encodeBlob` (`:182`) and `decodeBlob` (`:202`), and their six call sites (`:60`, `:70`, `:111`, `:118`, `:153`, `:161`)
- Test: `internal/backup/item_backup_test.go`

> Line numbers throughout this plan are indicative and drift as earlier steps
> edit the file. Locate each site by its function name or by `grep -n
> "encodeBlob(\|decodeBlob(" internal/backup/item_backup.go`, not by line
> number. Every one of these is a compile error if missed, so the compiler
> is the backstop.

**Interfaces:**
- Produces: `blobVersions{Key []model.KeyVersionRecord; Secret []model.SecretVersion}`; `encodeBlob(resourceType, resourceID string, data interface{}, versions blobVersions) (string, error)`; `decodeBlob(blob, expectedType string, out interface{}) (blobVersions, error)`. Tasks 2 and 3 consume exactly these.

- [ ] **Step 1: Write the failing test**

Append to `internal/backup/item_backup_test.go`:

```go
// TestBlobEnvelope_SecretVersionsRoundTrip pins the new envelope field.
func TestBlobEnvelope_SecretVersionsRoundTrip(t *testing.T) {
	t.Parallel()

	secretID := uuid.New()
	versions := []model.SecretVersion{
		{ID: uuid.New(), SecretID: secretID, UserID: uuid.New(), Name: "s", Value: "enc-v1", Version: 1},
		{ID: uuid.New(), SecretID: secretID, UserID: uuid.New(), Name: "s", Value: "enc-v2", Version: 2},
	}

	blob, err := backup.ExportedEncodeBlob("secret", secretID.String(),
		&model.Secret{ID: secretID, Name: "s"},
		backup.ExportedBlobVersions{Secret: versions})
	require.NoError(t, err)

	var out model.Secret
	got, err := backup.ExportedDecodeBlob(blob, "secret", &out)
	require.NoError(t, err)
	require.Len(t, got.Secret, 2)
	require.Equal(t, "enc-v1", got.Secret[0].Value)
	require.Empty(t, got.Key, "a secret blob carries no key version records")
}

// TestBlobEnvelope_KeyVersionsUnaffected proves this refactor did not disturb
// the key path's existing field.
func TestBlobEnvelope_KeyVersionsUnaffected(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	blob, err := backup.ExportedEncodeBlob("key", keyID.String(),
		&model.Key{ID: keyID, Name: "k"},
		backup.ExportedBlobVersions{Key: []model.KeyVersionRecord{{KeyID: keyID, Version: 1, Value: "enc"}}})
	require.NoError(t, err)

	var out model.Key
	got, err := backup.ExportedDecodeBlob(blob, "key", &out)
	require.NoError(t, err)
	require.Len(t, got.Key, 1)
	require.Empty(t, got.Secret)
}
```

`encodeBlob`, `decodeBlob`, and `blobVersions` are unexported and these tests live in the external `backup_test` package. Rather than exporting production symbols for tests, add an **`export_test.go`** in `internal/backup/` (the standard Go idiom — the file is only compiled during tests):

```go
package backup

// Test-only aliases. This file is compiled only under `go test`, so these
// export nothing to production consumers.

type ExportedBlobVersions = blobVersions

var (
	ExportedEncodeBlob = encodeBlob
	ExportedDecodeBlob = decodeBlob
)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/backup/ -run TestBlobEnvelope -v`
Expected: **build failure** — `undefined: blobVersions` (from `export_test.go`).

- [ ] **Step 3: Add `blobVersions` and the envelope field**

In `internal/backup/item_backup.go`, replace the `backupEnvelope` block (`:45-51`):

```go
// blobVersions carries whatever version history a resource type has. Both
// fields are optional: a key blob populates Key, a secret blob populates
// Secret, and a certificate blob populates neither (certificates have no
// version table).
type blobVersions struct {
	Key    []model.KeyVersionRecord
	Secret []model.SecretVersion
}

// backupEnvelope is the internal structure stored inside the opaque blob.
//
// Both version fields are omitempty and additive: a blob written before a
// given field existed simply decodes it as nil. That is what lets pre-2026-08
// key blobs and pre-2026-08-20 secret blobs still restore. Never rename or
// retype an existing field here -- it is a wire format.
type backupEnvelope struct {
	ResourceType   string                   `json:"resource_type"`
	ResourceID     string                   `json:"resource_id"`
	Data           json.RawMessage          `json:"data"`
	Versions       []model.KeyVersionRecord `json:"versions,omitempty"`        // keys only
	SecretVersions []model.SecretVersion    `json:"secret_versions,omitempty"` // secrets only
}
```

- [ ] **Step 4: Change `encodeBlob` and `decodeBlob`**

Replace both functions (`:182-218`):

```go
// encodeBlob marshals data into a JSON envelope and base64url-encodes it.
// versions carries whatever history the resource type has; a zero blobVersions
// means none, and both envelope fields are then omitted.
func encodeBlob(resourceType, resourceID string, data interface{}, versions blobVersions) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal data: %w", err)
	}
	envelope, err := json.Marshal(backupEnvelope{
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Data:           raw,
		Versions:       versions.Key,
		SecretVersions: versions.Secret,
	})
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return base64.URLEncoding.EncodeToString(envelope), nil
}

// decodeBlob base64url-decodes a blob and unmarshals the envelope into out.
// The returned blobVersions is zero for a resource type with no history, and
// zero for a blob encoded before the corresponding field existed -- both
// fields are purely additive.
func decodeBlob(blob, expectedType string, out interface{}) (blobVersions, error) {
	var none blobVersions

	raw, err := base64.URLEncoding.DecodeString(blob)
	if err != nil {
		return none, fmt.Errorf("%w: invalid encoding: %w", ErrInvalidBlob, err)
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return none, fmt.Errorf("%w: invalid format: %w", ErrInvalidBlob, err)
	}
	if envelope.ResourceType != expectedType {
		return none, fmt.Errorf("%w: type mismatch: expected %s, got %s", ErrInvalidBlob, expectedType, envelope.ResourceType)
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return none, err
	}
	return blobVersions{Key: envelope.Versions, Secret: envelope.SecretVersions}, nil
}
```

- [ ] **Step 5: Update the six call sites**

Mechanical. `BackupSecret` (`:55`) and `BackupCertificate` (`:148`) pass a zero value:

```go
	return encodeBlob("secret", id.String(), secret, blobVersions{})
```
```go
	return encodeBlob("certificate", id.String(), cert, blobVersions{})
```

`BackupKey` (`:111`):

```go
	return encodeBlob("key", id.String(), key, blobVersions{Key: versions})
```

The three `decodeBlob` callers change their receiving variable. `RestoreSecret` (`:70`) and `RestoreCertificate` (`:161`) currently discard it with `_`; leave them discarding for now — Task 3 wires the secret one:

```go
	if _, err := decodeBlob(blob, "secret", &secret); err != nil {
```

`RestoreKey` (`:118`) now receives the struct:

```go
	versions, err := decodeBlob(blob, "key", &key)
	if err != nil {
		return err
	}
```

and its replay loop at `:134` becomes:

```go
	for _, v := range versions.Key {
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go build ./... && go test ./internal/backup/ ./api/ -count=1 -v -run 'TestBlobEnvelope|Backup|Restore' 2>&1 | tail -25`

Expected: PASS, including `TestBackupRestoreKey_CarriesVersionHistory` and `TestRestoreKey_OldFormatBlob_NoVersionsField` — the two that prove the key path and its back-compat survived this refactor untouched.

- [ ] **Step 7: Commit**

```bash
git add internal/backup/item_backup.go internal/backup/export_test.go internal/backup/item_backup_test.go
git commit -m "refactor(backup): generalize the blob envelope to carry per-resource version history"
```

---

### Task 2: Collect secret versions into the backup blob

**Files:**
- Modify: `model/secret.go` (warning comment on `SecretVersion`)
- Modify: `internal/backup/item_backup.go:22-43` (struct + constructor), `:55-61` (`BackupSecret`)
- Modify: `internal/container/service_container.go:573`
- Modify: every `NewItemBackupService(` call site in tests
- Test: `internal/backup/item_backup_test.go`

**Interfaces:**
- Consumes: `blobVersions` and `encodeBlob` from Task 1; `repositories.SecretVersionRepositoryInterface.GetVersions(ctx, secretID uuid.UUID) ([]model.SecretVersion, error)`.
- Produces: `NewItemBackupService(secretRepo, keyRepo, certRepo, versionRepo)` — a fourth parameter. Task 3 relies on the `versionRepo` field existing.

- [ ] **Step 1: Write the failing test**

Append to `internal/backup/item_backup_test.go`. The existing `stubSecretRepo` does not implement the version repository, so add a small stub for it in the same file, modelled on the others:

```go
// stubSecretVersionRepo is a minimal in-memory SecretVersionRepositoryInterface.
type stubSecretVersionRepo struct {
	versions map[uuid.UUID][]model.SecretVersion
}

func newStubSecretVersionRepo() *stubSecretVersionRepo {
	return &stubSecretVersionRepo{versions: make(map[uuid.UUID][]model.SecretVersion)}
}

func (r *stubSecretVersionRepo) CreateVersion(_ context.Context, v *model.SecretVersion) error {
	r.versions[v.SecretID] = append(r.versions[v.SecretID], *v)
	return nil
}

func (r *stubSecretVersionRepo) GetVersions(_ context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	return r.versions[secretID], nil
}

func (r *stubSecretVersionRepo) GetVersion(_ context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	for i := range r.versions[secretID] {
		if r.versions[secretID][i].Version == version {
			return &r.versions[secretID][i], nil
		}
	}
	return nil, sql.ErrNoRows
}

func (r *stubSecretVersionRepo) GetLatestVersion(_ context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	list := r.versions[secretID]
	if len(list) == 0 {
		return nil, sql.ErrNoRows
	}
	return &list[len(list)-1], nil
}

func (r *stubSecretVersionRepo) DeleteVersions(_ context.Context, secretID uuid.UUID) error {
	delete(r.versions, secretID)
	return nil
}

func (r *stubSecretVersionRepo) DeleteSpecificVersion(_ context.Context, secretID uuid.UUID, version int) error {
	kept := r.versions[secretID][:0]
	for _, v := range r.versions[secretID] {
		if v.Version != version {
			kept = append(kept, v)
		}
	}
	r.versions[secretID] = kept
	return nil
}

func TestBackupSecret_CarriesVersionHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID,
		Name: "db-password", Value: "enc-v3", Version: 3, Enabled: true,
	}))

	vr := newStubSecretVersionRepo()
	for i := 1; i <= 2; i++ {
		require.NoError(t, vr.CreateVersion(ctx, &model.SecretVersion{
			ID: uuid.New(), SecretID: secretID, UserID: ownerID,
			Name: "db-password", Value: fmt.Sprintf("enc-v%d", i), Version: i,
		}))
	}

	svc := backup.NewItemBackupService(repo, nil, nil, vr)

	blob, err := svc.BackupSecret(ctx, secretID, ownerID, vaultID)
	require.NoError(t, err)

	var restored model.Secret
	got, err := backup.ExportedDecodeBlob(blob, "secret", &restored)
	require.NoError(t, err)
	require.Len(t, got.Secret, 2, "both archived versions must reach the blob")
	require.Equal(t, "enc-v1", got.Secret[0].Value)
	require.Equal(t, "enc-v2", got.Secret[1].Value)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/backup/ -run TestBackupSecret_CarriesVersionHistory -v`
Expected: **build failure** — `too many arguments in call to backup.NewItemBackupService`.

- [ ] **Step 3: Add the warning comment to `model.SecretVersion`**

In `model/secret.go`, above `type SecretVersion struct` (line 90):

```go
// SecretVersion is one archived version of a secret. Value carries the same
// master-key-encrypted form the database stores.
//
// This type IS marshaled into a secret backup blob, which
// POST /secrets/{id}/backup returns in its response body as a merely
// base64url-encoded (not encrypted) JSON envelope. A secret backup blob
// therefore contains every historical value of that secret and must be
// handled as secret material -- the same warning model.KeyVersionRecord
// carries for keys.
```

- [ ] **Step 4: Add the dependency**

In `internal/backup/item_backup.go`, extend the struct and constructor:

```go
type ItemBackupService struct {
	secretRepo  repositories.SecretRepositoryInterface
	keyRepo     repositories.KeyRepositoryInterface
	certRepo    repositories.CertificateRepositoryInterface
	versionRepo repositories.SecretVersionRepositoryInterface
}

// NewItemBackupService creates an ItemBackupService wired to the given repos.
// Any repo may be nil if that resource type is not required by the caller.
func NewItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *ItemBackupService {
	return &ItemBackupService{
		secretRepo:  secretRepo,
		keyRepo:     keyRepo,
		certRepo:    certRepo,
		versionRepo: versionRepo,
	}
}
```

- [ ] **Step 5: Collect the versions in `BackupSecret`**

```go
func (s *ItemBackupService) BackupSecret(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	secret, err := s.secretRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup secret: %w", err)
	}

	// Version rows are fetched by secret ID; the scoped read above is their
	// authorization. Without these the blob would restore a single version and
	// silently discard the rest -- the same loss B26 closed for keys.
	versions, err := s.versionRepo.GetVersions(ctx, id)
	if err != nil {
		return "", fmt.Errorf("backup secret: list versions: %w", err)
	}
	return encodeBlob("secret", id.String(), secret, blobVersions{Secret: versions})
}
```

- [ ] **Step 6: Update the container and every test call site**

`internal/container/service_container.go:573`:

```go
	c.itemBackupService = backup.NewItemBackupService(
		c.secretRepository,
		c.keyRepository,
		c.certificateRepository,
		c.versionRepository,
	)
```

(`c.versionRepository` is declared at `:147` and constructed at `:279`, before this point — verify that ordering holds before relying on it.)

Then find every other call site: `grep -rn "NewItemBackupService(" --include="*.go" . | grep -v worktrees`

Each test that does not exercise secrets passes `nil` as the fourth argument, matching how those tests already pass `nil` for repos they do not use.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go build ./... && go test ./internal/backup/ ./api/ -count=1 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add -u
git commit -m "feat(backup): carry secret version history into the backup blob"
```

---

### Task 3: Replay secret versions on restore

**Files:**
- Modify: `internal/backup/item_backup.go` (`RestoreSecret`)
- Test: `internal/backup/item_backup_test.go`

**Interfaces:**
- Consumes: `blobVersions.Secret` from Task 1; the `versionRepo` field from Task 2; `SecretVersionRepositoryInterface.CreateVersion(ctx, *model.SecretVersion) error`.
- Produces: nothing consumed downstream.

- [ ] **Step 1: Write the failing test**

Append to `internal/backup/item_backup_test.go`:

```go
func TestBackupRestoreSecret_CarriesVersionHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID,
		Name: "db-password", Value: "enc-v3", Version: 3, Enabled: true,
	}))

	vr := newStubSecretVersionRepo()
	for i := 1; i <= 2; i++ {
		require.NoError(t, vr.CreateVersion(ctx, &model.SecretVersion{
			ID: uuid.New(), SecretID: secretID, UserID: ownerID,
			Name: "db-password", Value: fmt.Sprintf("enc-v%d", i), Version: i,
		}))
	}

	svc := backup.NewItemBackupService(repo, nil, nil, vr)

	blob, err := svc.BackupSecret(ctx, secretID, ownerID, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	restorerID := uuid.New()
	newVaultID := uuid.New()
	require.NoError(t, svc.RestoreSecret(ctx, blob, restorerID, newVaultID, newID))

	restoredVersions, err := vr.GetVersions(ctx, newID)
	require.NoError(t, err)
	require.Len(t, restoredVersions, 2, "restore must replay the archived versions")

	for _, v := range restoredVersions {
		require.Equal(t, newID, v.SecretID, "versions must attach to the NEW secret")
		require.Equal(t, restorerID, v.UserID, "versions must belong to the restoring user")
		require.NotEqual(t, uuid.Nil, v.ID)
	}
	require.NotEqual(t, restoredVersions[0].ID, restoredVersions[1].ID,
		"each replayed version needs its own primary key")
}

// TestRestoreSecret_OldFormatBlob_NoVersionsField proves back-compat: a blob
// written before the secret_versions field existed must still restore.
func TestRestoreSecret_OldFormatBlob_NoVersionsField(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secretID := uuid.New()

	// Hand-built envelope with no secret_versions key at all.
	raw, err := json.Marshal(map[string]any{
		"resource_type": "secret",
		"resource_id":   secretID.String(),
		"data":          json.RawMessage(`{"id":"` + secretID.String() + `","name":"legacy","value":"enc","version":1}`),
	})
	require.NoError(t, err)
	blob := base64.URLEncoding.EncodeToString(raw)

	repo := newStubSecretRepo()
	vr := newStubSecretVersionRepo()
	svc := backup.NewItemBackupService(repo, nil, nil, vr)

	newID := uuid.New()
	require.NoError(t, svc.RestoreSecret(ctx, blob, uuid.New(), uuid.New(), newID),
		"a pre-versions blob must still restore")

	versions, err := vr.GetVersions(ctx, newID)
	require.NoError(t, err)
	require.Empty(t, versions)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/backup/ -run 'TestBackupRestoreSecret_CarriesVersionHistory|TestRestoreSecret_OldFormatBlob' -v`

Expected: `TestBackupRestoreSecret_CarriesVersionHistory` FAILS with `Not equal: expected: 2, actual: 0` — the blob now carries versions (Task 2) but restore still ignores them. `TestRestoreSecret_OldFormatBlob_NoVersionsField` passes already; it is the back-compat guard.

- [ ] **Step 3: Replay the versions in `RestoreSecret`**

```go
// RestoreSecret decodes blob and re-inserts it as newID, owned by userID,
// into vaultID -- the vault authorized by the caller's request, never the
// vault embedded in the blob. Trusting the blob's vault_id would let a
// caller with restore permission in one vault silently write into any vault
// a blob happens to reference.
//
// Archived versions in the blob are replayed under newID. Each gets a fresh
// primary key: secret_versions.id is a PRIMARY KEY, and the source secret
// usually still exists, so reusing the blob's IDs would collide.
func (s *ItemBackupService) RestoreSecret(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var secret model.Secret
	versions, err := decodeBlob(blob, "secret", &secret)
	if err != nil {
		return err
	}
	secret.ID = newID
	secret.UserID = userID
	secret.VaultID = vaultID
	if err := s.secretRepo.Create(ctx, &secret); err != nil {
		return err
	}
	// Create does not write purge_protection, so a protected item would be
	// restored unprotected. Re-apply the blob's flag as a second write.
	if secret.PurgeProtection {
		if err := s.secretRepo.SetPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore secret: set purge protection: %w", err)
		}
	}
	for _, v := range versions.Secret {
		v.ID = uuid.New()
		v.SecretID = newID
		v.UserID = userID
		if err := s.versionRepo.CreateVersion(ctx, &v); err != nil {
			return fmt.Errorf("restore secret: create version %d: %w", v.Version, err)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/backup/ -run 'TestBackupRestoreSecret_CarriesVersionHistory|TestRestoreSecret_OldFormatBlob' -v`
Expected: PASS.

Run: `go build ./... && go vet ./... && go test ./... -count=1 2>&1 | grep -v "^ok" | head -20`
Expected: no failures.

- [ ] **Step 5: Commit**

```bash
git add -u
git commit -m "feat(backup): replay secret version history on restore"
```

---

### Task 4: Record the change

**Files:**
- Modify: `.claude/azure-keyvault-parity.md` (§1 "Per-secret backup / restore" row, line 32)
- Modify: `.claude/known-bugs.md` (new entry)

**Interfaces:** none.

- [ ] **Step 1: Update the §1 parity row**

Replace line 32's RocketVault cell:

```
| Per-secret backup / restore | ✅ | ✅ `POST /secrets/{id}/backup`, `/secrets/restore` — the blob carries the secret's full `secret_versions` history and restore replays it under the new secret ID (2026-08-20), matching Azure's per-version backup semantics | ✅ |
```

- [ ] **Step 2: Add a known-bugs entry**

Append to `.claude/known-bugs.md` using the next free `### Bnn` number — check the file for the highest and increment; do not reuse a number another unmerged branch has claimed. Match the structure of neighbouring entries (read `### B26` and `### B28` first).

```markdown
### B<nn> — Secret backup silently discarded every archived version

**Status:** Fixed 2026-08-20.

**Symptom:** `POST /secrets/{id}/backup` produced a blob containing only the
secret's current row. Restoring it yielded a secret with one version and no
error, no warning, and no way for the caller to notice the loss. A secret with
ten historical versions round-tripped as a secret with one.

**Root cause:** `ItemBackupService.BackupSecret` ended
`return encodeBlob("secret", id.String(), secret, nil)`. The `nil` was the
versions argument. `model.Secret` carries a `Version` *number*, which made the
blob look complete, but the historical values live in the separate
`secret_versions` table that the blob never read.

**Why it survived:** the identical defect on the key path was found and fixed
on 2026-08-19 (§ B26), but that work was scoped to keys; `BackupSecret`'s `nil`
was left in place and only became conspicuous once `BackupKey` was explicit
about carrying history. Nothing tested for the absence.

**Fix:** `ItemBackupService` takes `SecretVersionRepositoryInterface`;
`BackupSecret` reads `GetVersions` and puts them in a new additive
`secret_versions` envelope field; `RestoreSecret` replays them under the new
secret ID with fresh primary keys (`secret_versions.id` is a PRIMARY KEY and
the source secret usually still exists) and the restoring user's ID
(`secret_versions.user_id` is a real FK to `users`, enforced on PostgreSQL).

**Security note:** a secret backup blob now carries every historical secret
value, so it is exactly as sensitive as a key backup blob. `model.SecretVersion`
gained the warning comment `model.KeyVersionRecord` already carried.

**Back-compat:** the new field is `omitempty` and additive, so blobs taken
before this change decode with a nil slice and restore unchanged — pinned by
`TestRestoreSecret_OldFormatBlob_NoVersionsField`.

**Pinned by:** `TestBackupSecret_CarriesVersionHistory`,
`TestBackupRestoreSecret_CarriesVersionHistory`,
`TestRestoreSecret_OldFormatBlob_NoVersionsField`
(`internal/backup/item_backup_test.go`).
```

- [ ] **Step 3: Commit**

```bash
git add .claude/azure-keyvault-parity.md .claude/known-bugs.md
git commit -m "docs: record secret backup version-history support"
```
