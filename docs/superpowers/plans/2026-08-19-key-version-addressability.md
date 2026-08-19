# Key Version Addressability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make archived key versions usable in crypto operations
(sign/verify/encrypt/decrypt/wrap/unwrap), so ciphertexts and signatures
produced before a key rotation stay decryptable/verifiable, and add a
read-only single-version metadata endpoint for keys to match secrets.

**Architecture:** The archived material is already persisted in
`key_versions.value` on every rotation — this plan wires a read path for it
through the repository, service, and API layers, and extends key
backup/restore to carry that history so a restore doesn't silently lose it
again. No schema migration; version numbers are computed, not stored.

**Tech Stack:** Go, `database/sql` (SQLite/Postgres via `internal/db`),
`testify` (`assert`/`require`/`mock`), `mockery` for interface mocks,
`gorilla/mux` for routing.

**Spec:** `docs/superpowers/specs/2026-08-19-key-version-addressability-design.md`

## Global Constraints

- No schema migration — version numbers are computed (`MAX(key_versions.version)`,
  or implicitly `1` when a key has zero `key_versions` rows), never stored.
- Per-version lifecycle attributes (enable/disable/expiry per version) are
  **not** introduced. Revocation/enabled/expiry stay key-level.
- `model.KeyVersion` (the API-facing type) must never gain a `Value` field —
  material-carrying data uses the separate, internal-only
  `model.KeyVersionRecord` type, so the versions-list/versions-get endpoints
  cannot leak material even by future mistake.
- OCT (symmetric) keys are out of scope — `RotateKey` has no case for them
  today and this plan does not add one.
- `WrapKeyRequest`/`UnwrapKeyRequest`/`WrapKeyResponse`/`UnwrapKeyResponse`
  declared in `model/key.go:130-158` are pre-existing dead code (zero
  callers, confirmed via `grep -rn "model\.WrapKeyRequest\|model\.UnwrapKeyRequest"`)
  — do not touch them. The live types are in `api/keys.go:96-119` (HTTP) and
  `internal/services/keys/crypto_service.go:93-123` (service).
- Every task must leave `go build ./...`, `go vet ./...`, and the touched
  packages' tests green before moving to the next task.

---

### Task 1: Repository layer — version-aware reads

**Files:**
- Modify: `internal/repositories/key_repository.go`
- Create: `internal/repositories/key_version_errors.go`
- Modify: `model/key.go`
- Test: `internal/repositories/key_versions_test.go`

**Interfaces:**
- Consumes: existing `KeyRepository` (`internal/repositories/key_repository.go`),
  existing `model.KeyVersion{KeyID, Version, CreatedAt}`.
- Produces:
  - `repositories.ErrKeyVersionNotFound` (sentinel, propagates unwrapped to
    callers — same pattern as `repositories.ErrKeyPurgeProtected`).
  - `model.KeyVersionRecord{KeyID uuid.UUID, Version int, Value string, CreatedAt time.Time}`
    (new type, material-carrying, internal use only).
  - `KeyRepositoryInterface.ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (string, error)`
  - `KeyRepositoryInterface.GetVersion(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (*model.KeyVersion, error)`
  - `KeyRepositoryInterface.ListVersionRecords(ctx context.Context, keyID uuid.UUID, userID uuid.UUID) ([]model.KeyVersionRecord, error)`

- [ ] **Step 1: Write the failing tests**

Append to `internal/repositories/key_versions_test.go`:

```go
func TestKeyVersions_ReadVersionValue_ArchivedVersion(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v2", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))

	value, err := repo.ReadVersionValue(context.Background(), keyID, 1, userID)
	require.NoError(t, err)
	require.Equal(t, "pem-v1", value)
}

func TestKeyVersions_ReadVersionValue_ImplicitVersionOneFallback(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	// Never rotated: zero key_versions rows. Version 1 must fall back to keys.value.
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-original", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	value, err := repo.ReadVersionValue(context.Background(), keyID, 1, userID)
	require.NoError(t, err)
	require.Equal(t, "pem-original", value)
}

func TestKeyVersions_ReadVersionValue_NonexistentVersion(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v1", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	_, err := repo.ReadVersionValue(context.Background(), keyID, 5, userID)
	require.ErrorIs(t, err, repositories.ErrKeyVersionNotFound)
}

func TestKeyVersions_ReadVersionValue_WrongOwner(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	other := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v1", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	_, err := repo.ReadVersionValue(context.Background(), keyID, 1, other)
	require.ErrorIs(t, err, repositories.ErrKeyVersionNotFound)
}

func TestKeyVersions_GetVersion_ArchivedAndImplicit(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v1", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	// Implicit version 1 (never rotated) resolves from the key row.
	v, err := repo.GetVersion(context.Background(), keyID, 1, userID)
	require.NoError(t, err)
	require.Equal(t, 1, v.Version)
	require.Equal(t, keyID, v.KeyID)

	// Nonexistent version.
	_, err = repo.GetVersion(context.Background(), keyID, 2, userID)
	require.ErrorIs(t, err, repositories.ErrKeyVersionNotFound)

	// After rotation, version 1 is archived and version 2 exists.
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))
	v, err = repo.GetVersion(context.Background(), keyID, 2, userID)
	require.NoError(t, err)
	require.Equal(t, 2, v.Version)
}

func TestKeyVersions_ListVersionRecords_IncludesValue(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	userID := uuid.New()
	k := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: model.KeyTypeRSA, Value: "pem-v2", Enabled: true, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), k))

	// Never rotated: zero records.
	records, err := repo.ListVersionRecords(context.Background(), keyID, userID)
	require.NoError(t, err)
	require.Empty(t, records)

	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(context.Background(), keyID, 2, "pem-v2"))

	records, err = repo.ListVersionRecords(context.Background(), keyID, userID)
	require.NoError(t, err)
	require.Len(t, records, 2)
	require.Equal(t, "pem-v1", records[0].Value)
	require.Equal(t, 1, records[0].Version)
	require.Equal(t, "pem-v2", records[1].Value)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/repositories/... -run TestKeyVersions -v`
Expected: FAIL — `repo.ReadVersionValue undefined (type *repositories.KeyRepository has no field or method ReadVersionValue)` (and similarly for `GetVersion`, `ListVersionRecords`, `repositories.ErrKeyVersionNotFound`).

- [ ] **Step 3: Add `KeyVersionRecord` to `model/key.go`**

Add immediately after the existing `KeyVersion` struct (`model/key.go:58-62`):

```go
// KeyVersionRecord carries one version's material for internal use only
// (the backup service). It is never marshaled into an HTTP response — API
// responses use KeyVersion, which has no Value field, so the versions-list
// and versions-get handlers cannot leak material even by future mistake.
type KeyVersionRecord struct {
	KeyID     uuid.UUID `json:"key_id"`
	Version   int       `json:"version"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}
```

- [ ] **Step 4: Add the sentinel in a new file**

Create `internal/repositories/key_version_errors.go`:

```go
package repositories

import "errors"

// ErrKeyVersionNotFound is returned when a requested key version does not
// exist (or is not visible to the requesting owner). Propagates unwrapped to
// callers — same pattern as ErrKeyPurgeProtected in
// purge_protection_errors.go.
var ErrKeyVersionNotFound = errors.New("key version not found")
```

- [ ] **Step 5: Implement the three repository methods**

Add to `internal/repositories/key_repository.go`, immediately after
`ListVersions` (`:702-724`):

```go
// ReadVersionValue returns the encrypted/handle material for one version of
// keyID, authorized against userID (matching ListVersions's existing
// owner-JOIN convention, not a model.Scope predicate). Falls back to
// keys.value when version==1 and the key has never been rotated (zero
// key_versions rows), matching RotateKey's own versioning math: a
// never-rotated key's only material is keys.value, which is version 1
// implicitly.
func (r *KeyRepository) ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (string, error) {
	if version < 1 {
		return "", fmt.Errorf("%w: version must be >= 1", ErrKeyVersionNotFound)
	}

	var value string
	err := r.db.QueryRowContext(ctx, `
		SELECT kv.value
		FROM key_versions kv
		JOIN keys k ON k.id = kv.key_id
		WHERE kv.key_id = ? AND kv.version = ? AND k.user_id = ?`,
		keyID.String(), version, userID.String(),
	).Scan(&value)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("failed to query key version: %w", err)
	}
	if version != 1 {
		return "", fmt.Errorf("%w: key %s has no version %d", ErrKeyVersionNotFound, keyID, version)
	}

	err = r.db.QueryRowContext(ctx,
		"SELECT value FROM keys WHERE id = ? AND user_id = ?",
		keyID.String(), userID.String(),
	).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: key %s has no version %d", ErrKeyVersionNotFound, keyID, version)
		}
		return "", fmt.Errorf("failed to query key: %w", err)
	}
	return value, nil
}

// GetVersion returns metadata (no material) for one version of keyID,
// authorized against userID. Same not-found and implicit-version-1 fallback
// semantics as ReadVersionValue.
func (r *KeyRepository) GetVersion(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (*model.KeyVersion, error) {
	if version < 1 {
		return nil, fmt.Errorf("%w: version must be >= 1", ErrKeyVersionNotFound)
	}

	var createdAt time.Time
	err := r.db.QueryRowContext(ctx, `
		SELECT kv.created_at
		FROM key_versions kv
		JOIN keys k ON k.id = kv.key_id
		WHERE kv.key_id = ? AND kv.version = ? AND k.user_id = ?`,
		keyID.String(), version, userID.String(),
	).Scan(&createdAt)
	if err == nil {
		return &model.KeyVersion{KeyID: keyID, Version: version, CreatedAt: createdAt}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to query key version: %w", err)
	}
	if version != 1 {
		return nil, fmt.Errorf("%w: key %s has no version %d", ErrKeyVersionNotFound, keyID, version)
	}

	err = r.db.QueryRowContext(ctx,
		"SELECT created_at FROM keys WHERE id = ? AND user_id = ?",
		keyID.String(), userID.String(),
	).Scan(&createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: key %s has no version %d", ErrKeyVersionNotFound, keyID, version)
		}
		return nil, fmt.Errorf("failed to query key: %w", err)
	}
	return &model.KeyVersion{KeyID: keyID, Version: 1, CreatedAt: createdAt}, nil
}

// ListVersionRecords returns every archived version of keyID INCLUDING
// material, authorized against userID. Internal use only (the backup
// service) — never wired to an HTTP response. Unlike ReadVersionValue/
// GetVersion, this does NOT synthesize an implicit version-1 entry for a
// never-rotated key: the backup service backs up keys.value separately, so
// no such entry is needed here.
func (r *KeyRepository) ListVersionRecords(ctx context.Context, keyID uuid.UUID, userID uuid.UUID) ([]model.KeyVersionRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT kv.version, kv.value, kv.created_at
		FROM key_versions kv
		JOIN keys k ON k.id = kv.key_id
		WHERE kv.key_id = ? AND k.user_id = ?
		ORDER BY kv.version ASC`,
		keyID.String(), userID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query key version records: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var records []model.KeyVersionRecord
	for rows.Next() {
		var rec model.KeyVersionRecord
		rec.KeyID = keyID
		if err := rows.Scan(&rec.Version, &rec.Value, &rec.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key version record: %w", err)
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}
```

Confirm `"database/sql"` and `"errors"` are already imported at the top of
`internal/repositories/key_repository.go` (they are — used elsewhere in the
file); no new imports needed there.

- [ ] **Step 6: Add the three methods to `KeyRepositoryInterface`**

In `internal/repositories/key_repository.go`, immediately after the existing
`ListVersions` interface line (`:48`):

```go
	// ReadVersionValue returns the encrypted/handle material for one
	// version of a key, authorized against userID.
	ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (string, error)
	// GetVersion returns metadata (no material) for one version of a key,
	// authorized against userID.
	GetVersion(ctx context.Context, keyID uuid.UUID, version int, userID uuid.UUID) (*model.KeyVersion, error)
	// ListVersionRecords returns every version of a key INCLUDING material,
	// authorized against userID. Internal use only (backup service).
	ListVersionRecords(ctx context.Context, keyID uuid.UUID, userID uuid.UUID) ([]model.KeyVersionRecord, error)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/repositories/... -run TestKeyVersions -v`
Expected: PASS (all new tests plus the existing `TestKeyVersions_CreateAndList`).

- [ ] **Step 8: Regenerate the `KeyRepositoryInterface` mock**

Run: `mockery --config .mockery.yaml`

This regenerates `internal/repositories/mocks/mock_KeyRepositoryInterface.go`
with the three new methods. Run `go build ./...` afterward to confirm the
mock package still compiles (mockery output is generated code — do not
hand-edit it).

- [ ] **Step 9: Run full package tests and commit**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./model/...`
Expected: PASS.

```bash
git add internal/repositories/key_repository.go internal/repositories/key_version_errors.go internal/repositories/key_versions_test.go internal/repositories/mocks/mock_KeyRepositoryInterface.go model/key.go
git commit -m "feat(keys): add repository methods to read archived version material"
```

---

### Task 2: Service layer — crypto operations accept a version

**Files:**
- Modify: `internal/services/keys/crypto_service.go`
- Test: `internal/services/keys/crypto_service_cache_test.go`
- Test: `internal/services/keys/crypto_vault_scope_test.go` (verify existing tests still pass unmodified — they all pass `Version: 0` implicitly via zero-value structs)

**Interfaces:**
- Consumes: `repositories.KeyRepositoryInterface.ReadVersionValue`/`ListVersions`
  (Task 1), `repositories.ErrKeyVersionNotFound` (Task 1),
  `keycache.Cache.Get`/`Set(keyID uuid.UUID, version int, ...)` (pre-existing,
  already version-parameterized).
- Produces: `SignRequest.Version`, `VerifyRequest.Version`,
  `EncryptRequest.Version`, `DecryptRequest.Version`, `WrapKeyRequest.Version`,
  `UnwrapKeyRequest.Version` (all `int`, `0` = current); `SignResult.Version`,
  `VerifyResult.Version`, `EncryptResult.Version`, `DecryptResult.Version`,
  `WrapKeyResult.Version`, `UnwrapKeyResult.Version` (resolved version echoed
  back).

- [ ] **Step 1: Write the failing test — version selects archived material**

Add to `internal/services/keys/crypto_service_cache_test.go` (it already has
the `mockKeyRepositoryInterface`-via-`mocks.NewMockKeyRepositoryInterface`
and `setupCacheTestMasterKey`/`generateCacheTestRSAPEM` helpers this test
needs):

```go
// TestSign_ArchivedVersion_UsesVersionMaterial verifies that passing a
// non-zero Version reads the version's own material (via
// ReadVersionValue), not the key's current keys.value.
func TestSign_ArchivedVersion_UsesVersionMaterial(t *testing.T) {
	setupCacheTestMasterKey()

	currentPEM := generateCacheTestRSAPEM(t)
	archivedPEM := generateCacheTestRSAPEM(t)
	encryptedCurrent, err := common.EncryptSecret(currentPEM)
	require.NoError(t, err)
	encryptedArchived, err := common.EncryptSecret(archivedPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: encryptedCurrent, Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	// Two versions exist: 1 (archived) and 2 (current, == keys.value).
	repo.On("ListVersions", mock.Anything, keyID, userID).Return([]model.KeyVersion{{KeyID: keyID, Version: 1}, {KeyID: keyID, Version: 2}}, nil)
	repo.On("ReadVersionValue", mock.Anything, keyID, 1, userID).Return(encryptedArchived, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	res, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      []byte("hello"),
		Algorithm: crypto.AlgorithmRS256,
		Version:   1,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Version)
	assert.NotEmpty(t, res.Signature)
}

// TestSign_VersionOmitted_UsesCurrentAndEchoesNumber verifies the default
// path (Version: 0) still uses keys.value and echoes the computed current
// version number in the result.
func TestSign_VersionOmitted_UsesCurrentAndEchoesNumber(t *testing.T) {
	setupCacheTestMasterKey()

	pem := generateCacheTestRSAPEM(t)
	encrypted, err := common.EncryptSecret(pem)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: encrypted, Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return([]model.KeyVersion{{KeyID: keyID, Version: 1}, {KeyID: keyID, Version: 2}}, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	res, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("hello"), Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Version)
	repo.AssertNotCalled(t, "ReadVersionValue", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestSign_NonexistentVersion_ReturnsErrKeyVersionNotFound verifies a
// request for a version that doesn't exist surfaces the repository's
// sentinel unwrapped.
func TestSign_NonexistentVersion_ReturnsErrKeyVersionNotFound(t *testing.T) {
	setupCacheTestMasterKey()

	pem := generateCacheTestRSAPEM(t)
	encrypted, err := common.EncryptSecret(pem)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: encrypted, Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return([]model.KeyVersion{{KeyID: keyID, Version: 1}}, nil)
	repo.On("ReadVersionValue", mock.Anything, keyID, 9, userID).Return("", repositories.ErrKeyVersionNotFound)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err = svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("hello"), Algorithm: crypto.AlgorithmRS256, Version: 9,
	})
	require.ErrorIs(t, err, repositories.ErrKeyVersionNotFound)
}

// TestResolveKeyMaterial_CacheKeyUsesRealVersion_NoCrossContamination is the
// regression test for the cache-key bug found during design: two calls for
// the same key at two different versions must not serve each other's
// material from the cache.
func TestResolveKeyMaterial_CacheKeyUsesRealVersion_NoCrossContamination(t *testing.T) {
	setupCacheTestMasterKey()

	currentPEM := generateCacheTestRSAPEM(t)
	archivedPEM := generateCacheTestRSAPEM(t)
	require.NotEqual(t, currentPEM, archivedPEM)
	encryptedCurrent, err := common.EncryptSecret(currentPEM)
	require.NoError(t, err)
	encryptedArchived, err := common.EncryptSecret(archivedPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: encryptedCurrent, Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return([]model.KeyVersion{{KeyID: keyID, Version: 1}, {KeyID: keyID, Version: 2}}, nil)
	repo.On("ReadVersionValue", mock.Anything, keyID, 1, userID).Return(encryptedArchived, nil)

	cache := &mockKeyCache{}
	// version 2 (current) miss then never re-fetched; version 1 (archived) miss too.
	cache.On("Get", keyID, 2).Return(nil, false)
	cache.On("Set", keyID, 2, mock.AnythingOfType("*keycache.Entry")).Return()
	cache.On("Get", keyID, 1).Return(nil, false)
	cache.On("Set", keyID, 1, mock.AnythingOfType("*keycache.Entry")).Return()

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      cache,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	// Sign with the current version (2), then the archived version (1).
	resCurrent, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("hello"), Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	resArchived, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("hello"), Algorithm: crypto.AlgorithmRS256, Version: 1,
	})
	require.NoError(t, err)

	// Different key material must produce different signatures.
	assert.NotEqual(t, resCurrent.Signature, resArchived.Signature)
	cache.AssertExpectations(t)
}
```

Add `"rocketvault/internal/repositories"` to the test file's imports if not
already present (it is not — `mocks` is imported from
`rocketvault/internal/repositories/mocks`, but the bare `repositories`
package for `ErrKeyVersionNotFound` needs its own import line).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/keys/... -run 'TestSign_ArchivedVersion|TestSign_VersionOmitted|TestSign_NonexistentVersion|TestResolveKeyMaterial_CacheKeyUsesRealVersion' -v`
Expected: FAIL — `req.Version undefined`, `res.Version undefined` (the six
request/result types don't have the field yet), and mock expectations for
`ListVersions`/`ReadVersionValue` are unmet.

- [ ] **Step 3: Add `Version` to the six request and six result types**

In `internal/services/keys/crypto_service.go`, add `Version int` as the last
field to each of `SignRequest` (`:22-29`), `VerifyRequest` (`:40-48`),
`EncryptRequest` (`:58-65`), `DecryptRequest` (`:76-84`), `WrapKeyRequest`
(`:93-100`), `UnwrapKeyRequest` (`:109-116`) — e.g.:

```go
type SignRequest struct {
	KeyID     uuid.UUID
	Data      []byte
	Algorithm crypto.SignatureAlgorithm
	UserID    uuid.UUID
	VaultID   uuid.UUID
	Scope     model.Scope
	Version   int // 0 = current
}
```

Add `Version int` as the last field to each of `SignResult` (`:32-37`),
`VerifyResult` (`:51-55`), `EncryptResult` (`:68-73`), `DecryptResult`
(`:87-91`), `WrapKeyResult` (`:104-107`), `UnwrapKeyResult` (`:120-123`) —
e.g.:

```go
type SignResult struct {
	Signature []byte
	Algorithm crypto.SignatureAlgorithm
	Digest    []byte
	KeyID     uuid.UUID
	Version   int // the version actually used
}
```

- [ ] **Step 4: Add `resolveVersionValue` and `currentVersionNumber` helpers**

Add immediately before `resolveKeyMaterial` (`:197`):

```go
// currentVersionNumber returns key's current version number: the highest
// key_versions row if any rotation has happened, else the implicit 1 (a
// never-rotated key's only material is keys.value). Matches RotateKey's own
// versioning math (key_service.go).
func (s *cryptoService) currentVersionNumber(ctx context.Context, key *model.Key) (int, error) {
	versions, err := s.keyRepo.ListVersions(ctx, key.ID, key.UserID)
	if err != nil {
		return 0, fmt.Errorf("failed to determine current key version: %w", err)
	}
	if len(versions) == 0 {
		return 1, nil
	}
	return versions[len(versions)-1].Version, nil // ListVersions orders ASC
}

// resolveVersionValue resolves which material to use for a crypto
// operation. requested == 0 (or equal to the current version number)
// resolves to key.Value directly — no key_versions read. Otherwise fetches
// the archived version's material via ReadVersionValue.
func (s *cryptoService) resolveVersionValue(ctx context.Context, key *model.Key, requested int) (value string, resolvedVersion int, err error) {
	current, err := s.currentVersionNumber(ctx, key)
	if err != nil {
		return "", 0, err
	}
	if requested == 0 || requested == current {
		return key.Value, current, nil
	}
	value, err = s.keyRepo.ReadVersionValue(ctx, key.ID, requested, key.UserID)
	if err != nil {
		return "", 0, err
	}
	return value, requested, nil
}
```

- [ ] **Step 5: Change `resolveKeyMaterial`'s signature and cache key**

Replace the existing `resolveKeyMaterial` (`:197-236`):

```go
// resolveKeyMaterial returns decrypted PEM key material from cache (hit) or
// via AES-GCM decrypt (miss), for the given value at the given version. For
// PKCS#11 keys the material is the raw token handle and caching is skipped
// entirely. On a cache hit, handle contains the decrypted PEM string stored
// earlier. The cache key is (key.ID, version) — using the real resolved
// version, not a hardcoded constant, is required for correctness once more
// than one version can be resolved per key: a hardcoded key would serve one
// version's material for a different version's request.
func (s *cryptoService) resolveKeyMaterial(key *model.Key, value string, version int) (
	handle string,
	isPKCS11 bool,
	cacheHit bool,
	err error,
) {
	// PKCS#11 keys store the token handle directly; never cache them.
	if strings.HasPrefix(value, pkcs11Prefix) {
		handle = strings.TrimPrefix(value, pkcs11Prefix)
		isPKCS11 = true
		return
	}

	// Check cache using keyID and the real resolved version.
	if entry, ok := s.keyCache.Get(key.ID, version); ok {
		if pemKey, ok := entry.PrivateKey.(keycache.PEMKey); ok {
			handle = pemKey.PEM
			cacheHit = true
			return
		}
	}

	// Cache miss: AES-GCM decrypt the stored PEM.
	decrypted, decErr := common.DecryptSecret(value)
	if decErr != nil {
		err = fmt.Errorf("failed to decrypt key: %w", decErr)
		return
	}

	// Store decrypted PEM in cache for subsequent calls.
	s.keyCache.Set(key.ID, version, &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: decrypted},
		KeyType:    key.Type,
		Version:    version,
	})

	handle = decrypted
	return
}
```

- [ ] **Step 6: Wire `resolveVersionValue` into all six methods**

For each of `Sign` (`:355`), `Verify` (`:411`), `Encrypt` (`:468`), `Decrypt`
(`:521`) — replace:

```go
	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key)
```

with:

```go
	value, resolvedVersion, err := s.resolveVersionValue(ctx, key, req.Version)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "<op>", "failed", "Failed to resolve key version", err)
		return nil, err
	}
	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key, value, resolvedVersion)
```

(substitute the literal op name — `sign`, `verify`, `encrypt`, `decrypt` —
matching each method's existing audit-log op string). Then add
`Version: resolvedVersion` to each method's final `return &XResult{...}`
literal.

For `WrapKey` (`:591`) and `UnwrapKey` (`:655`), the local variable names
differ (`wrapHandle`/`wrapIsPKCS11`, `unwrapHandle`/`unwrapIsPKCS11`) — same
pattern:

```go
	value, resolvedVersion, err := s.resolveVersionValue(ctx, key, req.Version)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "Failed to resolve key version", err)
		return nil, err
	}
	wrapHandle, wrapIsPKCS11, cacheHit, err := s.resolveKeyMaterial(key, value, resolvedVersion)
```

(and `"unwrap_key"` / `unwrapHandle` / `unwrapIsPKCS11` for `UnwrapKey`). Add
`Version: resolvedVersion` to `WrapKeyResult{WrappedKey: wrappedKey, Algorithm: req.Algorithm}`
and the equivalent `UnwrapKeyResult` return.

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/services/keys/... -v`
Expected: PASS — all new tests, and every pre-existing test in this package
(they all construct requests with `Version` implicitly `0`, so
`resolveVersionValue` resolves to `key.Value` exactly as before; the only
observable difference is one extra `ListVersions` mock expectation now
required on tests using `mocks.NewMockKeyRepositoryInterface` directly).

**If pre-existing tests fail** because they use
`mocks.NewMockKeyRepositoryInterface(t)` without a `ListVersions` stub: add
`repo.On("ListVersions", mock.Anything, keyID, userID).Return(nil, nil)` (or
the appropriate version list) to each — `currentVersionNumber` now calls
`ListVersions` on every crypto op. Grep for
`mocks.NewMockKeyRepositoryInterface` across `internal/services/keys/*_test.go`
to find every call site that needs this.

- [ ] **Step 8: Commit**

```bash
git add internal/services/keys/crypto_service.go internal/services/keys/crypto_service_cache_test.go
git commit -m "feat(keys): thread version selection through crypto operations"
```

---

### Task 3: Service layer — `GetKeyVersion`

**Files:**
- Modify: `internal/services/keys/key_service.go`
- Modify: `api/keys_crud_test.go` (hand-rolled `mockKeyService` must gain the
  new interface method or `go build ./...` breaks package-wide — see Step 6)
- Test: `internal/services/keys/key_service_test.go`

**Interfaces:**
- Consumes: `KeyRepositoryInterface.GetVersion` (Task 1), existing
  `keyService.GetKey` (`:` around the file, unchanged).
- Produces: `KeyService.GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error)`.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/keys/key_service_test.go` (check the file's
existing imports/helpers first — it already has a `mocks.NewMockKeyRepositoryInterface`
pattern for `keyService` construction, matching Task 2's test file):

```go
func TestGetKeyVersion_AuthorizesThenDelegatesToRepo(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Enabled: true}
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, scope).Return(vaultKey, nil)
	repo.On("GetVersion", mock.Anything, keyID, 1, userID).Return(&model.KeyVersion{KeyID: keyID, Version: 1}, nil)

	svc := keys.NewKeyService(keys.KeyServiceConfig{KeyRepository: repo, Logger: &logging.Logger{Logger: logrus.New()}})

	v, err := svc.GetKeyVersion(context.Background(), keyID, 1, scope)
	require.NoError(t, err)
	assert.Equal(t, 1, v.Version)
}
```

(`keys.KeyServiceConfig` — confirmed at `internal/services/keys/key_service.go:148-159` —
takes `KeyRepository repositories.KeyRepositoryInterface`, `KeyProvider crypto.KeyProvider`,
`KeyCache keycache.Cache`, `PolicyRepository repositories.KeyRotationPolicyRepositoryInterface`,
`Logger *logging.Logger`, `VaultRepository repositories.VaultRepositoryInterface` — all but
`KeyRepository` and `Logger` are optional for this test.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/keys/... -run TestGetKeyVersion_AuthorizesThenDelegatesToRepo -v`
Expected: FAIL — `svc.GetKeyVersion undefined`.

- [ ] **Step 3: Add `GetKeyVersion` to the interface and implementation**

In `internal/services/keys/key_service.go`, add to the `KeyService`
interface immediately after `ListKeyVersions` (`:131`):

```go
	// GetKeyVersion returns metadata for one version of keyID, authorized
	// by scope against the parent key.
	GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error)
```

Add the implementation immediately after `ListKeyVersions`'s body
(`:495-501`):

```go
// GetKeyVersion returns metadata for one version of keyID, authorized by
// scope against the parent key. Mirrors ListKeyVersions exactly.
func (s *keyService) GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error) {
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}
	return s.keyRepo.GetVersion(ctx, keyID, version, key.UserID)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/keys/... -run TestGetKeyVersion_AuthorizesThenDelegatesToRepo -v`
Expected: PASS.

- [ ] **Step 5: Regenerate the `KeyService` mock**

Run: `mockery --config .mockery.yaml`

Regenerates `internal/services/keys/mocks/mock_KeyService.go` (per
`.mockery.yaml`'s `rocketvault/internal/services/keys: interfaces: KeyService:`
entry) with the new method.

- [ ] **Step 6: Add `GetKeyVersion` to the hand-rolled `mockKeyService` in `api/keys_crud_test.go`**

`api/keys_crud_test.go` defines its own hand-rolled `mockKeyService`
(`type mockKeyService struct { mock.Mock }`, `:46-47`) that implements
`keyServices.KeyService` directly — it is not mockery-generated, and it is
the only `mockKeyService` type in the `api` package (shared by every test
file in that package that needs a fake `KeyService`). Adding a method to the
interface in Step 3 means this type no longer satisfies it, which breaks
`go build ./...` for the whole `api` package until this is added. Immediately
after the existing `ListKeyVersions` method (`:152-158`):

```go
func (m *mockKeyService) GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error) {
	args := m.Called(ctx, keyID, version, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyVersion), args.Error(1)
}
```

- [ ] **Step 7: Run full repository build and package tests, then commit**

Run: `go build ./... && go vet ./... && go test ./internal/services/keys/... ./api/...`
Expected: PASS — confirms Step 6 actually fixed the cross-package break.

```bash
git add internal/services/keys/key_service.go internal/services/keys/key_service_test.go internal/services/keys/mocks/mock_KeyService.go api/keys_crud_test.go
git commit -m "feat(keys): add GetKeyVersion service method"
```

---

### Task 4: API layer — six crypto handlers accept and echo `version`

**Files:**
- Modify: `api/keys.go`
- Modify: `api/errors_key.go`
- Test: `api/keys_crypto_test.go`

**Interfaces:**
- Consumes: `keyservices.SignRequest.Version` etc. (Task 2),
  `repositories.ErrKeyVersionNotFound` (Task 1).
- Produces: `"version"` JSON field on `SignKeyRequest`, `VerifyKeyRequest`,
  `EncryptKeyRequest`, `DecryptKeyRequest`, `WrapKeyRequest`,
  `UnwrapKeyRequest` (request), and on `SignKeyResponse`, `VerifyKeyResponse`,
  `EncryptKeyResponse`, `DecryptKeyResponse`, `WrapKeyResponse`,
  `UnwrapKeyResponse` (response).

- [ ] **Step 1: Write the failing test**

Add to `api/keys_crypto_test.go` (using the existing `stubCryptoSvc`,
`newCryptoContext`, `jsonBody` helpers already in this file):

```go
func TestSignKey_ThreadsVersionAndEchoesResolvedVersion(t *testing.T) {
	svc := &stubCryptoSvc{
		signFn: func(_ context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error) {
			assert.Equal(t, 1, req.Version)
			return &keyServices.SignResult{
				Signature: []byte("sig"),
				Algorithm: crypto.SignatureAlgorithm("RS256"),
				Version:   1,
			}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("hello")),
		"algorithm": "RS256",
		"version":   1,
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var resp SignKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Version)
}

func TestSignKey_VersionNotFound_Returns404(t *testing.T) {
	svc := &stubCryptoSvc{
		signFn: func(_ context.Context, _ keyServices.SignRequest) (*keyServices.SignResult, error) {
			return nil, repositories.ErrKeyVersionNotFound
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("hello")),
		"algorithm": "RS256",
		"version":   9,
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}
```

Add `"rocketvault/internal/repositories"` to this test file's imports if not
already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/... -run 'TestSignKey_ThreadsVersionAndEchoesResolvedVersion|TestSignKey_VersionNotFound_Returns404' -v`
Expected: FAIL — `req.Version`/`resp.Version` don't exist yet, and the
handler has no case for `ErrKeyVersionNotFound` so it falls through to the
`default: c.SetInternalError(err)` 500 branch.

- [ ] **Step 3: Add `Version` to the six HTTP request/response types**

In `api/keys.go`, add `Version int \`json:"version,omitempty"\`` to
`WrapKeyRequest` (`:96-100`) and `UnwrapKeyRequest` (`:108-112`); add
`Version int \`json:"version"\`` to `WrapKeyResponse` (`:102-106`) and
`UnwrapKeyResponse` (`:114-118`). Same pattern (request gets `omitempty`,
response does not) for `SignKeyRequest`/`SignKeyResponse` (`:121-133`),
`VerifyKeyRequest`/`VerifyKeyResponse` (`:134-146`),
`EncryptKeyRequest`/`EncryptKeyResponse` (`:148-160`),
`DecryptKeyRequest`/`DecryptKeyResponse` (`:162-174`). Example:

```go
type SignKeyRequest struct {
	Value     string `json:"value"`
	Algorithm string `json:"algorithm"`
	Version   int    `json:"version,omitempty"`
}

type SignKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	Version   int    `json:"version"`
}
```

- [ ] **Step 4: Thread `Version` through all six handlers**

For each of `signKey` (`:773`), `verifyKey` (`:842`), `encryptKey` (`:914`),
`decryptKey` (`:988`), `wrapKey` (`:637`), `unwrapKey` (`:705`): add
`Version: req.Version` to the service-request literal, and
`Version: result.Version` to the response-literal `json.NewEncoder(w).Encode(...)`
call. Example (`signKey`):

```go
	result, err := cryptoSvc.Sign(r.Context(), keyservices.SignRequest{
		KeyID:     keyID,
		Data:      data,
		Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
		UserID:    scope.ActorID(),
		VaultID:   scope.VaultID(),
		Scope:     scope,
		Version:   req.Version,
	})
	...
	json.NewEncoder(w).Encode(SignKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Value:     base64.StdEncoding.EncodeToString(result.Signature),
		Version:   result.Version,
	})
```

- [ ] **Step 5: Add the new error case to each of the six inline switches**

Each of the six handlers has its own `switch { case errors.Is(err, ...): ... }`
block (they do not share `writeKeyError`). Add one new case to each,
alongside the existing `ErrUnsupportedAlgorithm` case:

```go
		case errors.Is(err, repositories.ErrKeyVersionNotFound):
			c.SetNotFound("key version")
```

`api/keys.go` already imports `"rocketvault/internal/repositories"` (`:37`)
— no new import.

- [ ] **Step 6: Add the same case to `writeKeyError`**

In `api/errors_key.go`, add to the existing switch (used by `listKeyVersions`
and the new `getKeyVersion` handler in Task 5, not by the six crypto
handlers):

```go
	case errors.Is(err, repositories.ErrKeyVersionNotFound):
		c.SetNotFound("key version")
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./api/... -run 'TestSignKey|TestVerifyKey|TestEncryptKey|TestDecryptKey|TestWrapKey|TestUnwrapKey' -v`
Expected: PASS — the two new tests, and every pre-existing test in this file
(they all get `Version: 0`/omitted by default, which the stub's `signFn`
etc. don't assert on unless the test explicitly checks it, so no existing
assertion breaks).

- [ ] **Step 8: Commit**

```bash
git add api/keys.go api/errors_key.go api/keys_crypto_test.go
git commit -m "feat(keys): accept and echo key version on the six crypto endpoints"
```

---

### Task 5: API layer — `GET /keys/{id}/versions/{version}`

**Files:**
- Modify: `api/keys.go`
- Test: `api/keys_crud_test.go` (or a new `api/keys_version_test.go` if the
  existing file's helpers don't fit cleanly — check `api/keys_crud_test.go`'s
  existing `newKeyCtx`/mock-service pattern before choosing)

**Interfaces:**
- Consumes: `keyService.GetKeyVersion` (Task 3).
- Produces: `GET /keys/{key_id}/versions/{version}` and
  `GET /vaults/{vault_name}/keys/{key_id}/versions/{version}` (flat +
  vault-scoped, both registered automatically since `registerKeyRoutes`
  already runs twice — no separate wiring task needed).

- [ ] **Step 1: Write the failing test**

Read `api/keys_crud_test.go`'s existing `mockKeyService`/`newKeyCtx` helpers
first (referenced in Task 3 setup), then add:

```go
func TestGetKeyVersion_Success(t *testing.T) {
	svc := &mockKeyService{}
	keyID := uuid.New()
	svc.On("GetKeyVersion", mock.Anything, keyID, 1, mock.Anything).
		Return(&model.KeyVersion{KeyID: keyID, Version: 1}, nil)

	c := newKeyCtx(svc)
	c.Params.KeyID = keyID.String()
	c.Params.Version = 1
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	getKeyVersion(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var v model.KeyVersion
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &v))
	assert.Equal(t, 1, v.Version)
}

func TestGetKeyVersion_NotFound_Returns404(t *testing.T) {
	svc := &mockKeyService{}
	keyID := uuid.New()
	svc.On("GetKeyVersion", mock.Anything, keyID, 9, mock.Anything).
		Return(nil, repositories.ErrKeyVersionNotFound)

	c := newKeyCtx(svc)
	c.Params.KeyID = keyID.String()
	c.Params.Version = 9
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	getKeyVersion(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}
```

(`mockKeyService` — confirmed at `api/keys_crud_test.go:46-47` — embeds
`mock.Mock` directly, so the `.On(...)` calls above match its existing
convention exactly; its `GetKeyVersion` method was already added in Task 3
Step 6, so no further mock changes are needed here.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/... -run 'TestGetKeyVersion' -v`
Expected: FAIL — `getKeyVersion undefined`.

- [ ] **Step 3: Implement the handler**

Add to `api/keys.go`, near `listKeyVersions` (`:601-634`):

```go
// getKeyVersion retrieves metadata for one version of the vault key
// identified by {key_id}. Never returns key material — see model.KeyVersion.
func getKeyVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := keyService.GetKeyVersion(r.Context(), keyID, c.Params.Version, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version) //nolint:errcheck,gosec
}
```

- [ ] **Step 4: Register the route**

Immediately after the existing `/versions` registration (`api/keys.go:239`):

```go
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getKeyVersion)).Methods("GET")
```

This is inside `registerKeyRoutes(k *mux.Router, scope string)`, which
already runs twice (`api/keys.go:220-222`, once against
`api.BaseRoutes.Keys` and once against
`api.BaseRoutes.VaultScoped.PathPrefix("/keys").Subrouter()`) — so both the
flat and vault-scoped forms are registered by this one line, with no
`InitBackupItem`-style separate-registration gap to fix.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./api/... -run 'TestGetKeyVersion' -v`
Expected: PASS.

- [ ] **Step 6: Run the OpenAPI/route-inventory drift tests**

Run: `go test ./api/... -run 'TestOpenAPISpecCoversAllRoutes|TestGenerateRouteInventory' -v`
Expected: FAIL (new route not documented yet — handled in Task 7).

- [ ] **Step 7: Commit**

```bash
git add api/keys.go api/keys_crud_test.go
git commit -m "feat(keys): add GET /keys/{id}/versions/{version} metadata endpoint"
```

(Committing here despite the drift-test failure from Step 6 is intentional
— Task 7 fixes it in the same logical unit of work as originally scoped in
the backup-routing fix earlier in this branch, keeping the route-addition
commit and the docs-regen commit separable and independently reviewable.)

---

### Task 6: Backup/restore carries key version history

**Files:**
- Modify: `internal/backup/item_backup.go`
- Test: `internal/backup/item_backup_test.go`

**Interfaces:**
- Consumes: `KeyRepositoryInterface.ListVersionRecords` (Task 1),
  `KeyRepositoryInterface.CreateVersion` (pre-existing).
- Produces: `backupEnvelope.Versions`; `encodeBlob`/`decodeBlob` gain a
  `versions []model.KeyVersionRecord` parameter/return.

- [ ] **Step 1: Write the failing test**

Add to `internal/backup/item_backup_test.go` (using the existing
`stubKeyRepo` from this file):

```go
// TestBackupRestoreKey_CarriesVersionHistory verifies a rotated key's
// key_versions history survives a backup/restore round-trip, and that a
// crypto-relevant old version's material is still present afterward.
func TestBackupRestoreKey_CarriesVersionHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	repo := newStubKeyRepo()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultID, Name: "rotated-key",
		Value: "pem-v2", Type: model.KeyTypeRSA, Enabled: true,
	}))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 2, "pem-v2"))

	svc := backup.NewItemBackupService(nil, repo, nil)

	blob, err := svc.BackupKey(ctx, keyID, owner)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, owner, vaultID, newID))

	records, err := repo.ListVersionRecords(ctx, newID, owner)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "pem-v1", records[0].Value)
	assert.Equal(t, "pem-v2", records[1].Value)
}

// TestRestoreKey_OldFormatBlob_NoVersionsField verifies a blob encoded
// before this change (no "versions" field on its envelope) still restores
// correctly, with no version history — not an error.
func TestRestoreKey_OldFormatBlob_NoVersionsField(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	repo := newStubKeyRepo()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultID, Name: "never-rotated",
		Value: "pem-v1", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := backup.NewItemBackupService(nil, repo, nil)

	// A key with zero key_versions rows produces a blob with an empty/absent
	// "versions" field today, which is exactly the old-format shape.
	blob, err := svc.BackupKey(ctx, keyID, owner)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, owner, vaultID, newID))

	records, err := repo.ListVersionRecords(ctx, newID, owner)
	require.NoError(t, err)
	assert.Empty(t, records)
}
```

`stubKeyRepo` (`internal/backup/item_backup_test.go:228-234`) currently
implements `KeyRepositoryInterface` with a bare `keys map[uuid.UUID]*model.Key`
field, and its existing `CreateVersion` (`:289-291`) and `ListVersions`
(`:293-295`) are unconditional no-ops — confirmed by reading the file: they
don't track anything, which is fine for the tests that existed before this
plan (none of them assert on version data) but means `ListVersionRecords`
has nothing to read unless `CreateVersion` starts actually storing. Update
all three:

```go
type stubKeyRepo struct {
	keys     map[uuid.UUID]*model.Key
	versions map[uuid.UUID]map[int]string
}

func newStubKeyRepo() *stubKeyRepo {
	return &stubKeyRepo{
		keys:     make(map[uuid.UUID]*model.Key),
		versions: make(map[uuid.UUID]map[int]string),
	}
}
```

```go
func (r *stubKeyRepo) CreateVersion(_ context.Context, keyID uuid.UUID, version int, value string) error {
	if r.versions[keyID] == nil {
		r.versions[keyID] = make(map[int]string)
	}
	r.versions[keyID][version] = value
	return nil
}

func (r *stubKeyRepo) ListVersions(_ context.Context, keyID uuid.UUID, _ uuid.UUID) ([]model.KeyVersion, error) {
	var out []model.KeyVersion
	for v := range r.versions[keyID] {
		out = append(out, model.KeyVersion{KeyID: keyID, Version: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func (r *stubKeyRepo) ListVersionRecords(_ context.Context, keyID uuid.UUID, _ uuid.UUID) ([]model.KeyVersionRecord, error) {
	var records []model.KeyVersionRecord
	for v, val := range r.versions[keyID] {
		records = append(records, model.KeyVersionRecord{KeyID: keyID, Version: v, Value: val})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Version < records[j].Version })
	return records, nil
}
```

Add `"sort"` to this test file's imports if not already present (it is not).
This replaces the existing `CreateVersion` (`:289-291`) and `ListVersions`
(`:293-295`) method bodies in place — same method signatures, real
implementations instead of no-ops. No other test in this file asserts on the
old no-op behavior (confirmed: neither method's return value is checked
anywhere except through these new tests), so this is a safe in-place change.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/backup/... -run 'TestBackupRestoreKey_CarriesVersionHistory|TestRestoreKey_OldFormatBlob_NoVersionsField' -v`
Expected: FAIL — compile error (`stubKeyRepo` doesn't implement the updated
interface yet if Task 1 already landed; if it does compile, the test fails
because `repo.ListVersionRecords(ctx, newID, owner)` returns empty even
though version history should have been restored).

- [ ] **Step 3: Add `Versions` to `backupEnvelope` and thread it through `encodeBlob`/`decodeBlob`**

In `internal/backup/item_backup.go`, modify the envelope struct (`:46-50`):

```go
type backupEnvelope struct {
	ResourceType string                   `json:"resource_type"`
	ResourceID   string                   `json:"resource_id"`
	Data         json.RawMessage          `json:"data"`
	Versions     []model.KeyVersionRecord `json:"versions,omitempty"` // keys only
}
```

Modify `encodeBlob` (`:169-183`):

```go
// encodeBlob marshals data into a JSON envelope and base64url-encodes it.
// versions is nil for secrets/certificates (no version-material concept);
// keys pass their archived version records.
func encodeBlob(resourceType, resourceID string, data interface{}, versions []model.KeyVersionRecord) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal data: %w", err)
	}
	envelope, err := json.Marshal(backupEnvelope{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Data:         raw,
		Versions:     versions,
	})
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return base64.URLEncoding.EncodeToString(envelope), nil
}
```

Modify `decodeBlob` (`:187-200`):

```go
// decodeBlob base64url-decodes a blob and unmarshals the envelope into out.
// Returns the envelope's Versions (nil for secrets/certificates, and nil for
// a blob encoded before this field existed — the field is purely additive).
func decodeBlob(blob, expectedType string, out interface{}) ([]model.KeyVersionRecord, error) {
	raw, err := base64.URLEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid encoding: %w", ErrInvalidBlob, err)
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%w: invalid format: %w", ErrInvalidBlob, err)
	}
	if envelope.ResourceType != expectedType {
		return nil, fmt.Errorf("%w: type mismatch: expected %s, got %s", ErrInvalidBlob, expectedType, envelope.ResourceType)
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return nil, err
	}
	return envelope.Versions, nil
}
```

- [ ] **Step 4: Update every `encodeBlob`/`decodeBlob` call site**

`BackupSecret`/`BackupCertificate` — add `nil` as the fourth argument:

```go
	return encodeBlob("secret", id.String(), secret, nil)
```

```go
	return encodeBlob("certificate", id.String(), cert, nil)
```

`RestoreSecret`/`RestoreCertificate` — discard the new first return value:

```go
	if _, err := decodeBlob(blob, "secret", &secret); err != nil {
		return err
	}
```

```go
	if _, err := decodeBlob(blob, "certificate", &cert); err != nil {
		return err
	}
```

`BackupKey` — fetch version records and pass them:

```go
func (s *ItemBackupService) BackupKey(ctx context.Context, id, userID uuid.UUID) (string, error) {
	key, err := s.keyRepo.Read(ctx, id, model.NewAdminScope(userID))
	if err != nil {
		return "", fmt.Errorf("backup key: %w", err)
	}
	if key.UserID != userID {
		return "", ErrForbidden
	}
	versions, err := s.keyRepo.ListVersionRecords(ctx, id, userID)
	if err != nil {
		return "", fmt.Errorf("backup key: list versions: %w", err)
	}
	return encodeBlob("key", id.String(), key, versions)
}
```

`RestoreKey` — capture and replay version records:

```go
func (s *ItemBackupService) RestoreKey(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var key model.Key
	versions, err := decodeBlob(blob, "key", &key)
	if err != nil {
		return err
	}
	key.ID = newID
	key.UserID = userID
	key.VaultID = vaultID
	if err := s.keyRepo.Create(ctx, &key); err != nil {
		return err
	}
	if key.PurgeProtection {
		if err := s.keyRepo.SetPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore key: set purge protection: %w", err)
		}
	}
	for _, v := range versions {
		if err := s.keyRepo.CreateVersion(ctx, newID, v.Version, v.Value); err != nil {
			return fmt.Errorf("restore key: create version %d: %w", v.Version, err)
		}
	}
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/backup/... -v`
Expected: PASS — the two new tests, plus every pre-existing test in this
package (secrets/certificates pass `nil`/discard the new return value with
no behavior change; `TestRestoreSecretBlobTypeMismatch` and similar continue
to work since `Data`'s shape is untouched).

- [ ] **Step 6: Run the full test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS across the whole repository.

- [ ] **Step 7: Commit**

```bash
git add internal/backup/item_backup.go internal/backup/item_backup_test.go
git commit -m "feat(keys): carry key_versions history through backup/restore"
```

---

### Task 7: OpenAPI spec and route inventory

**Files:**
- Modify: `docs/api-specification.yaml`
- Modify: `docs/api-routes.generated.txt` (regenerated, not hand-edited)

**Interfaces:**
- Consumes: the new route from Task 5, the new `version` request/response
  fields from Task 4.

- [ ] **Step 1: Regenerate the route inventory**

Run: `go test ./api/... -run TestGenerateRouteInventory -update-route-inventory -v`

This rewrites `docs/api-routes.generated.txt` to include
`GET /api/v1/keys/{key_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}` and its
vault-scoped equivalent.

- [ ] **Step 2: Add the new route to `docs/api-specification.yaml`**

Follow the existing pattern for `GET /keys/{key_id}/versions` (find its
block in the file first) — add a sibling path immediately after it, for both
the flat and vault-scoped path groups, mirroring how secrets already
document `GET /secrets/{secret_id}/versions/{version}` (find that block too,
to match structure exactly — parameters, operationId naming convention
`getKeyVersionInVault` for the vault-scoped variant, response schema
referencing `KeyVersion`, standard 400/401/403/404 responses).

- [ ] **Step 3: Add `version` to the six existing crypto request/response schemas**

Find `SignKeyRequest`, `VerifyKeyRequest`, `EncryptKeyRequest`,
`DecryptKeyRequest`, `WrapKeyRequest`, `UnwrapKeyRequest` and their `*Response`
counterparts under `components.schemas` in `docs/api-specification.yaml`. Add
`version: {type: integer}` to each request schema (optional, no `required`
entry) and each response schema (present in the response body).

- [ ] **Step 4: Run the drift tests**

Run: `go test ./api/... -run 'TestOpenAPISpecCoversAllRoutes|TestGenerateRouteInventory' -v`
Expected: PASS.

- [ ] **Step 5: Run the full API test suite**

Run: `go test ./api/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add docs/api-specification.yaml docs/api-routes.generated.txt
git commit -m "docs(api): document GET /keys/{id}/versions/{version} and the version field"
```

---

### Task 8: Documentation

**Files:**
- Modify: `.claude/azure-keyvault-parity.md`
- Modify: `.claude/known-bugs.md`
- Modify: `docs/usage-guide.md` (§2 REST API, §6 Backup/restore tooling —
  check `docs/.usage-guide-map.json` for current section globs/anchors
  before editing, per this repo's `usage-guide-refresh` skill convention)

This task is documentation-only; no test cycle. Before starting, run
`git log --oneline -5` and `git status` — this branch has had concurrent
activity from another session throughout this work (visible in the
conversation this plan came from); re-check whether `.claude/azure-keyvault-parity.md`
or `.claude/known-bugs.md` have moved since this plan was written, and merge
by hand rather than overwriting.

- [ ] **Step 1: Update the parity doc**

In `.claude/azure-keyvault-parity.md` §2, "Rotate (new version)" row: change
from 🟡 to ✅ (or a narrower 🟡 if the CLI `--version` fast-follow noted in the
spec's "Not in scope" section is left open) — state plainly that crypto
operations now accept a version and old material stays usable. Update the
"Backup / Restore" row to note that key version history now survives a
restore. Add a dated correction note (matching this doc's existing
convention, e.g. the 2026-08-19 notes already in the file) explaining what
changed and pointing at this plan's spec.

- [ ] **Step 2: Add a `known-bugs.md` entry**

Add a new dated entry (next letter in the existing `B<N>` sequence — check
the last one used) describing: root cause (versions archived but never
readable), the fix (this plan), and the bundled cache-key bug found during
design. Mark it closed, with the commit range from Tasks 1-7.

- [ ] **Step 3: Update `docs/usage-guide.md`**

§2 (REST API): note the new `version` field on the six crypto endpoints and
the new `GET .../versions/{version}` route. §6 (Backup/restore tooling): note
that key backups now carry version history.

- [ ] **Step 4: Update `docs/.usage-guide-map.json`**

Set `lastVerifiedCommit` to the current `git rev-parse HEAD` and
`lastVerifiedDate` to today, per this repo's `usage-guide-refresh` skill
convention (see the file's existing shape before editing).

- [ ] **Step 5: Commit**

```bash
git add .claude/azure-keyvault-parity.md .claude/known-bugs.md docs/usage-guide.md docs/.usage-guide-map.json
git commit -m "docs: record key version addressability fix"
```

---

## Final Verification

After all 8 tasks:

```bash
go build ./...
go vet ./...
go test ./...
mockery --config .mockery.yaml && git diff --stat  # confirm no drift between interfaces and generated mocks
```

All must pass with zero diff from the mock regeneration (if `git diff`
shows changes, an interface changed after the last `mockery` run somewhere
in the plan — regenerate and fold into the relevant task's commit).
