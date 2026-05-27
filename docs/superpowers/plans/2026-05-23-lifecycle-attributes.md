# Resource Lifecycle Attributes (enabled / exp / nbf) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `enabled`, `exp` (expiry timestamp), and `nbf` (not-before timestamp) lifecycle attributes to secrets, keys, and certificates. Enforce these attributes at read time: return HTTP 403 when `enabled=false`, `exp < now()`, or `nbf > now()`. This brings RocketVault in line with Azure Key Vault's `attributes` block on all three resource types.

**Architecture:** Same pattern applied to three resource types. Database schema gains three columns per table. Repositories add them to INSERT/UPDATE/SELECT. Service `Get*` methods enforce lifecycle state. HTTP handlers surface the values in responses. Model types gain the three fields.

**Tech Stack:** Go 1.24.2, SQLite/PostgreSQL, `database/sql`, testify.

**Spec:** `docs/plans/2026-05-23-azure-keyvault-parity-audit.md` §Secrets, §Keys, §Certificates — "enabled / exp / nbf (attributes block)" row.

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `model/secret.go` | Modify | Add `Enabled bool`, `Exp *time.Time`, `Nbf *time.Time` fields |
| `model/key.go` | Modify | Add `Enabled bool`, `Exp *time.Time`, `Nbf *time.Time` fields |
| `model/certificate.go` | Modify | Add `Enabled bool`, `Exp *time.Time`, `Nbf *time.Time` fields |
| `internal/db/db.go` | Modify | Add `enabled`, `exp`, `nbf` columns to all three `CREATE TABLE` definitions; add `ALTER TABLE` migrations |
| `internal/repositories/secret_repository.go` | Modify | Include lifecycle fields in INSERT, UPDATE, SELECT |
| `internal/repositories/key_repository.go` | Modify | Include lifecycle fields in INSERT, UPDATE, SELECT |
| `internal/repositories/certificate_repository.go` | Modify | Include lifecycle fields in INSERT, UPDATE, SELECT |
| `internal/services/secrets/secret_service.go` | Modify | Enforce lifecycle state in `GetSecret` |
| `internal/services/keys/key_service.go` | Modify | Enforce lifecycle state in `GetKey` |
| `internal/services/certificates/certificate_service.go` | Modify | Enforce lifecycle state in `GetCertificate` |
| `api/secrets.go` | Modify | Surface `enabled`/`exp`/`nbf` in create/update request; pass to service |
| `api/keys.go` | Modify | Surface `enabled`/`exp`/`nbf` in create/update request |
| `api/certificates.go` | Modify | Surface `enabled`/`exp`/`nbf` in create/update request |
| `internal/repositories/secret_lifecycle_test.go` | Create | Repository-layer tests for lifecycle fields |
| `internal/services/secrets/lifecycle_enforcement_test.go` | Create | Service-layer tests for 403 on disabled/expired/nbf |

---

## Task 1: Update domain model structs

**Files:**
- Modify: `model/secret.go`, `model/key.go`, `model/certificate.go`

- [ ] **Step 1: Add lifecycle fields to `model/secret.go`**

Find the `Secret` struct in `model/secret.go`. After the existing fields, add:

```go
// Azure Key Vault attributes block
Enabled bool       `json:"enabled"`
Exp     *time.Time `json:"exp,omitempty"`  // expiry timestamp
Nbf     *time.Time `json:"nbf,omitempty"`  // not-before timestamp
```

The `Secret` struct already has `DeletedAt *time.Time`. Add the three fields after it.

Also update `CreateSecretRequest`:

```go
Enabled *bool      `json:"enabled,omitempty"` // default true if nil
Exp     *time.Time `json:"exp,omitempty"`
Nbf     *time.Time `json:"nbf,omitempty"`
```

And `UpdateSecretRequest`:

```go
Enabled *bool      `json:"enabled,omitempty"`
Exp     *time.Time `json:"exp,omitempty"`
Nbf     *time.Time `json:"nbf,omitempty"`
```

- [ ] **Step 2: Add lifecycle fields to `model/key.go`**

Same pattern — add to `Key`, `CreateKeyRequest`, and `UpdateKeyRequest`:

```go
Enabled bool       `json:"enabled"`
Exp     *time.Time `json:"exp,omitempty"`
Nbf     *time.Time `json:"nbf,omitempty"`
```

- [ ] **Step 3: Add lifecycle fields to `model/certificate.go`**

Same pattern — add to `Certificate` struct:

```go
Enabled bool       `json:"enabled"`
Exp     *time.Time `json:"exp,omitempty"`  // note: Certificate already has ExpiresAt; Exp here mirrors AKV attributes
Nbf     *time.Time `json:"nbf,omitempty"`
```

- [ ] **Step 4: Build to confirm model changes compile**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -20
```

Expected: compile errors about repository INSERT/SELECT not including the new fields — these are fixed in Task 2. If there are errors only in repos/services, proceed.

- [ ] **Step 5: Commit model changes**

```bash
git add model/secret.go model/key.go model/certificate.go
git commit -m "feat(model): add enabled/exp/nbf lifecycle attributes to Secret, Key, Certificate"
```

---

## Task 2: Add DB schema columns and migrations

**Files:**
- Modify: `internal/db/db.go`

- [ ] **Step 1: Update `createOptimizedSchema` for secrets table**

In `internal/db/db.go`, find `CREATE TABLE IF NOT EXISTS secrets`. Add three columns after `purge_protection BOOLEAN`:

```sql
enabled BOOLEAN NOT NULL DEFAULT TRUE,
exp TIMESTAMP NULL DEFAULT NULL,
nbf TIMESTAMP NULL DEFAULT NULL,
```

- [ ] **Step 2: Update `createOptimizedSchema` for keys table**

Find `CREATE TABLE IF NOT EXISTS keys`. Add after `purge_protection BOOLEAN`:

```sql
enabled BOOLEAN NOT NULL DEFAULT TRUE,
exp TIMESTAMP NULL DEFAULT NULL,
nbf TIMESTAMP NULL DEFAULT NULL,
```

- [ ] **Step 3: Update `createOptimizedSchema` for certificates table**

Find `CREATE TABLE IF NOT EXISTS certificates`. Add after existing columns (before closing `)`):

```sql
enabled BOOLEAN NOT NULL DEFAULT TRUE,
exp TIMESTAMP NULL DEFAULT NULL,
nbf TIMESTAMP NULL DEFAULT NULL,
```

- [ ] **Step 4: Add `migrateSchema` migrations**

Find the `migrations` slice in `migrateSchema`. Add six new entries (two per table):

```go
"ALTER TABLE secrets ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
"ALTER TABLE secrets ADD COLUMN exp TIMESTAMP NULL DEFAULT NULL",
"ALTER TABLE secrets ADD COLUMN nbf TIMESTAMP NULL DEFAULT NULL",
"ALTER TABLE keys ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
"ALTER TABLE keys ADD COLUMN exp TIMESTAMP NULL DEFAULT NULL",
"ALTER TABLE keys ADD COLUMN nbf TIMESTAMP NULL DEFAULT NULL",
"ALTER TABLE certificates ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
"ALTER TABLE certificates ADD COLUMN exp TIMESTAMP NULL DEFAULT NULL",
"ALTER TABLE certificates ADD COLUMN nbf TIMESTAMP NULL DEFAULT NULL",
```

- [ ] **Step 5: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -20
```

- [ ] **Step 6: Commit**

```bash
git add internal/db/db.go
git commit -m "feat(db): add enabled/exp/nbf columns to secrets, keys, and certificates tables"
```

---

## Task 3: Update repositories to persist and read lifecycle fields

**Files:**
- Modify: `internal/repositories/secret_repository.go`
- Modify: `internal/repositories/key_repository.go`
- Modify: `internal/repositories/certificate_repository.go`
- Create: `internal/repositories/secret_lifecycle_test.go`

- [ ] **Step 1: Write failing tests for lifecycle field persistence**

Create `internal/repositories/secret_lifecycle_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestSecretRepository_LifecycleFields_Persisted(t *testing.T) {
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestLogger(t))

	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	nbf := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)

	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "lifecycle-test",
		Value:     "encrypted-value",
		CreatedAt: time.Now(),
		Enabled:   false, // explicitly disabled
		Exp:       &exp,
		Nbf:       &nbf,
	}

	require.NoError(t, repo.Create(context.Background(), secret))

	got, err := repo.Read(context.Background(), secret.ID)
	require.NoError(t, err)

	assert.Equal(t, false, got.Enabled)
	require.NotNil(t, got.Exp)
	assert.Equal(t, exp, got.Exp.UTC().Truncate(time.Second))
	require.NotNil(t, got.Nbf)
	assert.Equal(t, nbf, got.Nbf.UTC().Truncate(time.Second))
}

func TestSecretRepository_Enabled_DefaultsToTrue(t *testing.T) {
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(db, newTestLogger(t))

	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "default-enabled",
		Value:     "v",
		CreatedAt: time.Now(),
		Enabled:   true, // set explicitly to true
	}
	require.NoError(t, repo.Create(context.Background(), secret))

	got, err := repo.Read(context.Background(), secret.ID)
	require.NoError(t, err)
	assert.True(t, got.Enabled)
}
```

- [ ] **Step 2: Run to confirm tests fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/repositories/... -run "TestSecretRepository_Lifecycle" -v 2>&1 | tail -10
```

Expected: FAIL — `Enabled`/`Exp`/`Nbf` not scanned.

- [ ] **Step 3: Update `secret_repository.go` INSERT**

Find the `INSERT INTO secrets` statement. Add `enabled, exp, nbf` to the column list and pass `secret.Enabled, secret.Exp, secret.Nbf` as values.

Pattern:

```go
_, err := r.db.ExecContext(ctx, `
    INSERT INTO secrets (id, user_id, name, value, ..., enabled, exp, nbf)
    VALUES (?, ?, ?, ?, ..., ?, ?, ?)`,
    ..., secret.Enabled, secret.Exp, secret.Nbf,
)
```

- [ ] **Step 4: Update `secret_repository.go` SELECT and Scan**

For every SELECT that reads secret rows, add `enabled, exp, nbf` to the column list. Add corresponding `Scan` variables:

```go
var (
    enabled bool
    expTime *time.Time
    nbfTime *time.Time
)
// In Scan: &enabled, &expTime, &nbfTime
// After Scan:
secret.Enabled = enabled
secret.Exp = expTime
secret.Nbf = nbfTime
```

Apply to `Read`, `ReadByName`, and any list queries.

- [ ] **Step 5: Update `secret_repository.go` UPDATE**

If there is an `UPDATE secrets SET ...` statement (for tagging or value updates), add:

```go
enabled = ?, exp = ?, nbf = ?
```

and pass `secret.Enabled, secret.Exp, secret.Nbf`.

- [ ] **Step 6: Repeat for `key_repository.go` and `certificate_repository.go`**

Apply the exact same INSERT/SELECT/UPDATE changes to `key_repository.go` (for the `Key` struct) and `certificate_repository.go` (for `Certificate`).

Write equivalent test files `key_lifecycle_test.go` and `certificate_lifecycle_test.go` following the same pattern as `secret_lifecycle_test.go`.

- [ ] **Step 7: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/repositories/... -v 2>&1 | grep -E "PASS|FAIL|---"
```

Expected: all lifecycle tests PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/repositories/
git commit -m "feat(repositories): persist and read enabled/exp/nbf lifecycle fields for secrets, keys, certs"
```

---

## Task 4: Enforce lifecycle state in service layer

**Files:**
- Modify: `internal/services/secrets/secret_service.go`
- Modify: `internal/services/keys/key_service.go`
- Modify: `internal/services/certificates/certificate_service.go`
- Create: `internal/services/secrets/lifecycle_enforcement_test.go`

- [ ] **Step 1: Write failing enforcement tests**

Create `internal/services/secrets/lifecycle_enforcement_test.go`:

```go
package secrets_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSecret_Returns403_WhenDisabled(t *testing.T) {
	svc, ownerID := setupSecretService(t)
	secretID := createTestSecret(t, svc, ownerID, func(s *model.Secret) {
		s.Enabled = false
	})

	_, err := svc.GetSecret(context.Background(), secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestGetSecret_Returns403_WhenExpired(t *testing.T) {
	svc, ownerID := setupSecretService(t)
	past := time.Now().Add(-1 * time.Hour)
	secretID := createTestSecret(t, svc, ownerID, func(s *model.Secret) {
		s.Exp = &past
	})

	_, err := svc.GetSecret(context.Background(), secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestGetSecret_Returns403_WhenNbfInFuture(t *testing.T) {
	svc, ownerID := setupSecretService(t)
	future := time.Now().Add(1 * time.Hour)
	secretID := createTestSecret(t, svc, ownerID, func(s *model.Secret) {
		s.Nbf = &future
	})

	_, err := svc.GetSecret(context.Background(), secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet active")
}

func TestGetSecret_Succeeds_WhenLifecycleValid(t *testing.T) {
	svc, ownerID := setupSecretService(t)
	secretID := createTestSecret(t, svc, ownerID, func(s *model.Secret) {
		s.Enabled = true
		// no exp or nbf set
	})

	got, err := svc.GetSecret(context.Background(), secretID, ownerID)
	require.NoError(t, err)
	assert.NotNil(t, got)
}
```

- [ ] **Step 2: Run to confirm tests fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/secrets/... -run "TestGetSecret_Returns403" -v 2>&1 | tail -15
```

Expected: FAIL — no lifecycle enforcement.

- [ ] **Step 3: Add lifecycle enforcement to `GetSecret`**

In `internal/services/secrets/secret_service.go`, find `GetSecret`. After reading the secret from the repository and confirming ownership, add:

```go
// Enforce lifecycle attributes (Azure Key Vault attributes block)
now := time.Now()
if !secret.Enabled {
    return nil, fmt.Errorf("secret %q is disabled: access forbidden", secret.Name)
}
if secret.Exp != nil && now.After(*secret.Exp) {
    return nil, fmt.Errorf("secret %q has expired: access forbidden", secret.Name)
}
if secret.Nbf != nil && now.Before(*secret.Nbf) {
    return nil, fmt.Errorf("secret %q is not yet active: access forbidden", secret.Name)
}
```

Import `"time"` if not already present.

- [ ] **Step 4: Add same enforcement to `GetKey` and `GetCertificate`**

Apply the same three-check block in:
- `internal/services/keys/key_service.go` → `GetKey` method
- `internal/services/certificates/certificate_service.go` → `GetCertificate` method

Use the resource name in the error message (`key.Name`, `cert.Name`).

- [ ] **Step 5: Enforce default `Enabled=true` on create**

In `internal/services/secrets/secret_service.go`, find `CreateSecret`. After the request is parsed but before the domain object is built, add:

```go
enabled := true
if req.Enabled != nil {
    enabled = *req.Enabled
}
```

Pass `enabled` into the `model.Secret{Enabled: enabled, Exp: req.Exp, Nbf: req.Nbf}` struct.

Apply the same default in `CreateKey` and `CreateCertificate`.

- [ ] **Step 6: Build and run service tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/... -v 2>&1 | grep -E "PASS|FAIL|---"
```

Expected: all three enforcement test files PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/services/secrets/ internal/services/keys/ internal/services/certificates/
git commit -m "feat(services): enforce enabled/exp/nbf lifecycle state on GetSecret, GetKey, GetCertificate"
```

---

## Task 5: Surface lifecycle attributes in HTTP handlers

**Files:**
- Modify: `api/secrets.go`, `api/keys.go`, `api/certificates.go`

- [ ] **Step 1: Update `createSecret` handler to accept lifecycle fields**

In `api/secrets.go`, find the `createSecret` handler. The request body is decoded into a struct (likely `model.CreateSecretRequest`). Verify that `Enabled`, `Exp`, and `Nbf` are now present (from Task 1). Pass them through to the service call:

```go
result, err := secretSvc.CreateSecret(r.Context(), secretservices.CreateSecretRequest{
    Name:    req.Name,
    Value:   req.Value,
    UserID:  userID,
    Tags:    req.Tags,
    Enabled: req.Enabled,
    Exp:     req.Exp,
    Nbf:     req.Nbf,
})
```

- [ ] **Step 2: Update response types to include lifecycle fields**

In the `getSecret` response and `listSecrets` response, include `enabled`, `exp`, and `nbf` from the secret model in the JSON output. If there is a `SecretResponse` struct, add the three fields:

```go
Enabled bool       `json:"enabled"`
Exp     *time.Time `json:"exp,omitempty"`
Nbf     *time.Time `json:"nbf,omitempty"`
```

- [ ] **Step 3: Repeat for `api/keys.go` and `api/certificates.go`**

Apply the same changes to the key and certificate create/get/list handlers.

- [ ] **Step 4: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add api/
git commit -m "feat(api): surface enabled/exp/nbf lifecycle attributes in secret, key, certificate endpoints"
```

---

## Task 6: Full regression pass

- [ ] **Step 1: Run full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|ok" | sort
```

Expected: all packages `ok`.

- [ ] **Step 2: Build binary**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build -o /tmp/rocketvault-lifecycle . && echo "build ok"
```

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: enabled/exp/nbf lifecycle attributes — secrets, keys, and certificates"
```
