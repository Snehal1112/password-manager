# Per-Vault Webhook Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a `CanManageVault`-authorized operator store, read, and delete one webhook URL plus a server-generated signing secret per vault, so a later sub-project has a delivery target to read.

**Architecture:** A conventional five-layer slice through this codebase — migration, model, repository, service, and two edges (HTTP handlers and a CLI package). Authorization lives at the two edges, not in the service, matching how `api/vault.go` and `cmd/vaults/authz.go` already split it. The signing secret is minted by the server from `crypto/rand`, encrypted at rest with `common.EncryptSecret`, and returned exactly once.

**Tech Stack:** Go 1.24, `database/sql` over SQLite (dev) and PostgreSQL (prod), Gorilla Mux, Cobra, testify.

**Spec:** `docs/superpowers/specs/2026-08-19-vault-webhook-config-design.md`

## Plan-time corrections to the spec

Reading the spec against the code turned up four places where it specified something the codebase does not do. Each is corrected below and the correction is carried into the tasks. **These override the spec where they conflict.**

**C1 — The service does NOT authorize, and takes no `model.Scope`.** The spec's §4 gives `VaultWebhookService` a `scope model.Scope` parameter and says it "authorizes via `CanManageVault`". Neither matches the code:

- `CanManageVault` (`internal/services/authorization/vault_authz.go:23`) has signature `(ctx, accountRole string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool`. It needs the caller's account role and an `AccessPolicyService` — neither of which a `model.Scope` carries.
- Every existing caller is an **edge**: `api/vault.go:71,115,174,212,269` and `cmd/vaults/authz.go:60,75,92`. No service in `internal/services/vaults/` calls it.
- `VaultService`'s own methods (`vault_service.go:108-120`) and `VaultRepositoryInterface` (`vault_repository.go:19-29`) take no `model.Scope` at all. `model.Scope` is a **data-plane** construct for per-vault user data (secrets/keys/certs, e.g. `KeyRotationPolicyRepositoryInterface`). Vault-management config is the other tier.

**Correction:** `VaultWebhookService` and `VaultWebhookRepositoryInterface` take no `model.Scope` and never call `CanManageVault`. Authorization is done by the HTTP handler (Task 6) and the CLI (Task 7), exactly as `updateVault`/`deleteVault` and `cmd/vaults/authz.go` already do it.

**C2 — `ON DELETE CASCADE` does not fire on SQLite; an explicit purge hook is required.** The spec added `ON DELETE CASCADE` to stop a purged vault orphaning a row holding an encrypted secret. That reasoning is right but the mechanism does not work here: **SQLite's `foreign_keys` PRAGMA is off in this project** (`internal/db/db.go:952`, `internal/db/audit_fk_test.go:6`, `internal/repositories/certificate_policy_repository_test.go:26`). `PurgeVault` already says so in a comment at `vault_service.go:465-467`: *"Secrets, keys, and certificates have no FK on vault_id either — purge their rows explicitly ... or they'd be stranded permanently."*

**Correction:** keep the `FOREIGN KEY ... ON DELETE CASCADE` clause (it is correct on PostgreSQL and matches every other table's declaration style), **and** add an explicit application-level cleanup on purge, modelled exactly on the existing `PolicyCleaner` optional hook (`vault_service.go:61-64`, `SetPolicyCleaner` at `:116`). That is Task 5. The cascade test asserts the real mechanism, not the inert PRAGMA.

**C3 — The repository's `created bool` return is redundant.** The spec's §3 has `Upsert(...) (created bool, err error)` so the service "knows whether the secret argument was required". But the spec's own §4 step 3 already has the service read the existing row first. Returning `created` portably from an `ON CONFLICT ... DO UPDATE` is also awkward (`RowsAffected` differs across drivers).

**Correction:** `Upsert(ctx, cfg) error`, matching `KeyRotationPolicyRepository.Upsert` (`key_rotation_policy_repository.go:51`) exactly. The service derives create-vs-update from its own prior `GetByVaultID`.

**C4 — Response timestamps are RFC3339 strings, not `time.Time`.** The spec's response structs use `time.Time`. `model.Vault.ToResponse` (`model/vault.go:137-149`) formats every timestamp with `.Format(time.RFC3339)` into `string` fields.

**Correction:** `CreatedAt`/`UpdatedAt` on the response types are `string`.

## Global Constraints

Copied from the spec; every task's requirements implicitly include these.

- **No delivery.** No outbound HTTP call, no `TestSend`, no `WebhookSender` interface, no payload schema. This sub-project is storage and CRUD only. A task that dials anything is out of scope.
- **Secret origin is the server.** 32 bytes from `crypto/rand`, base64-encoded. There is no client-supplied-secret path and no `--secret` flag anywhere.
- **Show-once.** The plaintext signing secret appears in the `PUT` response body only, on create or on an explicit rotate. `GET` never emits a `signing_secret` field on any code path.
- **Never log the secret.** Not at the service, handler, or CLI layer. `cmd/users/create.go:91` logs a TOTP secret to the structured logger; do **not** copy that.
- **Encryption at rest** via `common.EncryptSecret` (`common/encrypt.go:152`) / `common.DecryptSecret` (`:170`). An unrotated secret is carried through as ciphertext and never decrypted.
- **URL validation:** `url.Parse` must succeed, `Scheme` must be exactly `https`, `Host` must be non-empty. Nothing more — SSRF policy belongs to the sub-project that dials.
- **Route placement:** `/{name}/webhook` on `api.BaseRoutes.Vaults`, **not** `BaseRoutes.VaultScoped`.
- **Authorization at the edges only** (C1 above): handler and CLI call `authz.CanManageVault`; the service does not.
- **One config per vault**, `UNIQUE` on `vault_id`. Hard delete, no soft-delete or purge protection.
- **Go 1.24**, existing deps only — no new module requirements.

## File structure

| File | Responsibility |
|---|---|
| `internal/db/db.go` (modify, 2 sites) | `vault_webhook_configs` DDL, dual-registered in `createOptimizedSchema` and `migrateSchema` |
| `model/vault_webhook.go` (new) | `VaultWebhookConfig` domain type + two structurally-separate response types |
| `internal/repositories/vault_webhook_repository.go` (new) | Pure CRUD: `Upsert` / `GetByVaultID` / `DeleteByVaultID` |
| `internal/services/vaults/webhook_service.go` (new) | URL validation, secret minting, encryption, create-vs-update decision |
| `internal/services/vaults/vault_service.go` (modify) | `WebhookCleaner` hook + `SetWebhookCleaner` + call in `PurgeVault` |
| `internal/container/service_container.go` (modify) | Repository + service construction, interface method, getter, cleaner wiring |
| `api/vault_webhook.go` (new) | Three handlers, resolve-then-authorize, response shaping |
| `api/vault.go` (modify, `InitVault`) | Three route registrations |
| `cmd/vault-webhook/` (new package) | `set` / `get` / `delete` commands + package-local `authz.go` |
| `cmd/vault_webhook.go` (new) | Cobra parent command, mirroring `cmd/vault_access.go` |

---

## Task 1: Migration

**Files:**
- Modify: `internal/db/db.go` (two sites: `createOptimizedSchema`, after the `key_rotation_policies` block ending ~`:517`; and `migrateSchema`, after the `key_rotation_policies` index strings ~`:825-826`)
- Test: `internal/db/vault_webhook_schema_test.go` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: table `vault_webhook_configs` with columns `id, vault_id, url, signing_secret_encrypted, enabled, created_at, updated_at`.

**Why two sites:** `createOptimizedSchema` runs only for a brand-new database; `migrateSchema` runs against a pre-existing one that never had the table. `key_rotation_policies` is registered in both (`:486` and `:806`) for exactly this reason. Registering in only one leaves half the installs broken.

- [ ] **Step 1: Write the failing test**

Create `internal/db/vault_webhook_schema_test.go`:

```go
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

// TestVaultWebhookConfigsTable_CreatedByBothSchemaPaths proves the table is
// registered in createOptimizedSchema AND migrateSchema. Registering it in
// only one leaves either fresh installs or upgraded installs without it --
// the exact dual-registration requirement key_rotation_policies has.
func TestVaultWebhookConfigsTable_CreatedByBothSchemaPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*sql.DB) error
	}{
		{"createOptimizedSchema", createOptimizedSchema},
		{"migrateSchema", migrateSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database, err := sql.Open("sqlite3", ":memory:")
			require.NoError(t, err)
			defer database.Close() //nolint:errcheck

			require.NoError(t, tc.run(database))

			var name string
			err = database.QueryRow(
				"SELECT name FROM sqlite_master WHERE type='table' AND name='vault_webhook_configs'",
			).Scan(&name)
			require.NoError(t, err, "vault_webhook_configs missing from %s", tc.name)
			require.Equal(t, "vault_webhook_configs", name)
		})
	}
}

// TestVaultWebhookConfigsTable_VaultIDIsUnique proves the one-config-per-vault
// invariant is enforced by the schema, not just by convention in the service.
func TestVaultWebhookConfigsTable_VaultIDIsUnique(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer database.Close() //nolint:errcheck
	require.NoError(t, createOptimizedSchema(database))

	insert := `INSERT INTO vault_webhook_configs
		(id, vault_id, url, signing_secret_encrypted, enabled)
		VALUES (?, ?, ?, ?, ?)`
	_, err = database.Exec(insert, "id-1", "vault-1", "https://a.example", "ct", true)
	require.NoError(t, err)

	_, err = database.Exec(insert, "id-2", "vault-1", "https://b.example", "ct", true)
	require.Error(t, err, "a second config for the same vault must violate UNIQUE(vault_id)")
}
```

**Note on signatures:** `createOptimizedSchema` and `migrateSchema` are package-private functions in `internal/db`. Before writing the test, confirm their exact signatures with `grep -n "func createOptimizedSchema\|func migrateSchema" internal/db/db.go` and adjust the `run` field's type to match (if either takes a dialect or config argument, pass the SQLite-appropriate value).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestVaultWebhookConfigsTable -v`
Expected: FAIL — `no such table: vault_webhook_configs`.

- [ ] **Step 3: Add the DDL to `createOptimizedSchema`**

In `internal/db/db.go`, immediately after the `key_rotation_policies` block and its index/comment (which ends around `:517`, just before `CREATE TABLE IF NOT EXISTS crl`), add to the same SQL string:

```sql
		CREATE TABLE IF NOT EXISTS vault_webhook_configs (
			id                       TEXT PRIMARY KEY,
			vault_id                 TEXT NOT NULL UNIQUE,
			url                      TEXT NOT NULL,
			signing_secret_encrypted TEXT NOT NULL,
			enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
			created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_vault_webhook_configs_vault_id ON vault_webhook_configs(vault_id);
```

- [ ] **Step 4: Add the identical DDL to `migrateSchema`**

In the `migrateSchema` statement slice, after the two `idx_key_rotation_policies_*` index strings (~`:825-826`), add two entries. Note the different syntax: `migrateSchema` holds a slice of individual statement strings, not one multi-statement string.

```go
		`CREATE TABLE IF NOT EXISTS vault_webhook_configs (
			id                       TEXT PRIMARY KEY,
			vault_id                 TEXT NOT NULL UNIQUE,
			url                      TEXT NOT NULL,
			signing_secret_encrypted TEXT NOT NULL,
			enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
			created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_vault_webhook_configs_vault_id ON vault_webhook_configs(vault_id)",
```

The column list must be **byte-identical** between the two sites (modulo the trailing `;` vs `,` the surrounding syntax requires). A divergence between fresh-install and upgraded schemas is the bug class this dual registration exists to prevent.

No SQLite/PostgreSQL dialect branching is needed: `key_rotation_policies` uses `BOOLEAN NOT NULL DEFAULT TRUE` and `TIMESTAMP DEFAULT CURRENT_TIMESTAMP` verbatim in both paths.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/db/ -run TestVaultWebhookConfigsTable -v`
Expected: PASS (3 subtests).

Then run the whole package to check nothing else regressed: `go test ./internal/db/`

- [ ] **Step 6: Commit**

```bash
git add internal/db/db.go internal/db/vault_webhook_schema_test.go
git commit -m "feat(db): add vault_webhook_configs table

Dual-registered in createOptimizedSchema and migrateSchema, matching
key_rotation_policies -- migrateSchema runs against pre-existing databases
that never had the table, createOptimizedSchema only for fresh ones.

UNIQUE(vault_id) enforces one config per vault at the schema level."
```

---

## Task 2: Domain and response types

**Files:**
- Create: `model/vault_webhook.go`
- Test: `model/vault_webhook_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `model.VaultWebhookConfig` struct — fields `ID uuid.UUID`, `VaultID uuid.UUID`, `URL string`, `SigningSecretEncrypted string`, `Enabled bool`, `CreatedAt time.Time`, `UpdatedAt time.Time`.
  - `func (c *VaultWebhookConfig) ToResponse() VaultWebhookConfigResponse`
  - `model.VaultWebhookConfigResponse` — `URL string`, `Enabled bool`, `CreatedAt string`, `UpdatedAt string` (RFC3339).
  - `model.VaultWebhookConfigCreatedResponse` — embeds `VaultWebhookConfigResponse`, adds `SigningSecret string`.
  - `func (r *VaultWebhookConfigResponse) ToJson() string`
  - `func (r *VaultWebhookConfigCreatedResponse) ToJson() string`
  - `model.UpsertVaultWebhookRequest` — `URL string`, `RotateSecret bool`, `Enabled *bool`.
  - `func UpsertVaultWebhookRequestFromJson(r io.Reader) (*UpsertVaultWebhookRequest, error)`

**Design note:** the response types are structurally separate from the domain type — not a trimmed or tagged version of it — so "this type cannot carry the secret" is true by construction rather than by remembering to blank a field. `VaultWebhookConfig` has no json tags at all, so it can never be marshaled into a response by accident.

- [ ] **Step 1: Write the failing test**

Create `model/vault_webhook_test.go`:

```go
package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultWebhookConfig_ToResponse_OmitsSecret is the load-bearing test for
// this file: the API-facing type must not carry the encrypted secret, so a
// handler cannot leak it by forwarding the wrong struct.
func TestVaultWebhookConfig_ToResponse_OmitsSecret(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	cfg := &VaultWebhookConfig{
		ID:                     uuid.New(),
		VaultID:                uuid.New(),
		URL:                    "https://hooks.example/rv",
		SigningSecretEncrypted: "SUPER-SECRET-CIPHERTEXT",
		Enabled:                true,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	resp := cfg.ToResponse()
	assert.Equal(t, "https://hooks.example/rv", resp.URL)
	assert.True(t, resp.Enabled)
	assert.Equal(t, "2026-08-19T12:00:00Z", resp.CreatedAt)
	assert.Equal(t, "2026-08-19T12:00:00Z", resp.UpdatedAt)

	encoded := resp.ToJson()
	assert.NotContains(t, encoded, "SUPER-SECRET-CIPHERTEXT")
	assert.NotContains(t, encoded, "signing_secret")
}

// TestVaultWebhookConfig_HasNoJsonTags proves the domain type cannot be
// marshaled into a response shape by accident -- marshaling it yields Go
// field names, not the API's snake_case contract, so any handler that
// forwarded it directly would produce visibly wrong output caught by tests.
func TestVaultWebhookConfig_HasNoJsonTags(t *testing.T) {
	b, err := json.Marshal(&VaultWebhookConfig{URL: "https://x.example"})
	require.NoError(t, err)
	assert.Contains(t, string(b), `"URL"`, "domain type must not carry snake_case json tags")
}

// TestVaultWebhookConfigCreatedResponse_CarriesSecret is the counterpart:
// exactly one shape may carry the plaintext, and this is it.
func TestVaultWebhookConfigCreatedResponse_CarriesSecret(t *testing.T) {
	resp := VaultWebhookConfigCreatedResponse{
		VaultWebhookConfigResponse: VaultWebhookConfigResponse{
			URL:     "https://hooks.example/rv",
			Enabled: true,
		},
		SigningSecret: "plaintext-secret",
	}
	encoded := resp.ToJson()
	assert.Contains(t, encoded, `"signing_secret":"plaintext-secret"`)
	assert.Contains(t, encoded, `"url":"https://hooks.example/rv"`)
}

func TestUpsertVaultWebhookRequestFromJson(t *testing.T) {
	t.Run("enabled omitted stays nil", func(t *testing.T) {
		req, err := UpsertVaultWebhookRequestFromJson(strings.NewReader(`{"url":"https://a.example"}`))
		require.NoError(t, err)
		assert.Equal(t, "https://a.example", req.URL)
		assert.False(t, req.RotateSecret)
		assert.Nil(t, req.Enabled, "an omitted enabled must be nil, not false")
	})

	t.Run("enabled false is distinguishable from omitted", func(t *testing.T) {
		req, err := UpsertVaultWebhookRequestFromJson(strings.NewReader(`{"url":"https://a.example","enabled":false}`))
		require.NoError(t, err)
		require.NotNil(t, req.Enabled)
		assert.False(t, *req.Enabled)
	})

	t.Run("rotate_secret parses", func(t *testing.T) {
		req, err := UpsertVaultWebhookRequestFromJson(strings.NewReader(`{"url":"https://a.example","rotate_secret":true}`))
		require.NoError(t, err)
		assert.True(t, req.RotateSecret)
	})

	t.Run("malformed json errors", func(t *testing.T) {
		_, err := UpsertVaultWebhookRequestFromJson(strings.NewReader(`{`))
		assert.Error(t, err)
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/ -run VaultWebhook -v`
Expected: FAIL — `undefined: VaultWebhookConfig`.

- [ ] **Step 3: Write the implementation**

Create `model/vault_webhook.go`:

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// VaultWebhookConfig is a vault's webhook notification target. One row per
// vault, enforced by UNIQUE(vault_id).
//
// The signing secret is stored encrypted (common.EncryptSecret) and this type
// deliberately carries no json tags: it must never be marshaled into an API
// response. Responses are built from the separate, secret-less
// VaultWebhookConfigResponse below, so "the API shape cannot carry the secret"
// is true by construction rather than by remembering to clear a field.
type VaultWebhookConfig struct {
	ID                     uuid.UUID
	VaultID                uuid.UUID
	URL                    string
	SigningSecretEncrypted string
	Enabled                bool
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// ToResponse builds the API-facing shape, dropping the encrypted secret and
// formatting timestamps as RFC3339 strings to match VaultResponse.
func (c *VaultWebhookConfig) ToResponse() VaultWebhookConfigResponse {
	return VaultWebhookConfigResponse{
		URL:       c.URL,
		Enabled:   c.Enabled,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
	}
}

// VaultWebhookConfigResponse is the API-facing shape. It has no field for the
// signing secret in any form, encrypted or plain.
type VaultWebhookConfigResponse struct {
	URL       string `json:"url"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ToJson serializes the response.
func (r *VaultWebhookConfigResponse) ToJson() string {
	b, _ := json.Marshal(r) //nolint:errchkjson
	return string(b)
}

// VaultWebhookConfigCreatedResponse is returned exactly once, from the PUT
// that creates the config or rotates its secret. It is the only shape in this
// feature that ever carries SigningSecret in plaintext.
type VaultWebhookConfigCreatedResponse struct {
	VaultWebhookConfigResponse
	SigningSecret string `json:"signing_secret"`
}

// ToJson serializes the create/rotate response.
func (r *VaultWebhookConfigCreatedResponse) ToJson() string {
	b, _ := json.Marshal(r) //nolint:errchkjson
	return string(b)
}

// UpsertVaultWebhookRequest is the PUT body.
//
// Enabled is a pointer so an omitted field is distinguishable from an explicit
// false: with a bare bool, PUT {"url": "..."} would silently disable the
// webhook. Nil means "keep the current value" (true on create).
//
// There is no client-supplied secret field. The server mints the secret; set
// RotateSecret to replace an existing one.
type UpsertVaultWebhookRequest struct {
	URL          string `json:"url"`
	RotateSecret bool   `json:"rotate_secret"`
	Enabled      *bool  `json:"enabled"`
}

// UpsertVaultWebhookRequestFromJson decodes a PUT body.
func UpsertVaultWebhookRequestFromJson(r io.Reader) (*UpsertVaultWebhookRequest, error) {
	var req UpsertVaultWebhookRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./model/ -run VaultWebhook -v`
Expected: PASS (all subtests).

If the `//nolint:errchkjson` directive is rejected by this repo's linter config, match whatever directive `model/vault.go:176-179` uses on its own `json.Marshal` and use that instead.

- [ ] **Step 5: Commit**

```bash
git add model/vault_webhook.go model/vault_webhook_test.go
git commit -m "feat(model): add VaultWebhookConfig and its response types

The domain type carries no json tags and the API response type has no
secret field at all, so the API shape structurally cannot leak the signing
secret -- the same separation model.KeyVersion/KeyVersionRecord uses.

UpsertVaultWebhookRequest.Enabled is *bool so an omitted field is
distinguishable from an explicit false, which would otherwise silently
disable a webhook on a URL-only update."
```

---

## Task 3: Repository

**Files:**
- Create: `internal/repositories/vault_webhook_repository.go`
- Test: `internal/repositories/vault_webhook_repository_test.go`

**Interfaces:**
- Consumes: `model.VaultWebhookConfig` (Task 2); `repositories.ErrNotFound` (`internal/repositories/errors.go:10`).
- Produces:
  ```go
  type VaultWebhookRepositoryInterface interface {
      Upsert(ctx context.Context, cfg *model.VaultWebhookConfig) error
      GetByVaultID(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error)
      DeleteByVaultID(ctx context.Context, vaultID uuid.UUID) error
  }
  func NewVaultWebhookRepository(database db.DB, log *logging.Logger) VaultWebhookRepositoryInterface
  ```

Per correction C1 there is no `model.Scope` parameter, and per C3 `Upsert` returns only `error`.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/vault_webhook_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupWebhookTestDB creates an in-memory SQLite database with just the
// vault_webhook_configs table. A shared-cache DSN keeps every pooled
// connection on the same schema, matching setupTestDB in key_soft_delete_test.go.
func setupWebhookTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:webhooktest_" + uuid.NewString() + "?mode=memory&cache=shared"
	database, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })

	_, err = database.Exec(`
		CREATE TABLE IF NOT EXISTS vault_webhook_configs (
			id                       TEXT PRIMARY KEY,
			vault_id                 TEXT NOT NULL UNIQUE,
			url                      TEXT NOT NULL,
			signing_secret_encrypted TEXT NOT NULL,
			enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
			created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`)
	require.NoError(t, err)
	return database
}

func newWebhookRepo(t *testing.T, database *sql.DB) repositories.VaultWebhookRepositoryInterface {
	t.Helper()
	return repositories.NewVaultWebhookRepository(rvdb.NewSQLDB(database), logging.NewLogger())
}

func sampleConfig(vaultID uuid.UUID, url, ciphertext string) *model.VaultWebhookConfig {
	now := time.Now().UTC().Truncate(time.Second)
	return &model.VaultWebhookConfig{
		ID:                     uuid.New(),
		VaultID:                vaultID,
		URL:                    url,
		SigningSecretEncrypted: ciphertext,
		Enabled:                true,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
}

func TestVaultWebhookRepository_Upsert_CreatesThenReplaces(t *testing.T) {
	database := setupWebhookTestDB(t)
	repo := newWebhookRepo(t, database)
	ctx := context.Background()
	vaultID := uuid.New()

	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultID, "https://first.example", "ct-1")))

	got, err := repo.GetByVaultID(ctx, vaultID)
	require.NoError(t, err)
	assert.Equal(t, "https://first.example", got.URL)
	assert.Equal(t, "ct-1", got.SigningSecretEncrypted)

	// A second Upsert for the same vault replaces rather than duplicating.
	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultID, "https://second.example", "ct-2")))

	got, err = repo.GetByVaultID(ctx, vaultID)
	require.NoError(t, err)
	assert.Equal(t, "https://second.example", got.URL)
	assert.Equal(t, "ct-2", got.SigningSecretEncrypted)

	var count int
	require.NoError(t, database.QueryRow(
		"SELECT COUNT(*) FROM vault_webhook_configs WHERE vault_id = ?", vaultID.String(),
	).Scan(&count))
	assert.Equal(t, 1, count, "Upsert must replace, never duplicate")
}

func TestVaultWebhookRepository_GetByVaultID_UnknownReturnsErrNotFound(t *testing.T) {
	repo := newWebhookRepo(t, setupWebhookTestDB(t))

	_, err := repo.GetByVaultID(context.Background(), uuid.New())
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrNotFound), "expected ErrNotFound, got %v", err)
}

// TestVaultWebhookRepository_GetByVaultID_RealErrorIsNotErrNotFound proves a
// genuine failure is not laundered into a not-found, which would make a
// database outage look like an absent config.
func TestVaultWebhookRepository_GetByVaultID_RealErrorIsNotErrNotFound(t *testing.T) {
	database := setupWebhookTestDB(t)
	repo := newWebhookRepo(t, database)
	require.NoError(t, database.Close())

	_, err := repo.GetByVaultID(context.Background(), uuid.New())
	require.Error(t, err)
	assert.False(t, errors.Is(err, repositories.ErrNotFound), "a closed-DB error must not look like not-found")
}

func TestVaultWebhookRepository_DeleteByVaultID(t *testing.T) {
	repo := newWebhookRepo(t, setupWebhookTestDB(t))
	ctx := context.Background()
	vaultID := uuid.New()
	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultID, "https://a.example", "ct")))

	require.NoError(t, repo.DeleteByVaultID(ctx, vaultID))

	_, err := repo.GetByVaultID(ctx, vaultID)
	assert.True(t, errors.Is(err, repositories.ErrNotFound))
}

// TestVaultWebhookRepository_DeleteByVaultID_UnknownIsNotAnError keeps delete
// idempotent: the vault-purge cleanup hook calls this for every purged vault,
// including the overwhelming majority that never configured a webhook.
func TestVaultWebhookRepository_DeleteByVaultID_UnknownIsNotAnError(t *testing.T) {
	repo := newWebhookRepo(t, setupWebhookTestDB(t))
	assert.NoError(t, repo.DeleteByVaultID(context.Background(), uuid.New()))
}

func TestVaultWebhookRepository_Upsert_IsolatesVaults(t *testing.T) {
	repo := newWebhookRepo(t, setupWebhookTestDB(t))
	ctx := context.Background()
	vaultA, vaultB := uuid.New(), uuid.New()

	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultA, "https://a.example", "ct-a")))
	require.NoError(t, repo.Upsert(ctx, sampleConfig(vaultB, "https://b.example", "ct-b")))

	gotA, err := repo.GetByVaultID(ctx, vaultA)
	require.NoError(t, err)
	assert.Equal(t, "https://a.example", gotA.URL)

	gotB, err := repo.GetByVaultID(ctx, vaultB)
	require.NoError(t, err)
	assert.Equal(t, "https://b.example", gotB.URL)
}
```

**Before running:** confirm the constructor name for wrapping a `*sql.DB` into this repo's `db.DB` interface with `grep -rn "func NewSQLDB\|func New(" internal/db/*.go | head`. If the helper has a different name, adjust `newWebhookRepo` and mirror however `key_rotation_policy_repository_test.go` constructs its repository.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run VaultWebhookRepository -v`
Expected: FAIL — `undefined: repositories.NewVaultWebhookRepository`.

- [ ] **Step 3: Write the implementation**

Create `internal/repositories/vault_webhook_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// VaultWebhookRepositoryInterface defines pure CRUD for per-vault webhook
// configuration. One row per vault, enforced by UNIQUE(vault_id).
//
// Unlike the data-plane repositories (secrets, keys, certificates, key
// rotation policies) these methods take no model.Scope: webhook config is
// vault-management-tier, authorized by CanManageVault at the API and CLI
// edges, exactly as VaultRepositoryInterface is.
type VaultWebhookRepositoryInterface interface {
	// Upsert inserts the vault's config, or replaces url, signing secret,
	// enabled and updated_at if a row already exists. The caller supplies
	// the ciphertext; this layer never encrypts or decrypts.
	Upsert(ctx context.Context, cfg *model.VaultWebhookConfig) error
	// GetByVaultID returns the vault's config, or an error wrapping
	// ErrNotFound if the vault has none. The returned config includes
	// SigningSecretEncrypted; callers building an API response must use
	// model.VaultWebhookConfig.ToResponse rather than forwarding this value.
	GetByVaultID(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error)
	// DeleteByVaultID removes the vault's config. Deleting a vault that has
	// no config is not an error -- the vault-purge cleanup hook calls this
	// unconditionally.
	DeleteByVaultID(ctx context.Context, vaultID uuid.UUID) error
}

// VaultWebhookRepository is the default database-backed implementation.
type VaultWebhookRepository struct {
	db  db.DB
	log *logging.Logger
}

// NewVaultWebhookRepository creates a new VaultWebhookRepository.
func NewVaultWebhookRepository(database db.DB, log *logging.Logger) VaultWebhookRepositoryInterface {
	return &VaultWebhookRepository{db: database, log: log}
}

// Upsert inserts a new config or replaces the existing one for the same vault.
func (r *VaultWebhookRepository) Upsert(ctx context.Context, cfg *model.VaultWebhookConfig) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO vault_webhook_configs
			(id, vault_id, url, signing_secret_encrypted, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(vault_id) DO UPDATE SET
			url                      = excluded.url,
			signing_secret_encrypted = excluded.signing_secret_encrypted,
			enabled                  = excluded.enabled,
			updated_at               = excluded.updated_at`,
		cfg.ID.String(), cfg.VaultID.String(), cfg.URL,
		cfg.SigningSecretEncrypted, cfg.Enabled, cfg.CreatedAt, cfg.UpdatedAt,
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to upsert vault webhook config")
		return fmt.Errorf("upsert vault webhook config: %w", err)
	}
	return nil
}

// GetByVaultID retrieves the vault's webhook config.
func (r *VaultWebhookRepository) GetByVaultID(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error) {
	var (
		cfg     model.VaultWebhookConfig
		idStr   string
		vidStr  string
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT id, vault_id, url, signing_secret_encrypted, enabled, created_at, updated_at
		FROM vault_webhook_configs WHERE vault_id = ?`, vaultID.String(),
	).Scan(&idStr, &vidStr, &cfg.URL, &cfg.SigningSecretEncrypted,
		&cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("webhook config for vault %s: %w", vaultID, ErrNotFound)
		}
		return nil, fmt.Errorf("read vault webhook config: %w", err)
	}

	if cfg.ID, err = uuid.Parse(idStr); err != nil {
		return nil, fmt.Errorf("parse webhook config id %q: %w", idStr, err)
	}
	if cfg.VaultID, err = uuid.Parse(vidStr); err != nil {
		return nil, fmt.Errorf("parse webhook config vault_id %q: %w", vidStr, err)
	}
	return &cfg, nil
}

// DeleteByVaultID removes the vault's webhook config, if any.
func (r *VaultWebhookRepository) DeleteByVaultID(ctx context.Context, vaultID uuid.UUID) error {
	if _, err := r.db.ExecContext(ctx,
		"DELETE FROM vault_webhook_configs WHERE vault_id = ?", vaultID.String(),
	); err != nil {
		r.log.WithError(err).Error("Failed to delete vault webhook config")
		return fmt.Errorf("delete vault webhook config: %w", err)
	}
	return nil
}
```

**If `created_at`/`updated_at` fail to scan into `time.Time`** on SQLite, check how a neighbouring repository handles it — `key_rotation_policy_repository.go`'s `scanKeyRotationPolicyRow` is the reference — and match its approach (the driver usually needs `parseTime` in the DSN or a `sql.NullTime` intermediate).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/repositories/ -run VaultWebhookRepository -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/vault_webhook_repository.go internal/repositories/vault_webhook_repository_test.go
git commit -m "feat(repositories): add VaultWebhookRepository

Pure CRUD over vault_webhook_configs, with the ON CONFLICT(vault_id) DO
UPDATE idiom KeyRotationPolicyRepository.Upsert uses.

No model.Scope parameter: webhook config is vault-management-tier like
VaultRepository, not data-plane like the secret/key/cert repositories, so
authorization happens at the API and CLI edges via CanManageVault."
```

---

## Task 4: Webhook service

**Files:**
- Create: `internal/services/vaults/webhook_service.go`
- Test: `internal/services/vaults/webhook_service_test.go`

**Interfaces:**
- Consumes: `repositories.VaultWebhookRepositoryInterface` (Task 3), `model.VaultWebhookConfig` (Task 2), `common.EncryptSecret`/`common.DecryptSecret` (`common/encrypt.go:152,170`).
- Produces:
  ```go
  type VaultWebhookService interface {
      Upsert(ctx context.Context, vaultID uuid.UUID, req UpsertWebhookRequest) (cfg *model.VaultWebhookConfig, plaintextSecret string, err error)
      Get(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error)
      Delete(ctx context.Context, vaultID uuid.UUID) error
  }
  type UpsertWebhookRequest struct {
      URL          string
      RotateSecret bool
      Enabled      *bool
  }
  var ErrWebhookNotFound = errors.New("webhook config not found")
  var ErrInvalidWebhookURL = errors.New("webhook url must be an absolute https URL")
  func NewVaultWebhookService(repo repositories.VaultWebhookRepositoryInterface, log *logging.Logger) VaultWebhookService
  ```

Per correction C1, no `model.Scope` and no `CanManageVault` call.

**The `Upsert` sequence** (spec §4, minus the authorization step which moved to the edges):

1. Validate the URL: `url.Parse` must succeed, `Scheme == "https"`, `Host` non-empty. Otherwise return `ErrInvalidWebhookURL`.
2. Read the existing row to learn whether this is a create and to recover the current ciphertext.
3. Mint or carry the secret. On create, or on update with `RotateSecret: true`, generate 32 bytes via `crypto/rand.Read`, base64-encode, and encrypt with `common.EncryptSecret`. Otherwise carry the existing ciphertext through untouched — never decrypt-then-re-encrypt an unrotated secret.
4. Resolve `Enabled`: nil keeps the current value on update, and defaults to `true` on create.
5. `Upsert`, and return the plaintext only if step 3 minted one.

- [ ] **Step 1: Write the failing test**

Create `internal/services/vaults/webhook_service_test.go`:

```go
package vaults_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// fakeWebhookRepo is an in-memory VaultWebhookRepositoryInterface. A hand-
// written fake rather than a testify mock: these tests assert on stored state
// across successive calls, which a fake expresses far more directly.
type fakeWebhookRepo struct {
	rows    map[uuid.UUID]*model.VaultWebhookConfig
	upserts int
	failGet error
}

func newFakeWebhookRepo() *fakeWebhookRepo {
	return &fakeWebhookRepo{rows: map[uuid.UUID]*model.VaultWebhookConfig{}}
}

func (f *fakeWebhookRepo) Upsert(_ context.Context, cfg *model.VaultWebhookConfig) error {
	f.upserts++
	clone := *cfg
	f.rows[cfg.VaultID] = &clone
	return nil
}

func (f *fakeWebhookRepo) GetByVaultID(_ context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error) {
	if f.failGet != nil {
		return nil, f.failGet
	}
	cfg, ok := f.rows[vaultID]
	if !ok {
		return nil, repositories.ErrNotFound
	}
	clone := *cfg
	return &clone, nil
}

func (f *fakeWebhookRepo) DeleteByVaultID(_ context.Context, vaultID uuid.UUID) error {
	delete(f.rows, vaultID)
	return nil
}

func newWebhookService(repo repositories.VaultWebhookRepositoryInterface) vaults.VaultWebhookService {
	return vaults.NewVaultWebhookService(repo, logging.NewLogger())
}

func TestWebhookService_Upsert_CreateMintsAndReturnsSecret(t *testing.T) {
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	vaultID := uuid.New()

	cfg, secret, err := svc.Upsert(context.Background(), vaultID,
		vaults.UpsertWebhookRequest{URL: "https://hooks.example/rv"})
	require.NoError(t, err)

	assert.NotEmpty(t, secret, "create must mint and return a secret")
	assert.Equal(t, "https://hooks.example/rv", cfg.URL)
	assert.True(t, cfg.Enabled, "enabled defaults to true on create")

	// The stored value is ciphertext that decrypts back to what we returned.
	assert.NotEqual(t, secret, cfg.SigningSecretEncrypted, "the secret must be stored encrypted")
	decrypted, err := common.DecryptSecret(cfg.SigningSecretEncrypted)
	require.NoError(t, err)
	assert.Equal(t, secret, decrypted)
}

// TestWebhookService_Upsert_SecretsAreUnpredictable guards the crypto/rand
// source: a constant or a counter would pass every other test in this file.
func TestWebhookService_Upsert_SecretsAreUnpredictable(t *testing.T) {
	svc := newWebhookService(newFakeWebhookRepo())
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		_, secret, err := svc.Upsert(context.Background(), uuid.New(),
			vaults.UpsertWebhookRequest{URL: "https://hooks.example/rv"})
		require.NoError(t, err)
		require.False(t, seen[secret], "minted a duplicate secret on iteration %d", i)
		require.GreaterOrEqual(t, len(secret), 40, "32 random bytes must not base64 to fewer than 40 chars")
		seen[secret] = true
	}
}

func TestWebhookService_Upsert_UpdateWithoutRotateKeepsSecret(t *testing.T) {
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	created, firstSecret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://first.example"})
	require.NoError(t, err)
	require.NotEmpty(t, firstSecret)

	updated, secret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://second.example"})
	require.NoError(t, err)

	assert.Empty(t, secret, "an update that did not rotate must return no secret")
	assert.Equal(t, "https://second.example", updated.URL)
	assert.Equal(t, created.SigningSecretEncrypted, updated.SigningSecretEncrypted,
		"the stored ciphertext must be byte-identical when not rotating")
}

func TestWebhookService_Upsert_RotateMintsNewSecret(t *testing.T) {
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	created, firstSecret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example"})
	require.NoError(t, err)

	rotated, secondSecret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example", RotateSecret: true})
	require.NoError(t, err)

	assert.NotEmpty(t, secondSecret, "a rotate must return the new secret")
	assert.NotEqual(t, firstSecret, secondSecret)
	assert.NotEqual(t, created.SigningSecretEncrypted, rotated.SigningSecretEncrypted)

	decrypted, err := common.DecryptSecret(rotated.SigningSecretEncrypted)
	require.NoError(t, err)
	assert.Equal(t, secondSecret, decrypted)
}

// TestWebhookService_Upsert_NilEnabledKeepsStoredValue is the regression test
// for the bare-bool trap the *bool type exists to avoid: a URL-only update
// must not silently disable the webhook.
func TestWebhookService_Upsert_NilEnabledKeepsStoredValue(t *testing.T) {
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()
	disabled := false

	_, _, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example", Enabled: &disabled})
	require.NoError(t, err)

	updated, _, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://b.example"}) // Enabled nil
	require.NoError(t, err)
	assert.False(t, updated.Enabled, "a nil Enabled must keep the stored value, not reset it")

	enabled := true
	reenabled, _, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://b.example", Enabled: &enabled})
	require.NoError(t, err)
	assert.True(t, reenabled.Enabled)
}

func TestWebhookService_Upsert_RejectsBadURLs(t *testing.T) {
	svc := newWebhookService(newFakeWebhookRepo())
	for _, tc := range []struct{ name, url string }{
		{"http scheme", "http://hooks.example/rv"},
		{"no scheme", "hooks.example/rv"},
		{"scheme only, no host", "https://"},
		{"empty", ""},
		{"unparseable", "https://exa mple.com/\x7f"},
		{"not a url", "::::"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.Upsert(context.Background(), uuid.New(),
				vaults.UpsertWebhookRequest{URL: tc.url})
			require.Error(t, err)
			assert.True(t, errors.Is(err, vaults.ErrInvalidWebhookURL),
				"expected ErrInvalidWebhookURL, got %v", err)
		})
	}
}

// TestWebhookService_Upsert_RejectsBadURLBeforeTouchingRepo proves validation
// happens first, so an invalid request never reaches storage.
func TestWebhookService_Upsert_RejectsBadURLBeforeTouchingRepo(t *testing.T) {
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)

	_, _, err := svc.Upsert(context.Background(), uuid.New(),
		vaults.UpsertWebhookRequest{URL: "http://insecure.example"})
	require.Error(t, err)
	assert.Zero(t, repo.upserts, "an invalid URL must not reach the repository")
}

func TestWebhookService_Get_UnknownReturnsErrWebhookNotFound(t *testing.T) {
	svc := newWebhookService(newFakeWebhookRepo())

	_, err := svc.Get(context.Background(), uuid.New())
	require.Error(t, err)
	assert.True(t, errors.Is(err, vaults.ErrWebhookNotFound), "expected ErrWebhookNotFound, got %v", err)
}

// TestWebhookService_Get_RealRepoErrorIsNotNotFound keeps a database outage
// from being reported to the caller as "no webhook configured".
func TestWebhookService_Get_RealRepoErrorIsNotNotFound(t *testing.T) {
	repo := newFakeWebhookRepo()
	repo.failGet = errors.New("database is locked")
	svc := newWebhookService(repo)

	_, err := svc.Get(context.Background(), uuid.New())
	require.Error(t, err)
	assert.False(t, errors.Is(err, vaults.ErrWebhookNotFound))
}

func TestWebhookService_Get_DoesNotDecrypt(t *testing.T) {
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	_, secret, err := svc.Upsert(ctx, vaultID, vaults.UpsertWebhookRequest{URL: "https://a.example"})
	require.NoError(t, err)

	got, err := svc.Get(ctx, vaultID)
	require.NoError(t, err)
	assert.NotEqual(t, secret, got.SigningSecretEncrypted, "Get must return ciphertext, never plaintext")
}

func TestWebhookService_Delete(t *testing.T) {
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()
	_, _, err := svc.Upsert(ctx, vaultID, vaults.UpsertWebhookRequest{URL: "https://a.example"})
	require.NoError(t, err)

	require.NoError(t, svc.Delete(ctx, vaultID))

	_, err = svc.Get(ctx, vaultID)
	assert.True(t, errors.Is(err, vaults.ErrWebhookNotFound))
}

func TestWebhookService_Upsert_StampsTimestamps(t *testing.T) {
	svc := newWebhookService(newFakeWebhookRepo())
	before := time.Now().UTC().Add(-time.Second)

	cfg, _, err := svc.Upsert(context.Background(), uuid.New(),
		vaults.UpsertWebhookRequest{URL: "https://a.example"})
	require.NoError(t, err)
	assert.False(t, cfg.CreatedAt.Before(before))
	assert.False(t, cfg.UpdatedAt.Before(before))
}
```

**Note:** `common.EncryptSecret` needs the master key initialized. Check how existing tests in `internal/services/` that call it set that up (`grep -rn "EncryptSecret" --include="*_test.go" internal/ | head`) and add the same `TestMain` or setup helper to this file if required. If encryption cannot be initialized in a unit test, inject the encrypt/decrypt pair as function fields on the service struct defaulting to `common.EncryptSecret`/`common.DecryptSecret`, and have the tests substitute identity functions — but prefer the real thing if it works, since the round-trip is part of what these tests exist to verify.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestWebhookService -v`
Expected: FAIL — `undefined: vaults.NewVaultWebhookService`.

- [ ] **Step 3: Write the implementation**

Create `internal/services/vaults/webhook_service.go`:

```go
package vaults

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ErrWebhookNotFound is returned when a vault has no webhook config.
var ErrWebhookNotFound = errors.New("webhook config not found")

// ErrInvalidWebhookURL is returned when the supplied URL is not an absolute
// https URL with a host. Validation is deliberately minimal: SSRF policy
// (private-range blocking, allowlists, redirect handling) belongs to the
// sub-project that actually makes the outbound call, not to a layer that
// never dials anything.
var ErrInvalidWebhookURL = errors.New("webhook url must be an absolute https URL")

// webhookSecretBytes is the entropy of a generated signing secret, before
// base64 encoding.
const webhookSecretBytes = 32

// UpsertWebhookRequest is the service-layer input for creating or updating a
// vault's webhook config.
//
// There is no client-supplied secret: the server mints it. RotateSecret
// replaces an existing secret; Enabled is a pointer so nil means "keep the
// current value" rather than "set false".
type UpsertWebhookRequest struct {
	URL          string
	RotateSecret bool
	Enabled      *bool
}

// VaultWebhookService manages per-vault webhook configuration.
//
// It performs no authorization. Callers authorize with
// authorization.CanManageVault before invoking it -- the API handlers in
// api/vault_webhook.go and the CLI in cmd/vault-webhook/authz.go -- which is
// the same edge-authorized split VaultService and VaultRepository already use.
type VaultWebhookService interface {
	// Upsert creates or updates the vault's config. plaintextSecret is
	// non-empty only when this call minted a secret: always on create, and on
	// update only when req.RotateSecret is true. That empty/non-empty
	// distinction is how the caller knows whether to show the secret.
	Upsert(ctx context.Context, vaultID uuid.UUID, req UpsertWebhookRequest) (cfg *model.VaultWebhookConfig, plaintextSecret string, err error)
	// Get returns the vault's config, or ErrWebhookNotFound. The returned
	// config carries the encrypted secret, never the plaintext.
	Get(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error)
	// Delete removes the vault's config. Deleting when none exists succeeds.
	Delete(ctx context.Context, vaultID uuid.UUID) error
}

type vaultWebhookService struct {
	repo repositories.VaultWebhookRepositoryInterface
	log  *logging.Logger
}

// NewVaultWebhookService constructs a VaultWebhookService over the given repository.
func NewVaultWebhookService(repo repositories.VaultWebhookRepositoryInterface, log *logging.Logger) VaultWebhookService {
	return &vaultWebhookService{repo: repo, log: log}
}

// validateWebhookURL enforces an absolute https URL with a host.
func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidWebhookURL, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%w: got scheme %q", ErrInvalidWebhookURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidWebhookURL)
	}
	return nil
}

// mintSecret returns a new base64-encoded signing secret.
func mintSecret() (string, error) {
	buf := make([]byte, webhookSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate webhook signing secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Upsert creates or updates the vault's webhook config.
func (s *vaultWebhookService) Upsert(ctx context.Context, vaultID uuid.UUID, req UpsertWebhookRequest) (*model.VaultWebhookConfig, string, error) {
	// 1. Validate before touching storage.
	if err := validateWebhookURL(req.URL); err != nil {
		return nil, "", err
	}

	// 2. Learn whether this is a create, and recover the current ciphertext.
	existing, err := s.repo.GetByVaultID(ctx, vaultID)
	if err != nil && !errors.Is(err, repositories.ErrNotFound) {
		return nil, "", fmt.Errorf("read existing webhook config: %w", err)
	}
	creating := existing == nil

	now := time.Now().UTC()
	cfg := &model.VaultWebhookConfig{
		VaultID:   vaultID,
		URL:       req.URL,
		UpdatedAt: now,
	}

	// 3. Mint a secret on create or explicit rotate; otherwise carry the
	// existing ciphertext through untouched. An unrotated secret is never
	// decrypted -- nothing in this sub-project needs its plaintext.
	var plaintextSecret string
	if creating || req.RotateSecret {
		plaintextSecret, err = mintSecret()
		if err != nil {
			return nil, "", err
		}
		ciphertext, encErr := common.EncryptSecret(plaintextSecret)
		if encErr != nil {
			return nil, "", fmt.Errorf("encrypt webhook signing secret: %w", encErr)
		}
		cfg.SigningSecretEncrypted = ciphertext
	} else {
		cfg.SigningSecretEncrypted = existing.SigningSecretEncrypted
	}

	// 4. Resolve identity, timestamps and the enabled flag.
	if creating {
		cfg.ID = uuid.New()
		cfg.CreatedAt = now
		cfg.Enabled = true
	} else {
		cfg.ID = existing.ID
		cfg.CreatedAt = existing.CreatedAt
		cfg.Enabled = existing.Enabled
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}

	// 5. Persist, and return the plaintext only if this call minted one.
	if err := s.repo.Upsert(ctx, cfg); err != nil {
		return nil, "", err
	}
	s.log.WithFields(map[string]any{
		"vault_id": vaultID.String(),
		"created":  creating,
		"rotated":  plaintextSecret != "",
	}).Info("Vault webhook config saved")

	return cfg, plaintextSecret, nil
}

// Get returns the vault's webhook config.
func (s *vaultWebhookService) Get(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error) {
	cfg, err := s.repo.GetByVaultID(ctx, vaultID)
	if err != nil {
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("vault %s: %w", vaultID, ErrWebhookNotFound)
		}
		return nil, err
	}
	return cfg, nil
}

// Delete removes the vault's webhook config.
func (s *vaultWebhookService) Delete(ctx context.Context, vaultID uuid.UUID) error {
	return s.repo.DeleteByVaultID(ctx, vaultID)
}
```

**On the log call:** match this repo's actual logger API. If `*logging.Logger` has no `WithFields(map[string]any)`, use whatever shape `vault_service.go` uses for structured logging. The fields must never include the secret.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/vaults/ -run TestWebhookService -v`
Expected: PASS (all tests, including the 6 URL subtests).

Then the whole package: `go test ./internal/services/vaults/`

- [ ] **Step 5: Commit**

```bash
git add internal/services/vaults/webhook_service.go internal/services/vaults/webhook_service_test.go
git commit -m "feat(vaults): add VaultWebhookService

Server-minted signing secret (32 bytes from crypto/rand, base64), encrypted
at rest with common.EncryptSecret and returned in plaintext exactly once --
on create, or on an explicit rotate. An unrotated secret is carried through
as ciphertext and never decrypted.

URL validation is deliberately minimal (absolute https with a host); SSRF
policy belongs to the sub-project that actually dials.

The service performs no authorization: callers authorize via CanManageVault
at the API and CLI edges, matching VaultService."
```

---

## Task 5: Purge cleanup hook

**Files:**
- Modify: `internal/services/vaults/vault_service.go` (add `WebhookCleaner` next to `PolicyCleaner` ~`:61-64`; add `SetWebhookCleaner` to the `VaultService` interface ~`:116` and the struct ~`:125`; call it in `PurgeVault` ~`:471`)
- Test: `internal/services/vaults/vault_service_webhook_cleanup_test.go`

**Interfaces:**
- Consumes: nothing from Task 4 directly — the hook is an interface satisfied by `VaultWebhookRepositoryInterface`'s `DeleteByVaultID` (Task 3). Wiring happens in Task 6.
- Produces: `vaults.WebhookCleaner` interface, `VaultService.SetWebhookCleaner(c WebhookCleaner)`.

**Why this task exists (correction C2):** the `ON DELETE CASCADE` clause in Task 1 does not fire on SQLite, where the `foreign_keys` PRAGMA is off in this project (`internal/db/db.go:952`, `internal/db/audit_fk_test.go:6`). `PurgeVault` already documents this at `vault_service.go:465-467` and purges secrets/keys/certs explicitly for the same reason. Without this hook, purging a vault strands a row holding an encrypted signing secret forever — unreachable but never removed.

`PolicyCleaner` (`vault_service.go:61-64`, set via `SetPolicyCleaner`, invoked in `PurgeVault` right after `PurgeVaultContents`) is the exact precedent: an optional injected cleaner for a table the cascade adapter does not cover. Follow it rather than extending `cascadeAdapter`, whose `vaultContentRepo` interface is soft-delete-shaped (`SoftDeleteVaultContents`/`RecoverVaultContents`) and does not fit a table with no soft-delete columns.

- [ ] **Step 1: Read the surrounding code**

Read `internal/services/vaults/vault_service.go` lines 55-135 (the hook interfaces and the service struct) and the tail of `PurgeVault` from `:459` to the end of the function, to see exactly how `s.policies.DeleteByVault` is guarded and where its error goes. Match that shape exactly.

- [ ] **Step 2: Write the failing test**

Create `internal/services/vaults/vault_service_webhook_cleanup_test.go`. Construct the `VaultService` the same way the existing tests in this package do — read `vault_service_test.go` (or whichever file holds the package's purge tests) for the established setup helper and reuse it rather than inventing a new one.

```go
package vaults_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spyWebhookCleaner records the vault ids it was asked to clean.
type spyWebhookCleaner struct {
	cleaned []uuid.UUID
	err     error
}

func (s *spyWebhookCleaner) DeleteByVaultID(_ context.Context, vaultID uuid.UUID) error {
	s.cleaned = append(s.cleaned, vaultID)
	return s.err
}

// TestPurgeVault_RemovesWebhookConfig is the real cascade test. The DDL's ON
// DELETE CASCADE is inert on SQLite (the foreign_keys PRAGMA is off in this
// project), so the application-level hook is the actual mechanism keeping a
// purged vault from stranding a row that holds an encrypted signing secret.
func TestPurgeVault_RemovesWebhookConfig(t *testing.T) {
	svc, deps := newPurgeableVaultService(t) // reuse the package's existing helper
	spy := &spyWebhookCleaner{}
	svc.SetWebhookCleaner(spy)

	vaultID := deps.createVault(t, "doomed")
	require.NoError(t, svc.DeleteVault(context.Background(), "doomed"))
	require.NoError(t, svc.PurgeVault(context.Background(), "doomed"))

	require.Len(t, spy.cleaned, 1, "purge must clean the vault's webhook config")
	assert.Equal(t, vaultID, spy.cleaned[0])
}

// TestPurgeVault_WebhookCleanerErrorSurfaces keeps a failed cleanup from being
// swallowed -- a silently-skipped cleanup is exactly the stranded-secret bug
// this hook exists to prevent.
func TestPurgeVault_WebhookCleanerErrorSurfaces(t *testing.T) {
	svc, deps := newPurgeableVaultService(t)
	svc.SetWebhookCleaner(&spyWebhookCleaner{err: errors.New("boom")})

	deps.createVault(t, "doomed")
	require.NoError(t, svc.DeleteVault(context.Background(), "doomed"))

	err := svc.PurgeVault(context.Background(), "doomed")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook")
}

// TestPurgeVault_NoWebhookCleanerIsFine keeps the hook optional, matching
// PolicyCleaner: a service constructed without one must still purge.
func TestPurgeVault_NoWebhookCleanerIsFine(t *testing.T) {
	svc, deps := newPurgeableVaultService(t)
	deps.createVault(t, "doomed")
	require.NoError(t, svc.DeleteVault(context.Background(), "doomed"))
	assert.NoError(t, svc.PurgeVault(context.Background(), "doomed"))
}
```

`newPurgeableVaultService` and `deps.createVault` are placeholders for this package's **existing** test setup. Find the real helpers first and use their actual names and signatures; do not add a second parallel setup path.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestPurgeVault_ -v`
Expected: FAIL — `svc.SetWebhookCleaner undefined`.

- [ ] **Step 4: Add the hook interface**

In `internal/services/vaults/vault_service.go`, immediately after the `PolicyCleaner` declaration (`:61-64`):

```go
// WebhookCleaner removes a vault's webhook config (used on purge). Satisfied
// by repositories.VaultWebhookRepositoryInterface.
//
// This is required, not belt-and-braces: vault_webhook_configs declares a
// FOREIGN KEY ... ON DELETE CASCADE, but SQLite's foreign_keys PRAGMA is off
// in this project, so that clause never fires there. Without this hook a
// purged vault strands a row holding an encrypted signing secret -- the same
// reason PurgeVaultContents and DeleteByVault below exist.
type WebhookCleaner interface {
	DeleteByVaultID(ctx context.Context, vaultID uuid.UUID) error
}
```

- [ ] **Step 5: Add the setter, interface method and struct field**

Add `SetWebhookCleaner(c WebhookCleaner)` to the `VaultService` interface (after `SetPolicyCleaner` at `:116`), add `webhooks WebhookCleaner` to the `vaultService` struct (after `policies` at `:125`), and add the setter alongside `SetPolicyCleaner`:

```go
// SetWebhookCleaner attaches an optional cleaner that removes a vault's
// webhook config on purge.
func (s *vaultService) SetWebhookCleaner(c WebhookCleaner) { s.webhooks = c }
```

- [ ] **Step 6: Call it in `PurgeVault`**

In `PurgeVault`, next to the existing access-policy cleanup near `:471`, guarded the same way:

```go
	// vault_webhook_configs' ON DELETE CASCADE is inert on SQLite (the
	// foreign_keys PRAGMA is off here), so the row must be removed explicitly
	// or it strands an encrypted signing secret for a vault that no longer
	// exists.
	if s.webhooks != nil {
		if err := s.webhooks.DeleteByVaultID(ctx, v.ID); err != nil {
			return fmt.Errorf("purge vault webhook config: %w", err)
		}
	}
```

Place it adjacent to the `PolicyCleaner` call and match that call's error-handling posture — if the existing code logs-and-continues rather than returning, do the same so purge behaves consistently. The tests above assume the error surfaces; if the established posture is log-and-continue, change `TestPurgeVault_WebhookCleanerErrorSurfaces` to assert the logged-and-continued behaviour instead, and note the deviation in the commit message.

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/services/vaults/ -v`
Expected: PASS — the three new tests plus every pre-existing test in the package.

- [ ] **Step 8: Commit**

```bash
git add internal/services/vaults/vault_service.go internal/services/vaults/vault_service_webhook_cleanup_test.go
git commit -m "feat(vaults): remove a vault's webhook config on purge

vault_webhook_configs declares ON DELETE CASCADE, but SQLite's foreign_keys
PRAGMA is off in this project, so that clause never fires -- the same reason
PurgeVault already purges secrets, keys, certs and access policies
explicitly. Without this hook a purged vault strands a row holding an
encrypted signing secret: unreachable, but never removed.

Modelled on the existing optional PolicyCleaner hook rather than the cascade
adapter, whose vaultContentRepo interface is soft-delete-shaped and does not
fit a table with no soft-delete columns."
```

---

## Task 6: Container wiring

**Files:**
- Modify: `internal/container/service_container.go` (interface method near `:82`; struct field near `:185`; construction near `:284`; getter near `:728`)
- Test: `internal/container/container_test.go` (two existing assertion sites: `:139` nil-container, `:294` constructed-container)

**Interfaces:**
- Consumes: `repositories.NewVaultWebhookRepository` (Task 3), `vaultServices.NewVaultWebhookService` (Task 4), `VaultService.SetWebhookCleaner` (Task 5).
- Produces: `container.ServiceContainerInterface.GetVaultWebhookService() vaultServices.VaultWebhookService`.

This task makes the service reachable from both edges and closes the Task 5 hook by injecting the repository as the cleaner.

- [ ] **Step 1: Write the failing test**

Add to `internal/container/container_test.go`, following the two existing patterns exactly:

- In the nil/empty-container test around `:139`, alongside `assert.Nil(t, c.GetVaultService(), "GetVaultService")`:
  ```go
  	assert.Nil(t, c.GetVaultWebhookService(), "GetVaultWebhookService")
  ```
- In the fully-constructed-container test around `:294`, alongside `assert.NotNil(t, container.GetVaultService(), "GetVaultService")`:
  ```go
  	assert.NotNil(t, container.GetVaultWebhookService(), "GetVaultWebhookService")
  ```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/container/ -v`
Expected: FAIL — `c.GetVaultWebhookService undefined`.

- [ ] **Step 3: Add the interface method**

In `ServiceContainerInterface`, after `GetVaultService()` (`:82`):

```go
	GetVaultWebhookService() vaultServices.VaultWebhookService
```

- [ ] **Step 4: Add the struct field and construction**

Add the field beside `vaultService` (`:185`):

```go
	vaultWebhookService vaultServices.VaultWebhookService
```

And construct it beside the `vaultService` construction (`:284`). The repository doubles as the purge cleaner, which is what closes Task 5's hook:

```go
	vaultWebhookRepo := repositories.NewVaultWebhookRepository(c.database, c.logger)
	c.vaultWebhookService = vaultServices.NewVaultWebhookService(vaultWebhookRepo, c.logger)
	c.vaultService.SetWebhookCleaner(vaultWebhookRepo)
```

Match the surrounding code's actual field names for the database handle and logger (`c.database`/`c.logger` are the expected names — confirm against the neighbouring `NewVaultService(c.vaultRepository, vaultCascade, c.logger)` call at `:284`). The `SetWebhookCleaner` line must come after `c.vaultService` is assigned.

- [ ] **Step 5: Add the getter**

After `GetVaultService` (`:728-729`):

```go
// GetVaultWebhookService returns the per-vault webhook configuration service.
func (c *ServiceContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	return c.vaultWebhookService
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/container/ -v`
Expected: PASS.

Then confirm nothing implementing `ServiceContainerInterface` broke — adding a method to that interface breaks every mock:

```bash
go build ./... && go vet ./...
```

If a test mock fails to satisfy the interface, add the method to it returning `nil`, matching how that mock handles `GetVaultService`.

- [ ] **Step 7: Commit**

```bash
git add internal/container/service_container.go internal/container/container_test.go
git commit -m "feat(container): wire VaultWebhookService

The repository is injected twice on purpose: once as the service's store, and
once as VaultService's WebhookCleaner, which is what makes vault purge remove
the config row."
```

---

## Task 7: HTTP API

**Files:**
- Create: `api/vault_webhook.go`
- Modify: `api/vault.go` (`InitVault`, `:32-44` — add three routes and extend the doc comment's endpoint list)
- Test: `api/vault_webhook_test.go`

**Interfaces:**
- Consumes: `container.ServiceContainerInterface.GetVaultWebhookService()` (Task 6), `vaultServices.VaultWebhookService` (Task 4), `model.UpsertVaultWebhookRequestFromJson` and the response types (Task 2), `authzServices.CanManageVault`.
- Produces: three routes on `api.BaseRoutes.Vaults`.

**Handler shape:** copy `updateVault` (`api/vault.go:185-241`) exactly — resolve the target vault by `{name}` first (404 on miss), then `callerIdentity`, then `CanManageVault` against `target.ID` (403 on deny), and only then read the body or touch the service. That ordering is not stylistic: these `{name}` routes bypass `VaultResolutionMiddleware`, so the ambient policy check only ever evaluated the default vault (see the `InitVault` doc comment at `:15-24`). Getting the order wrong reintroduces the gap that comment describes.

- [ ] **Step 1: Write the failing test**

Create `api/vault_webhook_test.go`. Use this package's existing HTTP test scaffolding — read `api/vault_test.go` (or whichever file tests `updateVault`/`deleteVault`) and reuse its helpers for building a `*Context`, a stub service container, and an authenticated request. Do not build a second scaffolding.

```go
package api

import (
	"net/http"
	"testing"
)

// The tests below assume this package's existing helpers for a stubbed
// container and an authenticated request. Read api/vault_test.go first and
// substitute the real helper names; the assertions are what matter.

// TestUpsertVaultWebhook_Create_Returns200WithSecret proves show-once: the
// create response is the one shape that carries the plaintext.
func TestUpsertVaultWebhook_Create_Returns200WithSecret(t *testing.T) {
	// PUT /vaults/prod/webhook {"url":"https://hooks.example/rv"}
	// with a stub VaultWebhookService returning plaintextSecret "s3cr3t".
	// Assert: 200, body contains "signing_secret":"s3cr3t" and "url".
}

// TestUpsertVaultWebhook_UpdateWithoutRotate_OmitsSecret is the other half of
// show-once: an update that minted nothing must not invent a field.
func TestUpsertVaultWebhook_UpdateWithoutRotate_OmitsSecret(t *testing.T) {
	// Stub returns plaintextSecret "".
	// Assert: 200, body does NOT contain "signing_secret".
}

// TestGetVaultWebhook_NeverReturnsSecret is the load-bearing leak test.
func TestGetVaultWebhook_NeverReturnsSecret(t *testing.T) {
	// Stub Get returns a config whose SigningSecretEncrypted is
	// "CIPHERTEXT-SENTINEL".
	// Assert: 200, body contains neither "signing_secret" nor
	// "CIPHERTEXT-SENTINEL".
}

func TestGetVaultWebhook_NotConfigured_Returns404(t *testing.T) {
	// Stub Get returns vaultServices.ErrWebhookNotFound.
	// Assert: 404.
}

func TestUpsertVaultWebhook_InvalidURL_Returns400(t *testing.T) {
	// Stub Upsert returns vaultServices.ErrInvalidWebhookURL.
	// Assert: 400, not 500 -- a client error must not surface as a server fault.
}

func TestUpsertVaultWebhook_MalformedBody_Returns400(t *testing.T) {
	// Body "{". Assert: 400.
}

func TestVaultWebhook_UnknownVault_Returns404(t *testing.T) {
	// GetVault returns ErrVaultNotFound, for all three methods.
	// Assert: 404 each, and the webhook service was never called.
}

func TestVaultWebhook_Unauthorized_Returns403(t *testing.T) {
	// A caller failing CanManageVault, for all three methods.
	// Assert: 403 each, and the webhook service was never called --
	// authorization must precede any service call.
}

func TestDeleteVaultWebhook_Returns204(t *testing.T) {
	// Assert: 204 (or whatever deleteVault returns -- match it).
}

// TestInitVault_WebhookRoutesOnVaultsRouter proves the routes are registered
// on BaseRoutes.Vaults, not BaseRoutes.VaultScoped. The {name} router is the
// vault-management tier; VaultScoped would put webhook config behind the
// data-plane role check, which is the wrong authorization model for it.
func TestInitVault_WebhookRoutesOnVaultsRouter(t *testing.T) {
	// Walk the router (mux.Router.Walk) after InitVault and assert a
	// "/vaults/{name}/webhook" template exists for PUT, GET and DELETE,
	// and that no "/vaults/{vault_name}/webhook" template exists.
	_ = http.MethodPut
}
```

Fill each body in using the helpers found in `api/vault_test.go`. Every test above must be a real, executing test — a body left as comments is a plan failure, not a placeholder to leave behind.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/ -run VaultWebhook -v`
Expected: FAIL — handlers undefined.

- [ ] **Step 3: Write the handlers**

Create `api/vault_webhook.go`:

```go
package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// webhookSvc returns the vault webhook service, setting an internal error if
// unavailable. Mirrors vaultSvc in vault.go.
func (c *Context) webhookSvc() vaultServices.VaultWebhookService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetVaultWebhookService()
}

// resolveAndAuthorizeVault resolves the {name} path variable to a vault and
// checks CanManageVault against it, writing the 404 or 403 itself and
// returning ok=false when the caller must stop.
//
// The resolve-then-authorize order is load-bearing, not stylistic: the {name}
// vault routes bypass VaultResolutionMiddleware, so PolicyMiddleware only ever
// evaluated the default vault for them (see InitVault's doc comment). Each
// handler restores the per-vault check here.
func resolveAndAuthorizeVault(c *Context, r *http.Request) (*model.Vault, bool) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return nil, false
	}
	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return nil, false
		}
		c.SetInternalError(err)
		return nil, false
	}
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return nil, false
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return nil, false
	}
	return target, true
}

// upsertVaultWebhook creates or updates a vault's webhook config.
//
// The response carries the plaintext signing secret only when this call minted
// one -- on create, or on an explicit rotate. That is the entire show-once
// contract: there is no other path, here or in getVaultWebhook, that emits it.
func upsertVaultWebhook(c *Context, w http.ResponseWriter, r *http.Request) {
	target, ok := resolveAndAuthorizeVault(c, r)
	if !ok {
		return
	}
	svc := c.webhookSvc()
	if svc == nil {
		return
	}

	req, err := model.UpsertVaultWebhookRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	cfg, plaintextSecret, err := svc.Upsert(r.Context(), target.ID, vaultServices.UpsertWebhookRequest{
		URL:          req.URL,
		RotateSecret: req.RotateSecret,
		Enabled:      req.Enabled,
	})
	if err != nil {
		if errors.Is(err, vaultServices.ErrInvalidWebhookURL) {
			c.SetInvalidParam("url: " + err.Error())
			return
		}
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if plaintextSecret != "" {
		created := model.VaultWebhookConfigCreatedResponse{
			VaultWebhookConfigResponse: cfg.ToResponse(),
			SigningSecret:              plaintextSecret,
		}
		w.Write([]byte(created.ToJson())) //nolint:errcheck,gosec
		return
	}
	resp := cfg.ToResponse()
	w.Write([]byte(resp.ToJson())) //nolint:errcheck,gosec
}

// getVaultWebhook returns a vault's webhook config. It never emits the signing
// secret in any form -- VaultWebhookConfigResponse has no field for it.
func getVaultWebhook(c *Context, w http.ResponseWriter, r *http.Request) {
	target, ok := resolveAndAuthorizeVault(c, r)
	if !ok {
		return
	}
	svc := c.webhookSvc()
	if svc == nil {
		return
	}

	cfg, err := svc.Get(r.Context(), target.ID)
	if err != nil {
		if errors.Is(err, vaultServices.ErrWebhookNotFound) {
			c.SetNotFound("webhook config")
			return
		}
		c.SetInternalError(err)
		return
	}

	resp := cfg.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(resp.ToJson())) //nolint:errcheck,gosec
}

// deleteVaultWebhook removes a vault's webhook config.
func deleteVaultWebhook(c *Context, w http.ResponseWriter, r *http.Request) {
	target, ok := resolveAndAuthorizeVault(c, r)
	if !ok {
		return
	}
	svc := c.webhookSvc()
	if svc == nil {
		return
	}

	if err := svc.Delete(r.Context(), target.ID); err != nil {
		c.SetInternalError(err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

Match `deleteVault`'s actual success status rather than assuming `204` — read `api/vault.go:274` onward and mirror it.

- [ ] **Step 4: Register the routes**

In `api/vault.go`'s `InitVault`, after the existing `{name}` routes (`:39`):

```go
	v.Handle("/{name}/webhook", ApiSessionRequired(api.App, upsertVaultWebhook)).Methods("PUT")
	v.Handle("/{name}/webhook", ApiSessionRequired(api.App, getVaultWebhook)).Methods("GET")
	v.Handle("/{name}/webhook", ApiSessionRequired(api.App, deleteVaultWebhook)).Methods("DELETE")
```

Register on `v` (`api.BaseRoutes.Vaults`), **not** `api.BaseRoutes.VaultScoped`. Add three lines to the doc comment's endpoint list above the function:

```go
//   - PUT    /vaults/{name}/webhook : Create or update the vault's webhook config.
//   - GET    /vaults/{name}/webhook : Get the vault's webhook config.
//   - DELETE /vaults/{name}/webhook : Delete the vault's webhook config.
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./api/ -run VaultWebhook -v`
Expected: PASS.

Then the whole package: `go test ./api/`

- [ ] **Step 6: Commit**

```bash
git add api/vault_webhook.go api/vault.go api/vault_webhook_test.go
git commit -m "feat(api): add per-vault webhook config endpoints

PUT/GET/DELETE /vaults/{name}/webhook on BaseRoutes.Vaults, the
vault-management router -- not VaultScoped, which would put this behind the
data-plane role check rather than CanManageVault.

Each handler resolves the target vault before authorizing against it, the
same order updateVault and deleteVault use: these {name} routes bypass
VaultResolutionMiddleware, so the handler-level check is the only per-vault
authorization they get.

GET has no path that can emit the signing secret -- the response type has no
field for it."
```

---

## Task 8: CLI

**Files:**
- Create: `cmd/vault-webhook/authz.go`, `cmd/vault-webhook/vault.go`, `cmd/vault-webhook/set.go`, `cmd/vault-webhook/get.go`, `cmd/vault-webhook/delete.go`
- Create: `cmd/vault_webhook.go` (parent command)
- Test: `cmd/vault-webhook/set_test.go`, `cmd/vault-webhook/authz_test.go`

**Interfaces:**
- Consumes: `container.ServiceContainerInterface.GetVaultWebhookService()` (Task 6), `vaultServices.UpsertWebhookRequest` (Task 4).
- Produces: `rocketvault vault-webhook set|get|delete`.

**Why a package-local `authz.go`:** the CLI bypasses HTTP middleware entirely, so per CLAUDE.md's "CLI Authorization" section it must reproduce the check itself. `cmd/vaults/authz.go`'s `requireCanManageVault` is unexported, so this package needs its own — exactly as `cmd/vault-access/authz.go` does, whose header comment records the privilege-escalation gap that arose from omitting one.

- [ ] **Step 1: Read the two templates**

Read `cmd/vault-access/authz.go` in full (its `callerIdentity` and `require*` helpers), `cmd/vault-access/vault.go` (its `resolveVaultID` and `addVaultFlag`), one command file such as `cmd/vault-access/grant.go`, and `cmd/vault_access.go`. This task is structurally a copy of that package; matching it matters more than any code below.

- [ ] **Step 2: Write the failing test**

Create `cmd/vault-webhook/authz_test.go` and `cmd/vault-webhook/set_test.go`, following `cmd/vault-access/authz_test.go`'s patterns. Required assertions:

```go
// authz_test.go
// - requireCanManageVault denies a non-admin with no vaults/manage policy,
//   and the denial message names the vault.
// - requireCanManageVault allows the admin account role.
// - A context with no claims returns an error, not a silent allow.

// set_test.go
// - `set` with no --url is a flag error.
// - `set` on create prints the secret and the one-time notice.
// - `set` on an update that did not rotate prints NO secret line and no
//   notice -- the CLI must not invent a field the service did not return.
// - `set --rotate-secret` prints the new secret.
// - The secret never reaches the logger: capture log output during a create
//   and assert it does not contain the secret value. This is the CLI-side
//   guard against copying cmd/users/create.go:91's habit of logging one.
// - An authorization denial surfaces as a clear CLI error and the webhook
//   service is never called.
```

Write these as real executing tests using the stub container from `cmd/vault-access`'s tests.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./cmd/vault-webhook/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 4: Write `authz.go` and `vault.go`**

Create `cmd/vault-webhook/authz.go` and `cmd/vault-webhook/vault.go` as near-copies of `cmd/vault-access/authz.go` and `cmd/vault-access/vault.go`, with `package vaultwebhook`. `authz.go` needs `callerIdentity` (identical) and:

```go
// requireCanManageVault authorizes a webhook-config operation on vaultID with
// the same primitive the HTTP handlers use, so CLI and API cannot drift.
//
// The CLI calls the service layer directly and bypasses PolicyMiddleware
// entirely, so this is the only authorization enforcement point on this path
// -- a command that skips it bypasses authorization completely.
func requireCanManageVault(ctx context.Context, sc container.ServiceContainerInterface, vaultID uuid.UUID, vaultName string) error {
	role, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageVault(ctx, role, sc.GetAccessPolicyService(), principalID, vaultID) {
		return fmt.Errorf("permission denied: managing webhook config for vault %q requires admin or vaults/manage", vaultName)
	}
	return nil
}
```

`vault.go` carries `resolveVaultID` and `addVaultFlag`, copied verbatim from `cmd/vault-access/vault.go` with the package name changed.

- [ ] **Step 5: Write `set.go`**

The output copy is fixed by the spec — use it exactly:

```go
	fmt.Printf("Webhook configured for vault %q:\n", vaultName)
	fmt.Printf("  URL: %s\n", resp.URL)
	fmt.Printf("  Enabled: %t\n", resp.Enabled)
	if plaintextSecret != "" {
		fmt.Printf("  Signing Secret: %s\n", plaintextSecret)
		fmt.Printf("\nStore the signing secret now — it is not retrievable after this.\n")
	}
```

Flags: `--url` (string, required), `--rotate-secret` (bool), `--enabled` (bool), plus `addVaultFlag(cmd)`. There is no `--secret` flag.

`--enabled` must reach the service as `*bool`, nil when the user did not pass it, or the CLI reintroduces the exact bug the pointer type exists to prevent. Use Cobra's `cmd.Flags().Changed("enabled")`:

```go
	var enabled *bool
	if cmd.Flags().Changed("enabled") {
		v, err := cmd.Flags().GetBool("enabled")
		if err != nil {
			return err
		}
		enabled = &v
	}
```

The command body: resolve the container (the `ServiceContainerInterface` type assertion this repo uses in every CLI command), `resolveVaultID`, `requireCanManageVault`, then `GetVaultWebhookService().Upsert(...)`. Never log the secret.

- [ ] **Step 6: Write `get.go` and `delete.go`**

Same preamble (resolve container, resolve vault, authorize). `get` prints URL, Enabled, Created, Updated — and has no secret line, because the service returns only ciphertext and the CLI must not decrypt it. `delete` prints a one-line confirmation. Both surface `vaultServices.ErrWebhookNotFound` as a clear "no webhook configured for vault %q" message rather than a raw error.

- [ ] **Step 7: Write the parent command**

Create `cmd/vault_webhook.go`, mirroring `cmd/vault_access.go`:

```go
package cmd

import (
	"github.com/spf13/cobra"

	vaultwebhook "rocketvault/cmd/vault-webhook"
)

var vaultWebhookCmd = &cobra.Command{
	Use:   "vault-webhook",
	Short: "Manage per-vault webhook configuration",
	Long: `Configure the webhook RocketVault will use to notify a vault's operators.

Examples:
  rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault
  rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault --rotate-secret
  rocketvault vault-webhook get --vault prod
  rocketvault vault-webhook delete --vault prod`,
}

func init() {
	vaultwebhook.InitVaultWebhookSet(vaultWebhookCmd)
	vaultwebhook.InitVaultWebhookGet(vaultWebhookCmd)
	vaultwebhook.InitVaultWebhookDelete(vaultWebhookCmd)
	RootCmd.AddCommand(vaultWebhookCmd)
}
```

Match `cmd/vault_access.go`'s actual registration mechanism — if it adds to the root command somewhere other than `init()`, do the same.

- [ ] **Step 8: Run tests to verify they pass**

```bash
go test ./cmd/vault-webhook/ -v
go build ./... && go vet ./...
```

Then a manual smoke check that the command is reachable:

```bash
go run main.go vault-webhook --help
```

Expected: the three subcommands listed, and no `--secret` flag on `set`.

- [ ] **Step 9: Commit**

```bash
git add cmd/vault-webhook/ cmd/vault_webhook.go
git commit -m "feat(cli): add vault-webhook set/get/delete

A dedicated package with its own authz.go, mirroring cmd/vault-access: the
CLI bypasses PolicyMiddleware entirely, so requireCanManageVault is the only
authorization enforcement point on this path.

--enabled is threaded through as *bool via Flags().Changed so an unset flag
stays nil rather than silently disabling the webhook. There is no --secret
flag: the server mints the secret, keeping it off the command line and out
of shell history."
```

---

## Task 9: Documentation

**Files:**
- Modify: `.claude/known-bugs.md` (§ B27)
- Modify: `docs/api-specification.yaml`

**Interfaces:**
- Consumes: the shipped behaviour of Tasks 1-8.
- Produces: no code.

Write this only after Tasks 1-8 are green — it documents what shipped, not what was planned.

- [ ] **Step 1: Update B27 in `.claude/known-bugs.md`**

Read the existing B27 entry and append a dated note in that file's established style, recording that the storage layer for `notify_before_expiry_days` now exists while the bug stays **open**: nothing sends a notification yet. Name the follow-on sub-projects (delivery primitive, keys' near-expiry sweep, secrets' reminder wiring, certificates' warning wiring). Do not mark B27 fixed.

- [ ] **Step 2: Add the three routes to `docs/api-specification.yaml`**

Document `PUT`/`GET`/`DELETE /vaults/{name}/webhook` following the file's existing conventions for the other `/vaults/{name}` operations. The `PUT` response schema must show both shapes — with and without `signing_secret` — and the description must state that the secret appears only on create or rotate and is not retrievable afterwards. `GET`'s schema must have no `signing_secret` property.

- [ ] **Step 3: Deliberately NOT updated**

Per the spec's "Documentation to update" section, these stay untouched in this sub-project and are noted here so a reviewer does not read their absence as an oversight:

- `.claude/azure-keyvault-parity.md` — webhooks are a RocketVault extra, not an Azure capability, and a parity row is premature while nothing sends anything.
- `docs/usage-guide.md` — deferred until the chain is usable end-to-end (likely sub-project 3). Note: this repo's pre-commit hook may warn that `usage-guide.md` is stale; that warning is informational and does not block.

- [ ] **Step 4: Run the full verification gate**

```bash
go build ./...
go vet ./...
go test ./...
```

Expected: clean build, clean vet, no failures. Run the whole suite, not just the touched packages — Task 6 changed `ServiceContainerInterface`, which ripples to every mock in the repo.

- [ ] **Step 5: Commit**

```bash
git add .claude/known-bugs.md docs/api-specification.yaml
git commit -m "docs: record the vault webhook config storage layer

B27 stays open: notify_before_expiry_days now has somewhere to deliver to,
but nothing sends anything yet. The delivery primitive and the keys/secrets/
certs wiring are separate sub-projects."
```

---

## Verification gate

```bash
go build ./...
go vet ./...
go test ./internal/db/... ./internal/repositories/... ./internal/services/vaults/... ./internal/container/... ./api/... ./cmd/vault-webhook/... ./model/...
go test ./...
```

## Self-review notes

**Spec coverage.** Spec §1→Task 1, §2→Task 2, §3→Task 3, §4→Task 4, §5→Task 7, §6→Task 8; Testing→distributed across each task; Documentation→Task 9. Two tasks have no spec section: Task 5 (purge cleanup) exists because correction C2 found the spec's cascade mechanism inert on SQLite, and Task 6 (container wiring) is implied by the spec but never stated, and both edges need it.

**Type consistency.** `VaultWebhookConfig` field names are identical in Tasks 2, 3, 4. `UpsertWebhookRequest` (service, Task 4) and `UpsertVaultWebhookRequest` (HTTP body, Task 2) are deliberately distinct types with the same three fields — the handler in Task 7 maps one to the other explicitly. `DeleteByVaultID` is the name in Task 3's repository, Task 5's `WebhookCleaner`, and Task 4's service delegate; the service's own method is `Delete`.

**Known soft spots.** Four steps direct the implementer to confirm a local convention before writing code rather than stating it outright: the `createOptimizedSchema`/`migrateSchema` signatures (Task 1 Step 1), the `db.DB` wrapper constructor (Task 3 Step 1), the `EncryptSecret` test setup (Task 4 Step 1), and `PurgeVault`'s error posture for optional cleaners (Task 5 Step 6). Each is a question the code answers in one grep, and each is flagged with what to grep for. Task 7's and Task 8's test bodies are specified as assertion lists rather than complete code because they depend on this repo's HTTP and CLI test scaffolding, which those tasks' first step directs the implementer to read.
