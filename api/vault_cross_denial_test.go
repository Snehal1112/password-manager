// Package api — cross-vault denial regression tests backed by real SQLite
// repositories (design spec 2026-07-26, section 4.1 / 8). Unlike the
// hand-written fakes used elsewhere in this package, whose *InVault methods
// unconditionally succeed, these tests exercise the real repository SQL
// predicates (WHERE id = ? AND vault_id = ?) so a resource seeded in vault B
// is provably denied when requested via /vaults/{vault-a}/... . Permanent
// tests — not deleted by any later phase.
package api

import (
	"context"
	"database/sql"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"

	"rocketvault/app"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	keyServices "rocketvault/internal/services/keys"
	secretServices "rocketvault/internal/services/secrets"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// TestCrossVaultDenial_Secret_RealSQLite seeds a secret in vault B and
// requests it via /vaults/vault-a/secrets/{id}, asserting 404. The real
// SecretRepository.ReadInVault predicate enforces the denial, not a fake.
func TestCrossVaultDenial_Secret_RealSQLite(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultBID,
		Name: "db-password", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET secret: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// newCrossVaultSecretsTestAPI wires the vault-scoped secret routes onto a
// real SecretService backed by a real SecretRepository over an in-memory
// SQLite database. Only the SecretRepository needs to be real:
// GetSecretInVault's cross-vault-denial path returns before ever touching
// cryptoService or tagService, so both are left nil.
func newCrossVaultSecretsTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.SecretRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id               TEXT PRIMARY KEY,
		user_id          TEXT NOT NULL,
		vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name             TEXT NOT NULL,
		value            TEXT NOT NULL,
		version          INTEGER NOT NULL,
		created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at       TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type     TEXT NOT NULL DEFAULT '',
		enabled          BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at       TIMESTAMP NULL,
		not_before       TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create secrets schema: %v", err)
	}

	secretRepo := repositories.NewSecretRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	secretSvc := secretServices.NewSecretService(secretServices.SecretServiceConfig{
		SecretRepository: secretRepo,
		Logger:           userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, secretSvc: secretSvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	api.InitVault()
	api.InitSecrets()
	return api, vrepo, secretRepo
}

// TestCrossVaultDenial_Key_RealSQLite seeds a key in vault B and requests it
// via /vaults/vault-a/keys/{id}, asserting 404.
func TestCrossVaultDenial_Key_RealSQLite(t *testing.T) {
	api, vrepo, keyRepo := newCrossVaultKeysTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	keyID := uuid.New()
	if err := keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: uuid.New(), VaultID: vaultBID,
		Name: "signing-key", Type: "RSA", Value: "encrypted-pem", Enabled: true,
	}); err != nil {
		t.Fatalf("seed key in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/keys/"+keyID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET key: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// newCrossVaultKeysTestAPI wires the vault-scoped key routes onto a real
// KeyService backed by a real KeyRepository over an in-memory SQLite
// database. GetKeyInVault's cross-vault-denial path returns before
// touching keyProvider or keyCache, so both stay at their zero values.
func newCrossVaultKeysTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.KeyRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL,
		bits INTEGER NOT NULL DEFAULT 0,
		curve TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create keys schema: %v", err)
	}

	keyRepo := repositories.NewKeyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	keySvc := keyServices.NewKeyService(keyServices.KeyServiceConfig{
		KeyRepository: keyRepo,
		Logger:        userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, keySvc: keySvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	api.InitVault()
	api.InitKeys()
	return api, vrepo, keyRepo
}

// seedCrossVaultPair seeds two enabled vaults ("vault-a", "vault-b") into
// repo and returns their IDs. Shared by every cross-vault-denial test.
func seedCrossVaultPair(repo *vaultFakeRepo) (vaultAID, vaultBID uuid.UUID) {
	vaultAID = uuid.New()
	repo.byName["vault-a"] = &model.Vault{ID: vaultAID, Name: "vault-a", Enabled: true}
	repo.byID[vaultAID.String()] = repo.byName["vault-a"]

	vaultBID = uuid.New()
	repo.byName["vault-b"] = &model.Vault{ID: vaultBID, Name: "vault-b", Enabled: true}
	repo.byID[vaultBID.String()] = repo.byName["vault-b"]
	return
}
