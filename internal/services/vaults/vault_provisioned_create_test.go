package vaults_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// testPrincipal is the quota-bounded creator used throughout this file's tests.
var testPrincipal = uuid.New()

// quota and existingVaults name the two int arguments to
// newProvisionedTestService/newProvisionedTestServiceRealDB, so a call site
// reads as `quota(2), existingVaults(2)` instead of two bare integers.
func quota(n int) int          { return n }
func existingVaults(n int) int { return n }

// noopProvisionedCascade is a CascadeRepository that does nothing. The tests
// in this file exercise vault creation only, never delete/recover/purge, so
// the cascade is never invoked -- it exists solely to satisfy
// vaultServices.NewVaultService's signature.
type noopProvisionedCascade struct{}

func (noopProvisionedCascade) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (noopProvisionedCascade) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (noopProvisionedCascade) SoftDeleteVaultContentsTx(context.Context, rvdb.DBTX, uuid.UUID, time.Time) error {
	return nil
}
func (noopProvisionedCascade) RecoverVaultContentsTx(context.Context, rvdb.DBTX, uuid.UUID, time.Time) error {
	return nil
}
func (noopProvisionedCascade) PurgeVaultContents(context.Context, uuid.UUID) error { return nil }
func (noopProvisionedCascade) HasProtectedContent(context.Context, uuid.UUID) (bool, error) {
	return false, nil
}

// provisionedSchema is the minimal schema the quota-bounded create path
// touches: vaults (CreateTx/CountByCreatedBy) and vault_provisioning_grants
// (LockAndReadQuotaTx).
const provisionedSchema = `
	CREATE TABLE vaults (
		id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		purge_protection BOOLEAN NOT NULL DEFAULT 0,
		retention_days INTEGER NOT NULL DEFAULT 90,
		created_by TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		scheduled_purge_at TIMESTAMP NULL,
		tags TEXT NOT NULL DEFAULT '{}',
		updated_at TIMESTAMP NULL,
		updated_by TEXT NULL
	);
	CREATE TABLE vault_provisioning_grants (
		id TEXT PRIMARY KEY,
		principal_id TEXT UNIQUE NOT NULL,
		quota INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		created_by TEXT NOT NULL
	);
`

// newProvisionedTestDB opens a SQLite database at dsn, creates
// provisionedSchema, seeds testPrincipal's grant with quota q, and inserts n
// vaults already created by testPrincipal (proving soft-deleted-style
// pre-existing vaults count against quota just as active ones do -- this
// helper doesn't soft-delete any of them, but CountByCreatedBy's query has no
// deleted_at filter, so an already-deleted row would count exactly the same).
func newProvisionedTestDB(t *testing.T, dsn string, q, n int) *sql.DB {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec

	_, err = sqlDB.Exec(provisionedSchema)
	require.NoError(t, err)

	_, err = sqlDB.Exec(
		"INSERT INTO vault_provisioning_grants (id, principal_id, quota, created_by) VALUES (?, ?, ?, ?)",
		uuid.New().String(), testPrincipal.String(), q, testPrincipal.String())
	require.NoError(t, err)

	for i := 0; i < n; i++ {
		_, err = sqlDB.Exec(
			"INSERT INTO vaults (id, name, created_by) VALUES (?, ?, ?)",
			uuid.New().String(), fmt.Sprintf("existing-%d", i), testPrincipal.String())
		require.NoError(t, err)
	}
	return sqlDB
}

// newProvisionedService wires a VaultService for the quota-bounded create
// path against sqlDB: real VaultRepository and grant repository, TxBeginner
// and GrantLocker both set.
func newProvisionedService(t *testing.T, sqlDB *sql.DB) vaults.VaultService {
	t.Helper()
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)

	vaultRepo := repositories.NewVaultRepository(conn, nil)
	grantRepo := repositories.NewVaultProvisioningGrantRepository(conn)

	svc := vaults.NewVaultService(vaultRepo, noopProvisionedCascade{}, nil)
	svc.SetTxBeginner(conn)
	svc.SetGrantLocker(grantRepo)
	return svc
}

// newProvisionedTestService builds a quota-bounded VaultService against an
// in-memory SQLite database seeded with quota q and n pre-existing vaults
// created by testPrincipal.
func newProvisionedTestService(t *testing.T, q, n int) vaults.VaultService {
	t.Helper()
	return newProvisionedService(t, newProvisionedTestDB(t, ":memory:", q, n))
}

// newProvisionedTestServiceRealDB is like newProvisionedTestService but backed
// by a temp-file SQLite database rather than ":memory:". ":memory:" gives
// each connection in the pool its own private, throwaway database, so a
// concurrency test needing two connections to contend for one real row lock
// requires an actual file on disk.
func newProvisionedTestServiceRealDB(t *testing.T, q, n int) vaults.VaultService {
	t.Helper()
	// _busy_timeout makes a connection that finds the row locked wait for the
	// lock to clear (up to 5s) instead of failing immediately with
	// "database is locked" -- without it, concurrent writers race the OS
	// file lock itself rather than exercising the quota check.
	dsn := filepath.Join(t.TempDir(), "provisioned.db") + "?_busy_timeout=5000"
	return newProvisionedService(t, newProvisionedTestDB(t, dsn, q, n))
}

func TestCreateVaultProvisioned_RefusesAtQuota(t *testing.T) {
	svc := newProvisionedTestService(t, quota(2), existingVaults(2)) // helpers in Step 4

	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "third"}, testPrincipal, true)

	require.True(t, errors.Is(err, vaults.ErrVaultQuotaExceeded),
		"a create at quota must be refused, not merely logged")
}

func TestCreateVaultProvisioned_AllowsBelowQuota(t *testing.T) {
	svc := newProvisionedTestService(t, quota(2), existingVaults(1))

	v, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "second"}, testPrincipal, true)

	require.NoError(t, err)
	require.Equal(t, "second", v.Name)
}

func TestCreateVaultProvisioned_UnboundedIgnoresQuota(t *testing.T) {
	svc := newProvisionedTestService(t, quota(1), existingVaults(5))

	// quotaBounded=false is the admin / global-policy path.
	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "admin-made"}, testPrincipal, false)

	require.NoError(t, err, "admins and global-policy holders are not quota-bounded")
}

func TestCreateVaultProvisioned_RejectsPurgeProtectionFromGrantee(t *testing.T) {
	svc := newProvisionedTestService(t, quota(5), existingVaults(0))
	protect := true

	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "pinned", PurgeProtection: &protect}, testPrincipal, true)

	require.Error(t, err,
		"a grantee setting purge_protection could pin a quota slot permanently")
}

// TestCreateVaultProvisioned_ConcurrentCreatesRespectQuota demonstrates the
// row-lock guard (LockAndReadQuotaTx's no-op UPDATE) using SQLite's
// transaction escalation to RESERVED. It only demonstrates the guard: the
// race it defends against -- two concurrent creates both reading the same
// count under READ COMMITTED and both inserting -- is a PostgreSQL failure
// mode, since SQLite serializes writers regardless. The guard is still
// required so it also fails safe here rather than merely "by accident."
func TestCreateVaultProvisioned_ConcurrentCreatesRespectQuota(t *testing.T) {
	// Quota 2, one vault already present: exactly one of two concurrent
	// creates may succeed.
	svc := newProvisionedTestServiceRealDB(t, quota(2), existingVaults(1))

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.CreateVaultProvisioned(context.Background(),
				model.CreateVaultRequest{Name: fmt.Sprintf("race-%d", i)}, testPrincipal, true)
		}(i)
	}
	wg.Wait()

	var ok, refused int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, vaults.ErrVaultQuotaExceeded):
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	require.Equal(t, 1, ok, "exactly one concurrent create may succeed")
	require.Equal(t, 1, refused, "the other must be refused for quota")
}
