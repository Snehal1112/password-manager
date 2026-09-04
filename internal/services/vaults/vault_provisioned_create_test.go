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
// requires an actual file on disk. Returns the *sql.DB too, so a concurrency
// test can assert on final database state directly rather than trusting only
// the returned errors.
func newProvisionedTestServiceRealDB(t *testing.T, q, n int) (vaults.VaultService, *sql.DB) {
	t.Helper()
	// _busy_timeout makes a connection that finds the row locked wait for the
	// lock to clear (up to 5s) instead of failing immediately with
	// "database is locked" -- without it, concurrent writers race the OS
	// file lock itself rather than exercising the quota check.
	dsn := filepath.Join(t.TempDir(), "provisioned.db") + "?_busy_timeout=5000"
	sqlDB := newProvisionedTestDB(t, dsn, q, n)
	return newProvisionedService(t, sqlDB), sqlDB
}

// errGranterFailed is the induced failure stubCreatorGranter returns when
// configured to fail, standing in for a real write error (e.g. a constraint
// violation) at the grant-writing step.
var errGranterFailed = errors.New("granter: induced failure")

// stubCreatorGranter is a vaults.CreatorGranter that records every write it's
// given, or fails on the first call when failing is true -- used to prove a
// failure at the grant-writing step rolls back the vault insert that
// preceded it in the same transaction.
type stubCreatorGranter struct {
	failing  bool
	policies []*model.AccessPolicy
	roles    []*model.RoleAssignment
}

func (g *stubCreatorGranter) CreatePolicyTx(_ context.Context, _ rvdb.DBTX, p *model.AccessPolicy) error {
	if g.failing {
		return errGranterFailed
	}
	g.policies = append(g.policies, p)
	return nil
}

func (g *stubCreatorGranter) CreateRoleTx(_ context.Context, _ rvdb.DBTX, ra *model.RoleAssignment) error {
	if g.failing {
		return errGranterFailed
	}
	g.roles = append(g.roles, ra)
	return nil
}

// newProvisionedTestServiceWithGranter is newProvisionedTestService plus a
// recording CreatorGranter wired via SetCreatorGranter, so a test can assert
// on the policy/role-assignment writes CreateVaultProvisioned makes.
func newProvisionedTestServiceWithGranter(t *testing.T, q, n int) (vaults.VaultService, *stubCreatorGranter) {
	t.Helper()
	svc := newProvisionedTestService(t, q, n)
	granter := &stubCreatorGranter{}
	svc.SetCreatorGranter(granter)
	return svc, granter
}

// newProvisionedTestServiceWithFailingGranter is the same, but the granter
// fails on its first call -- used to prove the vault insert rolls back too
// when the grant-writing step fails partway through the transaction.
func newProvisionedTestServiceWithFailingGranter(t *testing.T, q, n int) (vaults.VaultService, *stubCreatorGranter) {
	t.Helper()
	svc := newProvisionedTestService(t, q, n)
	granter := &stubCreatorGranter{failing: true}
	svc.SetCreatorGranter(granter)
	return svc, granter
}

func TestCreateVaultProvisioned_GrantsCreatorFullRights(t *testing.T) {
	svc, granter := newProvisionedTestServiceWithGranter(t, quota(5), existingVaults(0))

	v, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "acme-prod"}, testPrincipal, true)
	require.NoError(t, err)

	require.Len(t, granter.policies, 1)
	require.Equal(t, model.PolicyResourceVaults, granter.policies[0].ResourceType)
	require.Equal(t, model.OpManage, granter.policies[0].Operation)
	require.Equal(t, model.PolicyEffectAllow, granter.policies[0].Effect)
	require.NotNil(t, granter.policies[0].VaultID)
	require.Equal(t, v.ID, *granter.policies[0].VaultID,
		"the creator's manage policy must be scoped to the new vault, never global")

	require.Len(t, granter.roles, 1)
	require.Equal(t, model.RoleKeyVaultAdministrator, granter.roles[0].Role)
	require.Equal(t, v.ID, granter.roles[0].VaultID)
	require.Equal(t, testPrincipal, granter.roles[0].PrincipalID)
}

func TestCreateVaultProvisioned_RollsBackAllThreeWrites(t *testing.T) {
	svc, _ := newProvisionedTestServiceWithFailingGranter(t, quota(5), existingVaults(0))

	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "doomed"}, testPrincipal, true)
	require.Error(t, err)

	_, err = svc.GetVault(context.Background(), "doomed")
	require.Error(t, err, "a failed grant write must roll back the vault insert too")
}

func TestCreateVaultProvisioned_RefusesAtQuota(t *testing.T) {
	svc := newProvisionedTestService(t, quota(2), existingVaults(2))

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

	require.ErrorIs(t, err, vaults.ErrPurgeProtectionNotPermitted,
		"a grantee setting purge_protection could pin a quota slot permanently")
}

// TestCreateVaultProvisioned_RefusesWhenTransactionDepsUnwired guards against
// a fail-open regression: a quota-bounded caller whose txBeginner or
// grantLocker is unwired (e.g. a missed wiring line when plan 06 hooks up the
// HTTP handler) must be refused outright, never silently handed the
// unchecked CreateVault path -- a guard that degrades to "no guard" on a
// wiring mistake is worse than no guard, because it looks like it's working.
func TestCreateVaultProvisioned_RefusesWhenTransactionDepsUnwired(t *testing.T) {
	sqlDB := newProvisionedTestDB(t, ":memory:", 5, 0)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	vaultRepo := repositories.NewVaultRepository(conn, nil)
	// Deliberately don't call SetTxBeginner/SetGrantLocker.
	svc := vaults.NewVaultService(vaultRepo, noopProvisionedCascade{}, nil)

	_, err := svc.CreateVaultProvisioned(context.Background(),
		model.CreateVaultRequest{Name: "unwired"}, testPrincipal, true)

	require.Error(t, err,
		"a quota-bounded caller must be refused, not silently fall back to the unchecked create path")

	var count int
	require.NoError(t, sqlDB.QueryRow("SELECT COUNT(*) FROM vaults").Scan(&count))
	require.Equal(t, 0, count, "no vault may be created when the quota cannot be enforced")
}

// txCreateCounter is the same capability CreateVaultProvisioned itself
// asserts for (unexported txCapableCreateRepo in vault_service.go). Declared
// locally so this external test package can drive the two Tx-scoped methods
// directly against the concrete *repositories.VaultRepository.
type txCreateCounter interface {
	CreateTx(ctx context.Context, ex rvdb.DBTX, v *model.Vault) error
	CountByCreatedBy(ctx context.Context, ex rvdb.DBTX, principalID uuid.UUID) (int, error)
}

// TestCreateVaultProvisioned_ConcurrentCreatesRespectQuota proves the row
// lock (LockAndReadQuotaTx's no-op UPDATE) is what prevents two concurrent
// creates from both reading the same pre-insert count and both inserting --
// the READ COMMITTED race this guard defends against on PostgreSQL.
//
// Two earlier versions of this test were rejected:
//
//   - Driving two goroutines through the public svc.CreateVaultProvisioned,
//     released together off a shared start channel, PASSED even with the lock
//     statement deleted: the two transactions' read-then-write sequences are
//     fast enough, and Go's scheduler coarse enough, that one goroutine's
//     entire transaction routinely completes before the other's even begins
//     -- accidental serialization by timing, not the lock.
//   - A version with an explicit two-party rendezvous (each racer signals
//     after its read, then both proceed to write together) DEADLOCKED when
//     the lock was present: LockAndReadQuotaTx's UPDATE is itself part of
//     the "read", so the second racer's read cannot complete until the
//     first's transaction ends -- but the first racer was waiting for the
//     second's read-done signal before ending its transaction. Neither side
//     could move.
//
// This version uses a one-directional handoff instead of a mutual one: racer
// B waits only for a signal that racer A has finished its OWN read and is
// about to pause before writing; racer A never waits on B and always
// proceeds to write+commit unconditionally after a short, generous pause.
// That pause exists purely to give B's read call time to actually be issued
// while A's transaction is still open and uncommitted:
//
//   - Lock absent: B's SELECT-only read does not block on A's uncommitted
//     write (SQLite readers aren't blocked by a pending, uncommitted
//     RESERVED lock), so B completes its read immediately, observes the same
//     stale pre-insert count A saw, and -- once A commits and releases the
//     write lock -- commits its own insert too. Both succeed: quota
//     overrun, reproduced deterministically on every run.
//   - Lock present: B's own UPDATE blocks until A's transaction ends, so B's
//     read can only complete after A has already committed, and correctly
//     observes the post-insert count. Exactly one of the two ever inserts.
func TestCreateVaultProvisioned_ConcurrentCreatesRespectQuota(t *testing.T) {
	// Quota 2, one vault already present: exactly one of two concurrent
	// creates may succeed.
	dsn := filepath.Join(t.TempDir(), "provisioned.db") + "?_busy_timeout=5000"
	sqlDB := newProvisionedTestDB(t, dsn, 2, 1)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)

	vaultRepo, ok := repositories.NewVaultRepository(conn, nil).(txCreateCounter)
	require.True(t, ok, "VaultRepository must support the Tx-scoped create/count pair")
	grantRepo := repositories.NewVaultProvisioningGrantRepository(conn)

	newVault := func(name string) *model.Vault {
		return &model.Vault{
			ID: uuid.New(), Name: name, Enabled: true, RetentionDays: 90,
			CreatedBy: testPrincipal, CreatedAt: time.Now(),
		}
	}

	// bMayStart is closed once A's read phase has completed and A is about
	// to pause before writing -- the only synchronization B waits on. A
	// itself never waits on B.
	bMayStart := make(chan struct{})
	var wg sync.WaitGroup
	var errA, errB error

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			errA = err
			return
		}
		quota, err := grantRepo.LockAndReadQuotaTx(ctx, tx, testPrincipal)
		if err != nil {
			_ = tx.Rollback()
			errA = err
			return
		}
		count, err := vaultRepo.CountByCreatedBy(ctx, tx, testPrincipal)
		if err != nil {
			_ = tx.Rollback()
			errA = err
			return
		}

		close(bMayStart)
		// Generous head start for B to at least ISSUE its own read call
		// while this transaction is still open and uncommitted -- SQLite
		// operations are microsecond-scale, so this margin is not tight.
		time.Sleep(50 * time.Millisecond)

		if count >= quota {
			_ = tx.Rollback()
			errA = fmt.Errorf("%w: %d of %d used", vaults.ErrVaultQuotaExceeded, count, quota)
			return
		}
		if err := vaultRepo.CreateTx(ctx, tx, newVault("race-a")); err != nil {
			_ = tx.Rollback()
			errA = err
			return
		}
		errA = tx.Commit()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-bMayStart
		ctx := context.Background()
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			errB = err
			return
		}
		// Blocks here until A's transaction ends, if and only if the lock
		// statement is present.
		quota, err := grantRepo.LockAndReadQuotaTx(ctx, tx, testPrincipal)
		if err != nil {
			_ = tx.Rollback()
			errB = err
			return
		}
		count, err := vaultRepo.CountByCreatedBy(ctx, tx, testPrincipal)
		if err != nil {
			_ = tx.Rollback()
			errB = err
			return
		}
		if count >= quota {
			_ = tx.Rollback()
			errB = fmt.Errorf("%w: %d of %d used", vaults.ErrVaultQuotaExceeded, count, quota)
			return
		}
		if err := vaultRepo.CreateTx(ctx, tx, newVault("race-b")); err != nil {
			_ = tx.Rollback()
			errB = err
			return
		}
		errB = tx.Commit()
	}()

	wg.Wait()

	var okCount, refused int
	for _, err := range []error{errA, errB} {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, vaults.ErrVaultQuotaExceeded):
			refused++
		default:
			// With the lock present this never happens: exactly one racer
			// succeeds and the other is cleanly refused. Without it, both
			// racers decide (on the same stale read) to write, and SQLite's
			// own locking then has both fighting to become the writer with
			// no coordinating read to arbitrate between them -- a lock
			// contention error here is itself evidence the guard is gone,
			// not an unrelated flake.
			t.Fatalf("unexpected error (a sign the row lock is missing and the racers are contending uncoordinated): %v", err)
		}
	}
	require.Equal(t, 1, okCount, "exactly one concurrent create may succeed")
	require.Equal(t, 1, refused, "the other must be refused for quota")

	var finalCount int
	require.NoError(t, sqlDB.QueryRow(
		"SELECT COUNT(*) FROM vaults WHERE created_by = ?", testPrincipal.String()).Scan(&finalCount))
	require.Equal(t, 2, finalCount,
		"final vault count must equal the quota exactly, proven against the database, not just the returned errors")
}
