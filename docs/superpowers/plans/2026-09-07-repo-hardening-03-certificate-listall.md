# Repository Hardening — Plan 03: `CertificateRepository.ListAll` SELECT-List Duplication

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the second hand-written SELECT list in `certificate_repository.go` by routing `ListAll` through the canonical `certificateColumns` const and the shared `scanCertificateRow`, removing three `uuid.MustParse` panic sites in the process.

**Architecture:** `certificate_repository.go` carries two column lists: the shared `certificateColumns` const (line 65) and a literal inside `ListAll` (line 709), which the certificate renewal scheduler reads through. The literal omits `vault_id`, `deleted_at`, and `purge_protection`, and its inline scanner uses `uuid.MustParse`. This is exactly the duplication that previously hid a bug where `keyColumns`/`certificateColumns` omitted `deleted_at`/`purge_protection` and every `List()` silently returned both fields zero-valued. One list, one scanner, no second place to forget.

**Tech Stack:** Go 1.24, `database/sql`, `github.com/google/uuid`, `testify`, in-memory SQLite.

**Spec:** `docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md` (finding F2)

## Global Constraints

- **No exported interface, signature, or error-message change.** `ListAll`'s signature (`ListAll(ctx context.Context) ([]model.Certificate, error)`) stays exactly as declared on `CertificateRepositoryInterface:52`. `internal/repositories/mocks/` must not be regenerated.
- **Never use `uuid.MustParse` in repository code.** It panics; every scanner returns a wrapped error instead.
- Tests live in `package repositories_test`. Package-scope helpers `setupTestDB`, `setupRotationTestDB`, `setupSessionTestDB`, and `setupCertLifecycleTestDB` already exist — name new helpers distinctly.
- Test helpers return `*sql.DB`; callers wrap with `rvdb.NewConn(db, rvdb.SQLite)`. The logger is `logging.InitLogger()`.
- Branch: `refactor/repo-hardening`. One signed commit per task (GPG key `61D246B30285ED35`).
- Per task, before committing: `go build ./...`, `go vet ./...`, `go test ./internal/repositories/... ./internal/services/...`

## Context an implementer needs

`ListAll`'s only caller is `internal/services/certificates/renewal_service.go:45`, inside `CheckAndRenewCertificates`. That method reads `cert.ExpiresAt`, `cert.RenewalDays`, `cert.AutoRenew`, `cert.CreatedAt`, `cert.ID`, `cert.UserID`, and `cert.Name`, and passes `model.NewAdminScope(cert.UserID)` to `RenewCertificate`.

It does **not** read `cert.VaultID`. So the missing `vault_id` column is a latent trap, not a live bug — an admin scope applies no vault predicate, so the zero value never reaches a query today. Do not describe this change as fixing a live vault-scoping bug; it is not. The live problem is the panic.

---

### Task 1: Route `ListAll` through the shared column list and scanner

**Files:**
- Modify: `internal/repositories/certificate_repository.go:704-744` (`ListAll`)
- Test: `internal/repositories/certificate_listall_test.go` (create)

**Interfaces:**
- Consumes: `certificateColumns` (`certificate_repository.go:65`) and `scanCertificateRow` (`:68`), both already present and unexported.
- Produces: nothing new; one method body changes.

- [ ] **Step 1: Write the failing test**

```go
// internal/repositories/certificate_listall_test.go
package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// setupCertListAllTestDB creates an in-memory SQLite database with the
// certificates table. Named distinctly from the package-scope setupTestDB,
// setupRotationTestDB, setupSessionTestDB and setupCertLifecycleTestDB helpers
// that already exist in this test package.
func setupCertListAllTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:certlistall_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP,
			auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days INTEGER NOT NULL DEFAULT 30,
			key_id TEXT,
			ca_cert_id TEXT,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			not_before TIMESTAMP,
			deleted_at TIMESTAMP,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE TABLE certificate_tags (
			certificate_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag)
		);
	`)
	require.NoError(t, err, "create certificates schema")

	return raw
}

// TestListAllPopulatesVaultID pins the F2 fix: ListAll must read through the
// canonical certificateColumns list, so vault_id survives the listing the
// renewal scheduler reads. Before the fix ListAll used its own SELECT list
// that omitted the column entirely, leaving VaultID zero on every row.
func TestListAllPopulatesVaultID(t *testing.T) {
	raw := setupCertListAllTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	vaultID := uuid.New()
	certID := uuid.New()

	_, err := raw.ExecContext(ctx,
		`INSERT INTO certificates
		 (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at,
		  auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before)
		 VALUES (?, ?, ?, 'web', 'PEM', 'KEY', ?, ?, TRUE, 30, ?, NULL, TRUE, NULL)`,
		certID.String(), uuid.New().String(), vaultID.String(),
		time.Now(), time.Now().Add(48*time.Hour), uuid.New().String())
	require.NoError(t, err, "insert certificate")

	certs, err := repo.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.Equal(t, vaultID, certs[0].VaultID, "vault_id must survive the ListAll read")
}

// TestListAllRejectsMalformedID pins the removal of uuid.MustParse: a corrupt
// id column must return an error, not panic the renewal scheduler's goroutine.
func TestListAllRejectsMalformedID(t *testing.T) {
	raw := setupCertListAllTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	_, err := raw.ExecContext(ctx,
		`INSERT INTO certificates
		 (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at,
		  auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before)
		 VALUES ('not-a-uuid', ?, ?, 'web', 'PEM', 'KEY', ?, ?, TRUE, 30, NULL, NULL, TRUE, NULL)`,
		uuid.New().String(), uuid.New().String(), time.Now(), time.Now().Add(48*time.Hour))
	require.NoError(t, err, "insert certificate with corrupt id")

	require.NotPanics(t, func() {
		_, err = repo.ListAll(ctx)
	}, "a corrupt id must not panic the renewal scheduler")
	require.Error(t, err, "a corrupt id must be reported as an error")
	require.Contains(t, err.Error(), "failed to parse certificate ID")
}

// TestListAllSkipsSoftDeleted confirms the WHERE clause is unchanged by the
// refactor -- the new column list adds deleted_at to the SELECT, and this
// guards against someone concluding it should therefore be returned.
func TestListAllSkipsSoftDeleted(t *testing.T) {
	raw := setupCertListAllTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	_, err := raw.ExecContext(ctx,
		`INSERT INTO certificates
		 (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at,
		  auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, deleted_at)
		 VALUES (?, ?, ?, 'gone', 'PEM', 'KEY', ?, ?, TRUE, 30, NULL, NULL, TRUE, NULL, ?)`,
		uuid.New().String(), uuid.New().String(), uuid.New().String(),
		time.Now(), time.Now().Add(48*time.Hour), time.Now())
	require.NoError(t, err, "insert soft-deleted certificate")

	certs, err := repo.ListAll(ctx)
	require.NoError(t, err)
	require.Empty(t, certs, "soft-deleted certificates stay out of ListAll")
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `go test ./internal/repositories/ -run TestListAll -v`
Expected:
- `TestListAllPopulatesVaultID` FAILS — `certs[0].VaultID` is `uuid.Nil`, not `vaultID`.
- `TestListAllRejectsMalformedID` FAILS — `uuid.MustParse` panics, so `require.NotPanics` fails.
- `TestListAllSkipsSoftDeleted` PASSES already (the `WHERE deleted_at IS NULL` clause is not changing).

- [ ] **Step 3: Replace the `ListAll` body**

In `internal/repositories/certificate_repository.go`, replace the whole body of `ListAll` (lines 705-743, from `var certs []model.Certificate` through `return certs, err`) with:

```go
	var certs []model.Certificate

	err := r.executeWithMetrics("list_all_certificates", func() error {
		// Reads through the shared certificateColumns/scanCertificateRow pair
		// rather than a second hand-written SELECT list. The previous literal
		// omitted vault_id, deleted_at and purge_protection, and parsed with
		// uuid.MustParse -- a corrupt column panicked the renewal scheduler's
		// goroutine instead of returning an error.
		rows, err := r.db.QueryContext(ctx,
			"SELECT "+certificateColumns+" FROM certificates WHERE deleted_at IS NULL")
		if err != nil {
			return fmt.Errorf("failed to list all certificates: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			cert, scanErr := scanCertificateRow(rows.Scan)
			if scanErr != nil {
				return scanErr
			}
			certs = append(certs, cert)
		}

		return rows.Err()
	})

	return certs, err
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/repositories/ -run TestListAll -v`
Expected: all three PASS.

- [ ] **Step 5: Confirm the file now has exactly one certificate column list**

Run: `grep -n "SELECT id, user_id" internal/repositories/certificate_repository.go`
Expected: no output — the only remaining SELECT list is the `certificateColumns` const at line 65.

Run: `grep -n "uuid.MustParse" internal/repositories/certificate_repository.go`
Expected: no output.

- [ ] **Step 6: Run the full verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

Pay particular attention to `internal/services/certificates/` — if a renewal test asserted on a zero `VaultID`, it was encoding the bug and should be updated to expect the real vault ID.

- [ ] **Step 7: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/certificate_repository.go internal/repositories/certificate_listall_test.go
```

---

### Task 2: Guard the single-column-list invariant

**Files:**
- Modify: `internal/repositories/certificate_repository.go:64-65` (the `certificateColumns` doc comment)
- Test: `internal/repositories/certificate_listall_test.go` (extend)

**Interfaces:**
- Consumes: `certificateColumns`, `scanCertificateRow` from Task 1.
- Produces: nothing new.

Task 1 removed the duplicate list. This task makes it costly to reintroduce one, since the same mistake has now been made twice in this file's history.

- [ ] **Step 1: Write the guard test**

Append to `internal/repositories/certificate_listall_test.go`:

```go
// TestCertificateSelectListIsNotDuplicated guards the F2 invariant. The
// certificates table has had a second, drifting SELECT list twice: once when
// certificateColumns omitted deleted_at/purge_protection, and again in
// ListAll, which additionally omitted vault_id and parsed with uuid.MustParse.
// Both times the drift was silent -- the affected fields simply read as zero.
//
// The guard is the fragment "user_id, name, certificate", which appears only
// in a certificates column list that has DROPPED vault_id. The canonical
// certificateColumns const and the INSERT both read
// "user_id, vault_id, name, certificate", so neither matches. That makes this
// assertion specific to the actual failure mode -- a hand-written list that
// drifted from the canonical one -- rather than to the shape of SQL in
// general.
//
// Note a blunter "SELECT id, user_id" check does NOT work here: ListRevoked
// legitimately issues "SELECT id, user_id, serial_number, name, revoked_at
// FROM crl", a different table with nothing to do with this invariant.
func TestCertificateSelectListIsNotDuplicated(t *testing.T) {
	src, err := os.ReadFile("certificate_repository.go")
	require.NoError(t, err, "read certificate_repository.go")

	require.NotContains(t, string(src), "user_id, name, certificate",
		"a certificates column list is missing vault_id — add columns to the certificateColumns const, never to a second hand-written list")
	require.NotContains(t, string(src), "uuid.MustParse",
		"repository scanners return wrapped parse errors; MustParse panics the caller's goroutine")
}
```

Add `"os"` to the file's import block.

- [ ] **Step 2: Run the test and verify it passes**

Run: `go test ./internal/repositories/ -run TestCertificateSelectListIsNotDuplicated -v`
Expected: PASS (Task 1 already removed both patterns).

- [ ] **Step 3: Verify the guard actually catches a regression**

Temporarily reintroduce the pattern to confirm the test is not vacuous:

```bash
# Add a throwaway line, confirm the test goes red, then revert it.
printf '\n// SELECT id, user_id, name FROM certificates\n' >> internal/repositories/certificate_repository.go
go test ./internal/repositories/ -run TestCertificateSelectListIsNotDuplicated
# Expected: FAIL
git checkout internal/repositories/certificate_repository.go
go test ./internal/repositories/ -run TestCertificateSelectListIsNotDuplicated
# Expected: PASS
```

Do not skip this step. A guard test that cannot fail is worse than no guard test, because it reads as coverage.

- [ ] **Step 4: Strengthen the `certificateColumns` comment**

Replace lines 64-65 of `internal/repositories/certificate_repository.go`:

```go
// certificateColumns is the canonical SELECT list shared by every scoped query.
const certificateColumns = "id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, deleted_at, purge_protection"
```

with:

```go
// certificateColumns is the canonical SELECT list for every certificates read
// in this file, ListAll included. It is the ONLY one: a new column goes here
// and into scanCertificateRow, never into a second hand-written list.
//
// This file has grown a competing list twice, and both times the drift was
// silent -- the omitted fields simply read back as their zero values, so
// nothing failed until someone depended on one. TestCertificateSelectListIsNotDuplicated
// now fails the build if a third one appears.
const certificateColumns = "id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, deleted_at, purge_protection"
```

- [ ] **Step 5: Run the full verification**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./internal/services/...`
Expected: all PASS

- [ ] **Step 6: Commit** (use the `1-git-commit` skill)

```bash
git add internal/repositories/certificate_repository.go internal/repositories/certificate_listall_test.go
```

---

## On completion

Finding F2 is closed. `certificate_repository.go` has one SELECT list and no `uuid.MustParse`, guarded by a test proven to fail when the pattern returns.

**Next plan — execute this immediately, without asking:**
`docs/superpowers/plans/2026-09-07-repo-hardening-04-error-sentinels.md`
