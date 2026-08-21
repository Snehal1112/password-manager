# B40 — `backup list` Hides Encrypted Backups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `backup list` show every `*.backup` file in a directory — encrypted, unencrypted or corrupt — instead of silently discarding any file whose contents don't start with `{`.

**Architecture:** `internal/backup.Manager.getBackupMetadata` currently treats "doesn't parse as plaintext JSON" as a hard error, and `ListBackups` drops any file that errors. The fix keeps the same content-sniffing test but stops treating a negative result as fatal: it becomes `Readable: false` on an enriched `BackupMetadata` that always carries filesystem-derived `Filename`/`Size`/`ModTime`, so every file still produces a row. `cmd/backup.go`'s table then renders the payload-derived columns (`TIMESTAMP`, `VERSION`, `TABLES`, `RECORDS`) as `-` for unreadable rows, adds `SIZE`/`MODIFIED` columns sourced from the filesystem, and prints the real `FILE` from disk instead of one synthesized from a payload timestamp that unreadable rows don't have.

**Tech Stack:** Go 1.24.2, `encoding/json`, `testify/require`.

**Spec:** `docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`

## Global Constraints

Copied verbatim from the spec's `## Non-goals` section (applies to all of
B35–B41; the lines relevant to this plan are the first and second):

- No down-migration support (B39 decision).
- No change to `backup`'s master-key sealing, which is correct for
  same-instance disaster recovery.
- No re-encryption or repair tooling for already-corrupted secrets; the plan
  documents what is and is not recoverable.
- No changes to the prose docs (`docs/cli-guide.md` and friends), which are a
  separate outstanding pass.

This plan's own explicit addition, required by the task brief and not a
literal spec quote (the design doc has no section titled "Global
constraints" — the closest actual heading is `## Non-goals`, quoted above):

- **Listing must never require or touch the master key.** `getBackupMetadata`
  and `ListBackups` must not call `common.DecryptSecret` / `common.EncryptSecret`
  or otherwise attempt decryption. A listing that fails or hangs when the
  master key is unavailable is worse than the bug it replaces — encrypted
  backups must list by filesystem metadata alone.
- Do not plan or implement decryption-during-listing in any task below.

---

### Task 1: Detect encrypted/corrupt backups by content, and stop discarding them

**Files:**
- Modify: `internal/backup/backup.go` (`BackupMetadata` struct at l.39-47,
  `getBackupMetadata` at l.476-496, `ListBackups` doc comment at l.204-205)
- Modify: `internal/backup/backup_internal_edge_test.go` (`TestListBackupsWithEncryptedFile`
  at l.91-107, `TestGetBackupMetadataEncryptedFile` at l.109-122)

**Interfaces:**
- Consumes: nothing new — `os.Open`, `io.ReadAll`, `encoding/json.Unmarshal`,
  all already reachable from this file (`io` is a new import).
- Produces (signature unchanged, behavior changed):
  ```go
  type BackupMetadata struct {
      Filename    string    `json:"filename"`
      Size        int64     `json:"size"`
      ModTime     time.Time `json:"mod_time"`
      Readable    bool      `json:"readable"`
      Version     string    `json:"version,omitempty"`
      Timestamp   time.Time `json:"timestamp,omitempty"`
      Database    string    `json:"database,omitempty"`
      TableCount  int       `json:"table_count,omitempty"`
      RecordCount int       `json:"record_count,omitempty"`
      Encrypted   bool      `json:"encrypted"`
      Checksum    string    `json:"checksum,omitempty"`
  }

  func (m *Manager) getBackupMetadata(backupPath string) (*BackupMetadata, error)
  ```
  `getBackupMetadata` now only returns an error for a real filesystem failure
  (open/stat/read). A file that isn't plaintext-JSON-parseable returns
  `(*BackupMetadata, nil)` with `Readable: false`, `Encrypted: true`, and
  `Filename`/`Size`/`ModTime` populated from the filesystem.

- [ ] **Step 1: Write the failing tests**

Replace lines 91-122 of `internal/backup/backup_internal_edge_test.go` (the
existing `TestListBackupsWithEncryptedFile` and
`TestGetBackupMetadataEncryptedFile`) with the following four tests. The two
renamed/rewritten tests assert the corrected behavior in place of the bug;
the two new tests are this plan's headline cases.

```go
func TestListBackupsWithEncryptedFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())

	// One plain backup and one encrypted backup -- both must appear.
	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "good.backup"), false))
	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "enc.backup"), true))

	backups, err := mgr.ListBackups(tmpDir)
	require.NoError(t, err)
	require.Len(t, backups, 2)

	byFile := make(map[string]BackupMetadata, len(backups))
	for _, b := range backups {
		byFile[b.Filename] = b
	}

	good, ok := byFile["good.backup"]
	require.True(t, ok)
	require.True(t, good.Readable)
	require.False(t, good.Encrypted)
	require.NotZero(t, good.TableCount)

	enc, ok := byFile["enc.backup"]
	require.True(t, ok)
	require.False(t, enc.Readable)
	require.True(t, enc.Encrypted)
	require.Zero(t, enc.TableCount)
	require.Zero(t, enc.RecordCount)
	require.True(t, enc.Timestamp.IsZero())
	require.Positive(t, enc.Size)
}

// TestListBackupsAllEncrypted is the B40 headline case: a directory holding
// only encrypted backups must list them, not report an empty directory.
func TestListBackupsAllEncrypted(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())

	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "enc1.backup"), true))
	require.NoError(t, mgr.CreateBackup(filepath.Join(tmpDir, "enc2.backup"), true))

	backups, err := mgr.ListBackups(tmpDir)
	require.NoError(t, err)
	require.NotEmpty(t, backups)
	require.Len(t, backups, 2)
	for _, b := range backups {
		require.False(t, b.Readable)
		require.True(t, b.Encrypted)
		require.NotEmpty(t, b.Filename)
		require.Positive(t, b.Size)
	}
}

func TestGetBackupMetadataEncryptedFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "enc.backup")
	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
	require.NoError(t, mgr.CreateBackup(encPath, true))

	meta, err := mgr.getBackupMetadata(encPath)
	require.NoError(t, err)
	require.False(t, meta.Readable)
	require.True(t, meta.Encrypted)
	require.Equal(t, "enc.backup", meta.Filename)
	require.Positive(t, meta.Size)
	require.Zero(t, meta.TableCount)
	require.Zero(t, meta.RecordCount)
	require.True(t, meta.Timestamp.IsZero())
}

// TestGetBackupMetadataCorruptFile covers a file that is neither plaintext
// backup JSON nor a normal encrypted backup -- e.g. truncated or hand-edited.
// The content-based detection in getBackupMetadata cannot distinguish this
// from "encrypted" (both fail the plaintext-JSON-parse test), so it gets the
// same treatment: list it, don't error.
func TestGetBackupMetadataCorruptFile(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir := t.TempDir()
	corruptPath := filepath.Join(tmpDir, "corrupt.backup")
	// Starts with '{' but is not valid backup JSON.
	require.NoError(t, os.WriteFile(corruptPath, []byte("{not valid json"), 0600))

	mgr := NewManager(db, rvdb.SQLite, logging.InitLogger())
	meta, err := mgr.getBackupMetadata(corruptPath)
	require.NoError(t, err)
	require.False(t, meta.Readable)
	require.Equal(t, "corrupt.backup", meta.Filename)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./internal/backup/ -run 'TestListBackupsWithEncryptedFile|TestListBackupsAllEncrypted|TestGetBackupMetadataEncryptedFile|TestGetBackupMetadataCorruptFile' -v
```
Expected: build failure — `meta.Readable undefined (type *BackupMetadata has
no field or method Readable)` (and similarly for `.Filename`, `.Size`) — the
struct doesn't have these fields yet.

- [ ] **Step 3: Implement the struct and detection changes**

In `internal/backup/backup.go`, add `"io"` to the import block (alongside the
existing `"os"`), then replace the `BackupMetadata` struct (l.39-47) with:

```go
// BackupMetadata contains metadata about a backup. Filename, Size and ModTime
// are always populated from the filesystem, regardless of whether the file's
// payload could be read. Readable is false when the file's contents could not
// be parsed as plaintext backup JSON -- either because it is encrypted (the
// expected case for a default "backup create") or genuinely corrupt. When
// Readable is false, Version, Timestamp, TableCount and RecordCount are their
// zero values and must not be treated as real data; Encrypted is set true in
// that case as a best-effort inference from content, not a decrypted fact.
type BackupMetadata struct {
	Filename    string    `json:"filename"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
	Readable    bool      `json:"readable"`
	Version     string    `json:"version,omitempty"`
	Timestamp   time.Time `json:"timestamp,omitempty"`
	Database    string    `json:"database,omitempty"`
	TableCount  int       `json:"table_count,omitempty"`
	RecordCount int       `json:"record_count,omitempty"`
	Encrypted   bool      `json:"encrypted"`
	Checksum    string    `json:"checksum,omitempty"`
}
```

Replace `getBackupMetadata` (l.475-496 including its doc comment) with:

```go
// getBackupMetadata reads metadata from a backup file. It never requires or
// touches the master key: detection is content-based (does the file parse as
// plaintext backup JSON?), never decryption-based. A file that fails that
// parse -- encrypted or corrupt -- still returns filesystem-derived metadata
// with Readable set to false, rather than an error; only a real filesystem
// failure (the file can't be opened, stat'd or read) returns an error.
func (m *Manager) getBackupMetadata(backupPath string) (*BackupMetadata, error) {
	f, err := os.Open(backupPath)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	base := BackupMetadata{
		Filename: filepath.Base(backupPath),
		Size:     info.Size(),
		ModTime:  info.ModTime(),
	}

	content := string(data)

	// A file whose contents don't start with '{' isn't plaintext backup
	// JSON -- it's either an encrypted backup (the default "backup create"
	// output) or genuinely corrupt. Either way, list it: the filesystem
	// fields above are still real, even though the payload isn't readable
	// without the master key, which this function never touches.
	if len(content) == 0 || content[0] != '{' {
		base.Encrypted = true
		return &base, nil
	}

	var backupData BackupData
	if err := json.Unmarshal([]byte(content), &backupData); err != nil {
		// Starts with '{' but isn't valid backup JSON: also genuinely
		// corrupt. Same treatment -- list what the filesystem knows, no
		// payload fields.
		base.Encrypted = true
		return &base, nil
	}

	md := backupData.Metadata
	md.Filename = base.Filename
	md.Size = base.Size
	md.ModTime = base.ModTime
	md.Readable = true
	return &md, nil
}
```

Update the `ListBackups` doc comment (l.204-205) to describe the new
contract:

```go
// ListBackups lists available backup files in a directory. A backup that
// cannot be read as plaintext JSON -- e.g. a normal encrypted backup --
// still appears as a row via getBackupMetadata's content-based fallback;
// only a real filesystem error (permission denied, file removed mid-scan)
// causes a file to be skipped, and that skip is still logged as a warning.
func (m *Manager) ListBackups(backupDir string) ([]BackupMetadata, error) {
```

The function body below that comment is unchanged — it already just skips on
error and appends otherwise, and `getBackupMetadata` no longer errors for the
content-mismatch case.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./internal/backup/ -run 'TestListBackupsWithEncryptedFile|TestListBackupsAllEncrypted|TestGetBackupMetadataEncryptedFile|TestGetBackupMetadataCorruptFile' -v
```
Expected: PASS, all four tests.

- [ ] **Step 5: Run the whole package to check for regressions**

Run:
```bash
go test ./internal/backup/... -v
gofmt -l internal/backup
go vet ./internal/backup/...
```
Expected: all pass, `gofmt` prints nothing. In particular
`TestBackupMetadata` (`backup_test.go`, unencrypted case) and the
`ListBackups` subtest of `TestBackupManager` must still pass unchanged — they
only exercise the readable path, which this task does not alter.

- [ ] **Step 6: Confirm no master-key use was introduced**

Run:
```bash
grep -n "DecryptSecret\|EncryptSecret" internal/backup/backup.go
```
Expected: the only matches are the pre-existing calls inside
`writeBackupFile`/`readBackupFile` (used by `CreateBackup`/`RestoreBackup`,
not by `getBackupMetadata`/`ListBackups`). If `getBackupMetadata` or
`ListBackups` appear near either call, stop — that would violate the Global
Constraints above.

- [ ] **Step 7: Commit**

```bash
git add internal/backup/backup.go internal/backup/backup_internal_edge_test.go
git commit -m "fix(backup): list encrypted and corrupt backups instead of hiding them

getBackupMetadata rejected any file not starting with '{' as an error,
and ListBackups silently skipped it -- so a directory of default
(encrypted) backups listed as empty. Detection is now content-based but
non-fatal: an unreadable file still produces a row, with filesystem
metadata (filename, size, mod time) and Readable=false, rather than
being discarded. Fixes B40."
```

---

### Task 2: `backup list` renders every row, with real filenames and honest gaps

**Files:**
- Modify: `cmd/backup.go` (`runBackupList` at l.252-295, table header/rows at
  l.276-289)
- Create: `cmd/backup_test.go`

**Interfaces:**
- Consumes: `backup.BackupMetadata` (extended in Task 1), `Manager.ListBackups`.
- Produces:
  ```go
  func backupListRow(b backup.BackupMetadata) [8]string
  ```
  Order: `[timestamp, version, tables, records, encrypted, file, size, modified]`.
  The first four render `"-"` when `b.Readable` is false; the last four are
  always populated (encrypted/file/size/modified all come from
  `BackupMetadata` fields that are set regardless of readability).

- [ ] **Step 1: Write the failing test**

Create `cmd/backup_test.go`:

```go
package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
)

func TestBackupListRowReadable(t *testing.T) {
	ts := time.Date(2026, 8, 20, 10, 30, 0, 0, time.UTC)
	mod := time.Date(2026, 8, 20, 10, 30, 5, 0, time.UTC)
	b := backup.BackupMetadata{
		Filename:    "good.backup",
		Size:        1024,
		ModTime:     mod,
		Readable:    true,
		Version:     "1.0",
		Timestamp:   ts,
		TableCount:  5,
		RecordCount: 42,
		Encrypted:   false,
	}

	row := backupListRow(b)

	require.Equal(t, "2026-08-20 10:30:00", row[0]) // timestamp
	require.Equal(t, "1.0", row[1])                 // version
	require.Equal(t, "5", row[2])                   // tables
	require.Equal(t, "42", row[3])                  // records
	require.Equal(t, "false", row[4])               // encrypted
	require.Equal(t, "good.backup", row[5])         // file
	require.Equal(t, "1024", row[6])                // size
	require.Equal(t, "2026-08-20 10:30:05", row[7]) // modified
}

func TestBackupListRowUnreadable(t *testing.T) {
	mod := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	b := backup.BackupMetadata{
		Filename:  "enc.backup",
		Size:      2048,
		ModTime:   mod,
		Readable:  false,
		Encrypted: true,
	}

	row := backupListRow(b)

	require.Equal(t, "-", row[0]) // timestamp unknown -- listing never decrypts
	require.Equal(t, "-", row[1]) // version unknown
	require.Equal(t, "-", row[2]) // tables unknown
	require.Equal(t, "-", row[3]) // records unknown
	require.Equal(t, "true", row[4])
	require.Equal(t, "enc.backup", row[5]) // actual filename, not synthesized from a timestamp
	require.Equal(t, "2048", row[6])
	require.Equal(t, "2026-08-21 09:00:00", row[7])
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestBackupListRow -v`
Expected: build failure — `undefined: backupListRow`.

- [ ] **Step 3: Implement `backupListRow` and rewire `runBackupList`**

In `cmd/backup.go`, replace `runBackupList` (l.252-295) with:

```go
func runBackupList(cmd *cobra.Command) error {
	if _, err := requireBackupAdmin(cmd); err != nil {
		return err
	}

	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)

	// Create backup manager
	manager := backup.NewManager(db, backupDialect(), logger)

	// List backups
	backups, err := manager.ListBackups(backupListDir)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	if len(backups) == 0 {
		fmt.Printf("No backup files found in %s\n", backupListDir)
		return nil
	}

	// Display results in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tVERSION\tTABLES\tRECORDS\tENCRYPTED\tFILE\tSIZE\tMODIFIED") //nolint:errcheck
	fmt.Fprintln(w, "---------\t-------\t------\t-------\t---------\t----\t----\t--------") //nolint:errcheck

	for _, b := range backups {
		row := backupListRow(b)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck
			row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7])
	}

	w.Flush() //nolint:errcheck,gosec
	fmt.Printf("\n📊 Found %d backup files in %s\n", len(backups), backupListDir)

	return nil
}

// backupListRow renders one "backup list" row as
// [timestamp, version, tables, records, encrypted, file, size, modified].
// Timestamp, version, tables and records come from the backup's payload and
// render as "-" when b.Readable is false -- an encrypted (or corrupt) backup
// never has its payload read during listing, so those columns are honestly
// unknown rather than guessed. File, size and modified always come from the
// filesystem and are populated regardless of readability.
func backupListRow(b backup.BackupMetadata) [8]string {
	timestamp, version, tables, records := "-", "-", "-", "-"
	if b.Readable {
		timestamp = b.Timestamp.Format("2006-01-02 15:04:05")
		version = b.Version
		tables = fmt.Sprintf("%d", b.TableCount)
		records = fmt.Sprintf("%d", b.RecordCount)
	}
	return [8]string{
		timestamp,
		version,
		tables,
		records,
		fmt.Sprintf("%t", b.Encrypted),
		b.Filename,
		fmt.Sprintf("%d", b.Size),
		b.ModTime.Format("2006-01-02 15:04:05"),
	}
}
```

No import changes: `fmt`, `os`, `text/tabwriter`, `database/sql`,
`rocketvault/common`, `rocketvault/internal/backup`, `rocketvault/internal/logging`
are all already imported in `cmd/backup.go`. `filepath.Base` is no longer
called in this function, but `path/filepath` stays imported — `filepath.Dir`
is still used in `runBackupCreate` (l.232).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/ -run TestBackupListRow -v`
Expected: PASS, both tests.

- [ ] **Step 5: Verify the package still builds and tests pass**

Run:
```bash
go build ./...
go test ./cmd/... -v
gofmt -l cmd
go vet ./cmd/...
```
Expected: all pass, `gofmt` silent.

- [ ] **Step 6: Manual smoke check of the rendered table**

Run:
```bash
go run . backup list --dir ./nonexistent-dir-for-smoke-test
```
Expected: `No backup files found in ./nonexistent-dir-for-smoke-test` (this
just confirms the binary still builds and the command still runs end to end;
full behavioral coverage is in the unit tests above since exercising the real
`RunE` needs an authenticated admin session).

- [ ] **Step 7: Commit**

```bash
git add cmd/backup.go cmd/backup_test.go
git commit -m "fix(backup): render actual filename and honest gaps in backup list

The FILE column was synthesized from each backup's own timestamp
instead of read from disk, so it disagreed with a renamed file. It now
uses BackupMetadata.Filename. Adds SIZE and MODIFIED columns (always
filesystem-derived) and renders TIMESTAMP/VERSION/TABLES/RECORDS as
'-' for a backup whose payload wasn't read. Part of B40."
```

---

### Task 3: Correct the help text that describes the old (buggy) behavior

**Files:**
- Modify: `cmd/backup.go` (`backupListCmd.Long` at l.148-159,
  `backupCreateCmd.Long` at l.117-132, `backupCreateCmd.Example` at l.133-138)

**Interfaces:** none — prose only, no flags added or removed. No new test;
verification is the existing `cmd/help_examples_test.go` guard plus a manual
read-through against `.claude/cli-help-conventions.md`.

- [ ] **Step 1: Replace `backupListCmd`'s `Long`**

In `cmd/backup.go`, replace the `Long` field of `backupListCmd` (the string
currently starting "Scan a directory for files matching..." at l.148) with:

```go
	Long: `Scan a directory for files matching "*.backup" and print one row per file:
when it was taken, its format version, how many tables and records it holds,
whether it is encrypted, its filename, size and modification time. The scan
is not recursive.

Requires the global admin role.

Listing never requires the master key and never decrypts a backup. Metadata
is read by attempting a plaintext JSON parse; a backup written with the
default encryption fails that parse, so its TIMESTAMP, VERSION, TABLES and
RECORDS columns print "-" instead of real values. FILE, SIZE and MODIFIED
always come from the filesystem, so an encrypted backup — or even a corrupt
one — still appears as a row, identified by its actual filename, instead of
being silently skipped. A directory holding only encrypted backups is never
reported as empty.`,
```

Leave `backupListCmd.Example` unchanged — it names only `--dir`, which is
still accurate and still registered.

- [ ] **Step 2: Replace `backupCreateCmd`'s `Long` and `Example`**

`backupCreateCmd.Long`'s last sentence ("Only unencrypted backups can be
inspected with \"backup list\".") is now false — both kinds appear in the
listing, they just show different detail. Replace the full `Long` field
(l.117-132) with:

```go
	Long: `Write every table in the database to one JSON file: all vaults' secrets, keys
and certificates, including soft-deleted rows, together with users, sessions,
role assignments and the audit log. Rows are copied verbatim, so values that
are sealed in the database stay sealed inside the file.

Requires the global admin role. The backup spans every vault, so --vault does
not apply.

--output is required; its directory is created if missing and the file is
written readable only by its owner. The default --encrypt=true seals the
whole file with the master key, which means it can only be restored on an
instance holding that same key. --encrypt=false writes plain JSON instead:
secret values and private keys inside it remain master-key sealed, but names,
tags, users, password hashes and role assignments become readable by anyone
who can read the file. Both encrypted and unencrypted backups appear in
"backup list"; only an unencrypted one shows its table and record counts
there, since listing never decrypts the payload.`,
```

Replace `backupCreateCmd.Example` (l.133-138), whose second scenario's
comment repeats the same now-false claim:

```go
	Example: `  # Create an encrypted backup (the default)
  rocketvault backup create --output ./backups/<name>.backup

  # Create an unencrypted backup, readable in full by "backup list"
  rocketvault backup create --output ./backups/<name>.backup \
    --encrypt=false`,
```

- [ ] **Step 3: Verify wrapping and flag registration**

Run:
```bash
go build ./...
go test ./cmd/ -run TestExampleFlagsAreRegistered -v
gofmt -l cmd
```
Expected: all pass. Then eyeball each changed paragraph against
`.claude/cli-help-conventions.md`'s "Wrap at 78 columns" rule — e.g.:
```bash
awk '{ print length, $0 }' cmd/backup.go | sort -rn | head -5
```
No line inside the three changed `Long`/`Example` blocks should be
conspicuously over 78 visible characters (the backtick-delimited Go source
lines correspond 1:1 with the printed help text).

- [ ] **Step 4: Commit**

```bash
git add cmd/backup.go
git commit -m "docs(backup): fix help text that described the pre-fix listing bug

backupListCmd and backupCreateCmd both claimed only unencrypted backups
are visible to 'backup list'. That was the bug; now both kinds list,
so both Long strings are corrected to describe actual behavior. Part
of B40."
```

---

### Task 4: Full verification and bug-tracker update

**Files:**
- Modify: `.claude/known-bugs.md` (B40 entry, currently at l.1884-1898)

**Interfaces:** none.

- [ ] **Step 1: Full-repo verification**

Run:
```bash
go build ./...
go test ./...
gofmt -l .
go vet ./...
```
Expected: all pass, `gofmt` prints nothing, no regressions outside
`internal/backup` and `cmd`.

- [ ] **Step 2: Re-confirm the three headline scenarios by hand**

These are already covered by `TestListBackupsAllEncrypted` (Task 1),
`TestListBackupsWithEncryptedFile` (Task 1) and `TestBackupListRowUnreadable`
(Task 2), so this step is a read-through, not new test-writing:

- A directory containing only encrypted backups lists non-empty, filename
  present, payload columns `-` — `TestListBackupsAllEncrypted`.
- A mixed directory lists both kinds correctly — `TestListBackupsWithEncryptedFile`.
- A genuinely corrupt file still lists rather than vanishing —
  `TestGetBackupMetadataCorruptFile`.

If any of these three is not actually exercised by name in
`internal/backup/backup_internal_edge_test.go` or `cmd/backup_test.go` at
this point, stop and go back — a task was skipped.

- [ ] **Step 3: Update `.claude/known-bugs.md`**

Get the commit hash for Task 1 (or the most recent of the three fix commits):
```bash
git log --oneline -3
```

In `.claude/known-bugs.md`, change the B40 entry's status line (currently
`**Status**: Open, found 2026-08-21`, at l.1886) to:

```markdown
**Status**: Fixed in commit `<short-hash>` (2026-08-21)
```

Replace `<short-hash>` with the actual hash from the log output. Leave the
rest of the entry (Severity, Files, root-cause description) as-is — it
remains an accurate description of what was wrong.

- [ ] **Step 4: Commit the bug-tracker update**

```bash
git add .claude/known-bugs.md
git commit -m "docs(known-bugs): mark B40 fixed

backup list now lists encrypted and corrupt backups instead of
silently discarding them, and FILE reflects the real filename."
```

## Definition of Done

- `internal/backup.BackupMetadata` carries `Filename`/`Size`/`ModTime`/`Readable`
  in addition to the existing payload fields.
- `getBackupMetadata` never errors on a file that merely fails the
  plaintext-JSON content test; it only errors on a real filesystem failure.
  It never calls `common.DecryptSecret`/`common.EncryptSecret`.
- `ListBackups` returns a row for every `*.backup` file in the directory
  except ones that hit a genuine filesystem error (still logged and skipped).
- `backup list`'s `FILE` column is the real filename from disk; `TIMESTAMP`,
  `VERSION`, `TABLES`, `RECORDS` print `-` for a backup whose payload wasn't
  read; `SIZE`/`MODIFIED` are always populated from the filesystem.
- `backupListCmd.Long` and `backupCreateCmd.Long`/`Example` no longer claim
  encrypted backups are invisible to `backup list`.
- `go build ./...`, `go test ./...`, `gofmt -l .`, `go vet ./...` all clean.
- `.claude/known-bugs.md`'s B40 entry marked Fixed with a real commit hash.
