# B42 CSV Round-Trip Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `secret_service.go`'s hand-rolled CSV writing and parsing with `encoding/csv`, so a secret value or tag containing a quote, a comma, or a newline round-trips through `secrets export --format csv` and `secrets import --format csv` intact instead of being silently corrupted.

**Architecture:** `ExportSecrets`'s CSV branch builds each row with `encoding/csv.Writer.Write`, encoding a secret's tag list into a single field via a small nested `csv.Writer`/`csv.Reader` pair (`csvEncodeTags`/`csvDecodeTags`) rather than a bare comma-join, so a tag containing a comma survives. `ImportSecrets`'s CSV branch reads records with `encoding/csv.Reader`, locking `FieldsPerRecord` to the header row's own column count so a row with the wrong number of fields is reported as an error instead of silently truncated or misread. `parseCSVLine` is deleted; nothing else calls it.

**Tech Stack:** Go 1.24.2, `encoding/csv` (standard library, no new dependency), testify.

**Spec:** docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md

## Global Constraints

- Go 1.24.2. Do not raise the version floor.
- **No new module dependencies.** `golang.org/x/crypto` v0.48.0 and
  `golang.org/x/term` are already present and were verified to compile and run
  offline on 2026-08-21.
- Comments are short, full sentences ending in a punctuation mark.
- Never log, print, or embed a passphrase or a plaintext secret in an error
  message.
- Argon2id parameters: `time=1`, `memory=65536`, `threads=4`, `keyLen=32`,
  `saltLen=16`.
- Any help-text change follows `.claude/cli-help-conventions.md`, and
  `cmd/help_examples_test.go` must stay green — every flag named in an
  `Example` must be registered on that command or inherited.
- `go build ./...`, `go test ./...`, `gofmt -l` and `go vet` must be clean at
  the end of every task.
- Fix the defect and nothing else. Adjacent problems get filed in
  `.claude/known-bugs.md`, not fixed opportunistically.

(The Argon2id and help-text bullets above are inherited from the parent spec
verbatim, as instructed, but do not apply to this plan: B42 touches no CLI
flags and no passphrase/KDF code. The build-clean and single-defect bullets
are the ones that actually govern this work.)

---

## Relationship to B36 (`docs/superpowers/plans/2026-08-21-02-b36-export-encryption.md`)

B36 has not landed yet as of this writing — `ExportSecretsRequest` and
`ImportSecretsRequest` in the current tree still have only their original
fields (`Scope`, `Format`, `FilterTags`, `IncludeTags` / `Scope`, `Data`,
`Format`, `Overwrite`; verified by reading `secret_service.go` lines 89–103
directly). B36's own plan explicitly filed this defect as out of scope
(`2026-08-21-02-b36-export-encryption.md`, "Out of scope, deliberately": *"The
CSV writer's quoting... That is a pre-existing defect independent of
encryption — sealing a malformed CSV yields the same malformed CSV on the way
back — and it is not filed [now filed as B42]. Raise it as a new bug rather
than fixing it inside this plan."*).

**No conflict, in either landing order:**

- **If this plan lands first:** B36's Task 1 inserts a sealing block into
  `ExportSecrets` *after* the `if req.Format == "json" {...} else {...}`
  branch closes and *before* the audit-log call — i.e. after `data` already
  holds the fully-formatted bytes, whatever produced them. It wraps
  `common.SealExport` around `data`; it does not read or care how `data` was
  built. Likewise B36's Task 2 guard in `ImportSecrets` (`IsSealedExport`
  check) runs *before* the format branch this plan rewrites. The two changes
  touch adjacent, non-overlapping regions of the same two functions.
- **If B36 lands first:** the CSV branch this plan rewrites still assigns to
  the same `data []byte` variable B36's sealing block reads afterward; sealing
  a correctly-escaped CSV payload instead of a malformed one only makes the
  round trip *more* correct, never less.
- Line numbers below are taken from the tree as read for this plan (no B36
  code present). If B36 has landed by the time this plan is executed, re-locate
  the anchors below with `grep -n` for the quoted snippets rather than trusting
  the raw line numbers, since B36's insertions will have shifted them.

---

## Design decisions

**Malformed-row handling.** The old `parseCSVLine` had no way to detect a
malformed row at all — `len(parts) < 2` was the only check, so a row with
*extra* fields (e.g. a stray comma) silently kept only the first two and threw
the rest away with no error. `encoding/csv.Reader.FieldsPerRecord`, set from
the header row (Go's zero-value default: `0` means "auto-detect from the
first record read"), makes every subsequent row's field count enforced against
that header. A row with the wrong number of fields now produces a
`*csv.ParseError` for that `Read()` call, which is caught, turned into an
entry in `ImportResult.Errors`, and the row is skipped — **not** added to
`secretsToImport`, so it counts toward neither `TotalCount` nor
`SkippedCount`, matching how a header-parse failure is already reported
independently. The rest of the file continues to be read normally; one bad
row does not abort the import. This is strictly better than before: previously
a bad row was either miscounted as a 2-field row (silently dropping any extra
fields) or, if it had fewer than 2 fields, reported with a generic message —
now every shape of malformed row is caught by the same mechanism and reported.

**Tags column.** The old code joined tags with a bare comma and wrapped the
result in manual quotes: `fmt.Sprintf(`"%s"`, strings.Join(secret.Tags, ","))`.
On import it reversed this with `strings.Split(parts[2], ",")`. Both steps are
lossy: a tag that itself contains a comma is indistinguishable from two
tags split at that comma. The fix packs the tag list into its column using
`encoding/csv` recursively: `csvEncodeTags` writes `secret.Tags` through a
*second*, throwaway `csv.Writer` into a string (trimming the trailing
newline `Write` always appends), and `csvDecodeTags` reads it back through a
second `csv.Reader`. This reuses the same quoting/escaping logic the outer
writer/reader already use, so a tag containing a comma, a quote, or (in
principle) a newline is quoted by the inner writer, and the resulting string
— which may now itself contain quote characters — is then quoted and escaped
correctly by the *outer* writer when it writes the tags column as one field.
Reading reverses both layers. For the common case (no tag contains a comma or
quote), the inner writer produces exactly the same bytes the old bare
`strings.Join` did, which is why the backward-compatibility case in Task 5
below still parses.

**Backward compatibility — stated plainly.** A CSV file written by the *old*
buggy code can still be read by the new `encoding/csv`-based reader **for the
common case**: a value, name, or tag with no embedded `"`, `,`, or newline.
This holds because the old writer's hand-rolled quoting, while unable to
*escape* a special character, produced syntactically valid strict CSV whenever
none of the fields actually contained one — every field was always wrapped in
`"..."` with no special characters inside, which is valid CSV regardless of
whether the quoting was strictly necessary, and the header/data field counts
already agree. This is verified directly in Task 5 by feeding the reader a
byte-for-byte reproduction of the old writer's output for a name, value and
two tags with no special characters, and asserting it parses to the exact
original values.

For an old file whose value or tag **did** already contain a `"` or a
newline, the data is already corrupted at the moment it was written — the old
writer produced genuinely ambiguous CSV (an unescaped quote inside a quoted
field, or a record that ends mid-value at an embedded newline) — and no reader,
old or new, can recover the original value from it. What changes is the
failure mode: the old hand-rolled parser silently misread such a row (wrong
field boundaries, no error); the new reader detects the malformed syntax and
reports the row as an error instead of guessing. This is demonstrated, not
assumed, in Task 5's second test. **Nothing in this plan re-processes or
repairs CSV exports written before this fix** — that is out of scope, per the
Global Constraint to fix only the filed defect.

---

### Task 1: `ExportSecrets`'s CSV branch uses `encoding/csv.Writer`

**Files:**
- Modify: `internal/services/secrets/secret_service.go`
  - imports, lines 3–18 (add `"bytes"`, `"encoding/csv"`)
  - `ExportSecrets`, CSV branch, lines 649–668 (inside the `if req.Format ==
    "json" {...} else {...}` at lines 625–668)
  - new helpers `csvEncodeTags`/`csvDecodeTags`, added just above
    `parseCSVLine` (line 862; `csvDecodeTags` is unused until Task 2 wires it
    into `ImportSecrets` — Go will not complain, since both are called from
    Task 1's writer path or Task 2's reader path, but `csvDecodeTags` has no
    caller until Task 2. To keep this task's `go vet`/build green on its own,
    Task 1 adds `csvEncodeTags` only; `csvDecodeTags` is added in Task 2
    alongside its first caller.)
- Modify: `internal/services/secrets/secret_service_test.go` (append)

**Interfaces:**
- Consumes: `encoding/csv.Writer`, `bytes.Buffer`.
- Produces:
  ```go
  // csvEncodeTags packs a secret's tags into a single CSV field using
  // encoding/csv itself, so a tag containing a comma or a quote survives
  // being embedded in the outer record.
  func csvEncodeTags(tags []string) (string, error)
  ```

- [ ] **Step 1: Write the failing test**

Append to `internal/services/secrets/secret_service_test.go`, after the last
function (`TestUpdateSecret_VaultScope_NonOwnerVaultMember_CreateVersionUsesSecretOwner`,
ending at line 631):

```go
func TestExportSecretsCSV_EscapesEmbeddedQuote(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: `d"b`, Value: "enc-v1"}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return(`a"b`, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, userID),
		Format: "csv",
	})
	require.NoError(t, err)

	expected := "name,value\n" + `"d""b","a""b"` + "\n"
	assert.Equal(t, expected, string(data), "an embedded quote must be doubled, not left bare")
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
go test ./internal/services/secrets/ -run TestExportSecretsCSV_EscapesEmbeddedQuote -v
```
Expected: FAIL. The current hand-rolled writer produces
`name,value\n"d"b","a"b"\n` (the embedded `"` is not doubled), so
`assert.Equal` reports a mismatch, not a compile error.

- [ ] **Step 3: Add the `bytes` and `encoding/csv` imports**

In `internal/services/secrets/secret_service.go`, replace the import block
(lines 3–18):

```go
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)
```

- [ ] **Step 4: Add `csvEncodeTags`**

Add this directly above `parseCSVLine` (currently line 862):

```go
// csvEncodeTags packs a secret's tags into a single CSV field using
// encoding/csv itself, so a tag containing a comma or a quote survives
// being embedded in the outer record (B42).
func csvEncodeTags(tags []string) (string, error) {
	if len(tags) == 0 {
		return "", nil
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(tags); err != nil {
		return "", err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
```

- [ ] **Step 5: Replace the CSV export branch**

In `ExportSecrets`, replace the `else` branch (lines 649–668) with:

```go
	} else {
		// Export as CSV via encoding/csv, which quotes and escapes embedded
		// quotes, commas and newlines correctly. Hand-rolled string
		// concatenation could not do this safely (B42).
		var buf bytes.Buffer
		writer := csv.NewWriter(&buf)

		header := []string{"name", "value"}
		if req.IncludeTags {
			header = append(header, "tags")
		}
		if err := writer.Write(header); err != nil {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to write CSV header", err)
			return nil, fmt.Errorf("failed to write CSV header: %w", err)
		}

		for _, secret := range secretsList {
			row := []string{secret.Name, secret.Value}
			if req.IncludeTags {
				tagsField, tagErr := csvEncodeTags(secret.Tags)
				if tagErr != nil {
					s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to encode tags", tagErr)
					return nil, fmt.Errorf("failed to encode tags for %q: %w", secret.Name, tagErr)
				}
				row = append(row, tagsField)
			}
			if err := writer.Write(row); err != nil {
				s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to write CSV row", err)
				return nil, fmt.Errorf("failed to write CSV row for %q: %w", secret.Name, err)
			}
		}

		writer.Flush()
		if err := writer.Error(); err != nil {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to flush CSV writer", err)
			return nil, fmt.Errorf("failed to flush CSV writer: %w", err)
		}
		data = buf.Bytes()
	}
```

- [ ] **Step 6: Run the test to verify it passes**

Run:
```bash
go test ./internal/services/secrets/ -run TestExportSecretsCSV_EscapesEmbeddedQuote -v
```
Expected: PASS.

- [ ] **Step 7: Update the pre-existing exact-format assertion**

`TestSecretServiceExportAndImport` in `coverage_boost_test.go` (function
starts line 671) asserts the *old* always-quote-every-field output at line
720:

```go
	assert.Contains(t, string(csvData), `"csv-db","csv-plain","csv,prod"`)
```

`encoding/csv` only quotes a field when it actually needs it — `csv-db` and
`csv-plain` contain no comma/quote/newline, so the new writer leaves them
unquoted; only the tags field (`csv,prod`, containing a comma) is quoted.
Replace that line with:

```go
	assert.Contains(t, string(csvData), `csv-db,csv-plain,"csv,prod"`)
```

Run: `go test ./internal/services/secrets/ -run TestSecretServiceExportAndImport -v`
Expected: still FAILS at this point — the CSV *import* half of the same test
function still uses the old parser and old input shape; that is fixed in
Task 2. Confirm the failure is now only in the import portion (the export
assertion above passes) before moving on.

- [ ] **Step 8: Run gofmt and vet on the package**

Run: `gofmt -l internal/services/secrets && go vet ./internal/services/secrets/`
Expected: `gofmt` silent. `go vet` clean (ignore the still-red
`TestSecretServiceExportAndImport` import half; it is addressed in Task 2).

- [ ] **Step 9: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_service_test.go internal/services/secrets/coverage_boost_test.go
git commit -m "fix(secrets): write CSV exports with encoding/csv (B42)

ExportSecrets's CSV branch built rows with fmt.Sprintf and no escaping,
so an embedded quote or comma corrupted the row. encoding/csv.Writer
quotes and escapes correctly; tags are packed into their column with a
second, nested csv.Writer so a tag containing a comma survives too."
```

---

### Task 2: `ImportSecrets`'s CSV branch uses `encoding/csv.Reader`; delete `parseCSVLine`

**Files:**
- Modify: `internal/services/secrets/secret_service.go`
  - imports, add `"io"`
  - `ImportSecrets`, CSV branch, lines 723–747 (inside the `if req.Format ==
    "json" {...} else {...}` at lines 717–747)
  - add `csvDecodeTags` next to `csvEncodeTags` (added in Task 1)
  - delete `parseCSVLine`, lines 862–886 (now dead — its only caller was the
    branch just replaced)
- Modify: `internal/services/secrets/coverage_boost_test.go` (fix the CSV
  import input line so the pre-existing test still exercises the "missing
  value" skip path it was written for, under the new, stricter field-count
  check)
- Modify: `internal/services/secrets/secret_service_test.go` (append)

**Interfaces:**
- Consumes: `encoding/csv.Reader`.
- Produces:
  ```go
  // csvDecodeTags reverses csvEncodeTags. An empty field means no tags.
  func csvDecodeTags(field string) ([]string, error)
  ```

- [ ] **Step 1: Write the failing test**

Append to `internal/services/secrets/secret_service_test.go`:

```go
func TestImportSecretsCSV_UnescapesDoubledQuote(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", `a"b`).Return("enc-imported", nil)
	var created *model.Secret
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	data := []byte("name,value\n" + `"d""b","a""b"` + "\n")

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   data,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	require.NotNil(t, created)
	assert.Equal(t, `d"b`, created.Name)
	assert.Equal(t, "enc-imported", created.Value)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
go test ./internal/services/secrets/ -run TestImportSecretsCSV_UnescapesDoubledQuote -v
```
Expected: FAIL. The current `parseCSVLine` toggles `inQuotes` on every `"`
independently, so it does not collapse `""` to `"`; `created.Name` comes out
as `d""b` (or the row is mis-split), not `d"b`.

- [ ] **Step 3: Add the `io` import and `csvDecodeTags`**

Add `"io"` to the import block (alphabetically after `"encoding/json"`, before
`"errors"`):

```go
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)
```

Add `csvDecodeTags` directly below `csvEncodeTags` (added in Task 1):

```go
// csvDecodeTags reverses csvEncodeTags. An empty field means no tags (B42).
func csvDecodeTags(field string) ([]string, error) {
	if field == "" {
		return nil, nil
	}
	r := csv.NewReader(strings.NewReader(field))
	tags, err := r.Read()
	if err != nil {
		return nil, err
	}
	return tags, nil
}
```

- [ ] **Step 4: Replace the CSV import branch**

In `ImportSecrets`, replace the `else` branch (lines 723–747) with:

```go
	} else {
		// Parse CSV via encoding/csv, which handles doubled-quote escaping
		// and embedded newlines inside a quoted field correctly — the
		// hand-rolled parseCSVLine could not (B42).
		reader := csv.NewReader(strings.NewReader(string(req.Data)))
		reader.FieldsPerRecord = 0 // Locked to the header row's own column count.

		header, err := reader.Read()
		if err != nil && err != io.EOF {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "import_secrets", "failed", "Failed to parse CSV header", err)
			return nil, fmt.Errorf("failed to parse CSV: %w", err)
		}
		hasTags := len(header) > 2

		lineNum := 1
		for {
			record, readErr := reader.Read()
			if readErr == io.EOF {
				break
			}
			lineNum++
			if readErr != nil {
				// A row with the wrong number of fields, or an unescaped
				// quote, is reported here instead of silently mis-split —
				// the defect this replaces (B42).
				result.Errors = append(result.Errors, fmt.Sprintf("Line %d: invalid CSV: %v", lineNum, readErr))
				continue
			}
			if len(record) < 2 {
				result.Errors = append(result.Errors, fmt.Sprintf("Line %d: invalid format", lineNum))
				continue
			}

			secret := importSecret{
				Name:  record[0],
				Value: record[1],
			}
			if hasTags && len(record) > 2 && record[2] != "" {
				tags, tagErr := csvDecodeTags(record[2])
				if tagErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Line %d: invalid tags: %v", lineNum, tagErr))
					continue
				}
				secret.Tags = tags
			}
			secretsToImport = append(secretsToImport, secret)
		}
	}
```

- [ ] **Step 5: Delete `parseCSVLine`**

Delete lines 862–886 (the `// parseCSVLine parses a CSV line handling quoted
values.` comment and the function body) from `internal/services/secrets/secret_service.go`.
Confirm nothing else calls it:

```bash
grep -rn "parseCSVLine" internal/ cmd/ api/ model/
```
Expected: no output.

- [ ] **Step 6: Run the test to verify it passes**

Run:
```bash
go test ./internal/services/secrets/ -run TestImportSecretsCSV_UnescapesDoubledQuote -v
```
Expected: PASS.

- [ ] **Step 7: Fix the pre-existing `TestSecretServiceExportAndImport`**

The stricter `FieldsPerRecord` check (from the 3-column header
`name,value,tags`) now rejects the test's existing `"missing,\n"` row before
it ever reaches `secretsToImport` — it has 2 fields where the header declares
3, so it is a malformed row, not a well-formed row with an empty value. That
changes the test's counts (`TotalCount` would drop from 2 to 1). Restore the
row to 3 fields, still with an empty value, so it keeps exercising the
"missing name or value" skip path this test was written for.

In `internal/services/secrets/coverage_boost_test.go`, in
`TestSecretServiceExportAndImport` (line 733), change:

```go
		Data:   []byte("name,value,tags\napi,one,\"prod,api\"\nmissing,\n"),
```
to:
```go
		Data:   []byte("name,value,tags\napi,one,\"prod,api\"\nmissing,,\n"),
```

The three count assertions immediately below (lines 736–738,
`result.ImportedCount == 1`, `result.SkippedCount == 1`,
`result.TotalCount == 2`) are unchanged — with the third field present (even
empty), the row now has 3 fields, matches the header, parses into
`secretsToImport` with an empty `Value`, and is still skipped later by the
"Secret missing name or value" check in the create loop, exactly as before.

- [ ] **Step 8: Run the whole test, verify it passes**

Run: `go test ./internal/services/secrets/ -run TestSecretServiceExportAndImport -v`
Expected: PASS.

- [ ] **Step 9: Run the whole package**

Run: `go test ./internal/services/secrets/ && gofmt -l internal/services/secrets && go vet ./internal/services/secrets/`
Expected: PASS, `gofmt` silent, `go vet` clean.

- [ ] **Step 10: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_service_test.go internal/services/secrets/coverage_boost_test.go
git commit -m "fix(secrets): parse CSV imports with encoding/csv (B42)

parseCSVLine toggled inQuotes on every quote with no doubled-quote
handling and operated on input already split by line, so it could
neither unescape a doubled quote nor see a newline embedded in a
quoted field. encoding/csv.Reader handles both; FieldsPerRecord,
locked to the header's column count, also gives real malformed-row
detection the old parser never had. parseCSVLine is deleted."
```

---

### Task 3: Headline round-trip test — quote, comma and newline together, plus a comma-containing tag

**Files:**
- Modify: `internal/services/secrets/secret_service_test.go` (append)

**Interfaces:** none new — exercises `ExportSecrets`/`ImportSecrets` end to
end, as B36's `TestExportSecrets_SealedRoundTripsThroughImport` does for the
encryption layer.

- [ ] **Step 1: Write the test**

This is the scenario the bug report calls out by name: a value containing a
double quote, a comma, *and* a newline, plus a tag containing a comma. Append
to `internal/services/secrets/secret_service_test.go`:

```go
func TestExportImportCSV_RoundTripsQuoteCommaNewlineValueAndCommaTag(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	// Contains a double quote, a comma, and a newline in one value — the
	// exact combination the pre-fix writer could not represent and the
	// pre-fix reader could not parse.
	value := "she said \"hi, there\"\nbye"
	tags := []string{"prod,west"}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1", Tags: tags}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return(value, nil)
	tag.On("GetTags", ctx, stored[0].ID).Return(tags, nil)

	svc := newService(repo, crypto, ver, tag, t)
	csvData, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:       model.NewVaultScope(vaultID, userID),
		Format:      "csv",
		IncludeTags: true,
	})
	require.NoError(t, err)

	importRepo := &testutils.MockSecretRepository{}
	importCrypto := &testutils.MockCryptographyService{}
	importCrypto.On("EncryptSecret", value).Return("enc-imported", nil)

	var created *model.Secret
	importRepo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	importSvc := newService(importRepo, importCrypto, &testutils.MockVersioningService{}, &testutils.MockTagService{}, t)
	result, err := importSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   csvData,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)

	require.NotNil(t, created, "import did not create a secret")
	assert.Equal(t, "db-password", created.Name)
	assert.Equal(t, "enc-imported", created.Value, "EncryptSecret must have been called with the exact original value")
	assert.Equal(t, tags, created.Tags, "the comma-containing tag must survive the round trip intact")
}
```

- [ ] **Step 2: Run the test to verify it fails against the pre-fix code**

This step documents the bug for the record; by the time Task 1 and Task 2 are
complete, running this test alone will already pass. To see the historical
failure, run it against a checkout before this plan's commits:
```bash
git stash && go test ./internal/services/secrets/ -run TestExportImportCSV_RoundTripsQuoteCommaNewlineValueAndCommaTag -v ; git stash pop
```
Expected on the pre-fix checkout: FAIL — the exported CSV corrupts the record
boundary at the embedded newline, so `ImportSecrets` either errors out or
creates a secret with a truncated `Name`/`Value` that does not match `value`.

- [ ] **Step 3: Run the test against the current (post Task 1–2) code**

Run:
```bash
go test ./internal/services/secrets/ -run TestExportImportCSV_RoundTripsQuoteCommaNewlineValueAndCommaTag -v
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/services/secrets/secret_service_test.go
git commit -m "test(secrets): pin the B42 headline CSV round trip

A value containing a quote, a comma and a newline together, plus a
tag containing a comma, now round-trips through export then import
byte-for-byte. This is the scenario named in .claude/known-bugs.md
B42's test requirement."
```

---

### Task 4: Malformed-row detection is real, not silent

**Files:**
- Modify: `internal/services/secrets/secret_service_test.go` (append)

**Interfaces:** none new.

- [ ] **Step 1: Write the test**

This demonstrates the concrete improvement named in the design doc: the old
parser silently dropped extra fields with no error at all; the new reader
reports the row. Append:

```go
func TestImportSecretsCSV_FieldCountMismatch_IsReportedNotSilentlyDropped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	svc := newService(repo, crypto, ver, tag, t)
	// The header declares 2 columns; this row has 3. The pre-fix parser
	// (parts := parseCSVLine(line)) kept only parts[0]/parts[1] and threw
	// "extra" away with no error at all — a silent data loss on read, not
	// just on write. encoding/csv's FieldsPerRecord check must catch this.
	data := []byte("name,value\nn1,v1,extra\n")

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   data,
		Format: "csv",
	})
	require.NoError(t, err, "one malformed row must not fail the whole import")
	require.Len(t, result.Errors, 1, "the malformed row must be reported, not silently mis-parsed")
	assert.Contains(t, result.Errors[0], "Line 2")
	assert.Equal(t, 0, result.TotalCount, "a malformed row must not be counted as a parsed record")
	assert.Equal(t, 0, result.ImportedCount)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the test to verify it fails against the pre-fix code**

```bash
git stash && go test ./internal/services/secrets/ -run TestImportSecretsCSV_FieldCountMismatch_IsReportedNotSilentlyDropped -v ; git stash pop
```
Expected on the pre-fix checkout: FAIL. `parseCSVLine("n1,v1,extra")` returns
`["n1","v1","extra"]` (3 parts, `len(parts) >= 2`), so the old code happily
builds `importSecret{Name: "n1", Value: "v1"}`, silently drops `"extra"`, adds
it to `secretsToImport`, and it gets imported successfully — `result.Errors`
is empty and `result.ImportedCount == 1`, not what the test asserts.

- [ ] **Step 3: Run the test against the current code**

```bash
go test ./internal/services/secrets/ -run TestImportSecretsCSV_FieldCountMismatch_IsReportedNotSilentlyDropped -v
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/services/secrets/secret_service_test.go
git commit -m "test(secrets): pin real malformed-CSV-row detection (B42)

A row with more fields than the header declares used to have its
extra field silently dropped with no error. It is now reported in
ImportResult.Errors and excluded from the import, instead of
partially imported with data loss."
```

---

### Task 5: Backward compatibility — stated and proven, not assumed

**Files:**
- Modify: `internal/services/secrets/secret_service_test.go` (append)

**Interfaces:** none new.

- [ ] **Step 1: Write the common-case backward-compatibility test**

This feeds the reader a byte-for-byte reproduction of what the *old* writer
produced for a name, value and two tags with no special characters, and
asserts it still parses correctly — proving the stated backward-compatibility
claim rather than assuming it. Append:

```go
func TestImportSecretsCSV_ParsesOldPreFixExportForCommonCase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", "legacy-value").Return("enc-legacy", nil)
	var created *model.Secret
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	// Byte-for-byte what the pre-fix hand-rolled writer produced for a
	// secret and tags with no embedded quote, comma or newline — the
	// common case. This fix must still read it correctly: no export ever
	// written before this fix should become unreadable because of it.
	oldFormatData := []byte("name,value,tags\n" + `"legacy","legacy-value","tag1,tag2"` + "\n")

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   oldFormatData,
		Format: "csv",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	require.NotNil(t, created)
	assert.Equal(t, "legacy", created.Name)
	assert.Equal(t, "enc-legacy", created.Value)
	assert.Equal(t, []string{"tag1", "tag2"}, created.Tags)
}
```

- [ ] **Step 2: Run the test to verify it passes**

```bash
go test ./internal/services/secrets/ -run TestImportSecretsCSV_ParsesOldPreFixExportForCommonCase -v
```
Expected: PASS. This must pass against both the pre-fix and post-fix reader —
run it once now to confirm the post-fix reader accepts old-format input.

- [ ] **Step 3: Write the "already-corrupted, not recoverable" test**

This documents, rather than merely asserts in prose, that an old file whose
value already contained a quote is unrecoverable — but is now reported as an
error instead of silently misread. Append:

```go
func TestImportSecretsCSV_OldFormatWithEmbeddedQuote_FailsLoudlyNotSilently(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	svc := newService(repo, crypto, ver, tag, t)
	// Byte-for-byte what the pre-fix writer produced for Name="legacy",
	// Value=`say "hi"`: fmt.Sprintf(`"%s","%s"`, name, value) leaves a
	// bare, unescaped quote inside a quoted field. That file was already
	// corrupted the moment it was written — no reader can recover the
	// original value from it. What changed is that this reader reports
	// the row as malformed instead of silently returning a truncated or
	// wrong value.
	oldCorruptData := []byte("name,value\n" + `"legacy","say "hi""` + "\n")

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   oldCorruptData,
		Format: "csv",
	})
	require.NoError(t, err, "one bad row must not fail the whole import")
	require.Len(t, result.Errors, 1)
	assert.Equal(t, 0, result.ImportedCount)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
go test ./internal/services/secrets/ -run TestImportSecretsCSV_OldFormatWithEmbeddedQuote_FailsLoudlyNotSilently -v
```
Expected: PASS. (For contrast, not required as a step: the pre-fix
`parseCSVLine` on this same input toggles `inQuotes` on every `"` it sees and
returns a value silently split in the wrong place, with no error at all —
exactly the silent-corruption failure mode this fix replaces.)

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/secret_service_test.go
git commit -m "test(secrets): prove CSV backward compatibility, and its limit (B42)

An export written by the pre-fix code still imports correctly when no
field contains a quote, comma or newline — the common case. A
pre-fix export whose value already contained a quote was already
corrupted at write time and cannot be recovered; the new reader now
reports that row as an error instead of silently misreading it."
```

---

### Task 6: Whole-tree verification and bug-status update

**Files:**
- Modify: `.claude/known-bugs.md`, B42 entry (lines 1947–1983)

**Interfaces:** none.

- [ ] **Step 1: Build, vet and format the whole tree**

```bash
go build ./...
gofmt -l internal common cmd api
go vet ./internal/services/secrets/...
```
Expected: all clean, `gofmt` silent.

- [ ] **Step 2: Run the full test suite**

```bash
go test ./...
```
Expected: PASS. Pay particular attention to `./internal/services/secrets/`
(this plan's changes), `./internal/services/retry/` (wraps `SecretService`
and must still compile against the unchanged `ExportSecrets`/`ImportSecrets`
signatures — this plan changes no signature), and `./internal/cache/` (same
reason).

- [ ] **Step 3: Confirm `parseCSVLine` is fully gone**

```bash
grep -rn "parseCSVLine" internal/ cmd/ api/ model/
```
Expected: no output.

- [ ] **Step 4: Manual round-trip against a scratch instance**

Use an isolated config and database so this does not touch `dev-rocketvault.db`
(per `.claude/known-bugs.md`'s own convention and the project memory on
isolated manual test instances):

```bash
cd /tmp && rm -f rv-b42.db rv-b42.yaml
cp "$OLDPWD/.rocketvault.yaml.example" rv-b42.yaml
# Fill both GENERATE_WITH placeholders in rv-b42.yaml with: openssl rand -base64 32
# Point its database path at /tmp/rv-b42.db, then from the repo root:
go run . --config /tmp/rv-b42.yaml users admin --admin-username admin --admin-password '<pw>' --bootstrap-token '<token from rv-b42.yaml>'
go run . --config /tmp/rv-b42.yaml users login --username admin
go run . --config /tmp/rv-b42.yaml secrets create --name tricky --value $'quote"comma,newline\nend' --tags 'tag,withcomma'
go run . --config /tmp/rv-b42.yaml secrets export --format csv --file /tmp/rv-b42.csv --encrypt=false
go run . --config /tmp/rv-b42.yaml secrets import --format csv --file /tmp/rv-b42.csv --encrypted=false
go run . --config /tmp/rv-b42.yaml secrets list
```
Expected: both `secrets create`-sourced and the freshly imported secret list
with the original value intact (no error, no truncation). Clean up:
`rm -f /tmp/rv-b42.db /tmp/rv-b42.yaml /tmp/rv-b42.csv`.

(`--encrypt=false`/`--encrypted=false` above assume B36 has landed by the time
this step runs, since `--encrypt` currently exists but is unread. If B36 has
not landed yet, drop both flags — the current `secrets export`/`secrets
import` write and read plaintext CSV regardless.)

- [ ] **Step 5: Mark B42 fixed in `.claude/known-bugs.md`**

In `.claude/known-bugs.md`, change the B42 entry's status line (currently
line 1949):

```markdown
**Status**: Open, found 2026-08-21
```
to:
```markdown
**Status**: Fixed in commit `<hash>` (2026-08-21)
```
Fill `<hash>` from `git log --oneline -n 20 | grep 'parse CSV imports with encoding/csv'`
(Task 2's commit — the last of the two production-code commits).

Then, directly below the existing **Fix sketch** paragraph (which stays,
since it correctly describes what was done), add:

```markdown
**What was fixed**: `ExportSecrets`'s CSV branch now writes with
`encoding/csv.Writer` and `ImportSecrets`'s CSV branch reads with
`encoding/csv.Reader`, with `FieldsPerRecord` locked to the header row's own
column count so a malformed row is reported in `ImportResult.Errors` instead
of silently mis-parsed. Tags are packed into their column through a second,
nested `csv.Writer`/`csv.Reader` pair (`csvEncodeTags`/`csvDecodeTags`) so a
tag containing a comma round-trips too. `parseCSVLine` is deleted.

**Backward compatibility**: a CSV export written before this fix still
imports correctly when no field contains a quote, comma, or newline — the
common case, verified by
`TestImportSecretsCSV_ParsesOldPreFixExportForCommonCase`. An export whose
value already contained a quote was already corrupted at write time; that
row is now reported as a parse error on import instead of being silently
misread (`TestImportSecretsCSV_OldFormatWithEmbeddedQuote_FailsLoudlyNotSilently`).
Nothing repairs an already-corrupted historical export — there is no data to
recover from a row that was mis-written before this fix existed.
```

- [ ] **Step 6: Commit**

```bash
git add .claude/known-bugs.md
git commit -m "docs(known-bugs): mark B42 fixed

CSV export/import now round-trips a quoted, comma-containing,
multi-line value and a comma-containing tag. Backward compatible
for exports with no embedded quote/comma/newline; already-corrupted
pre-fix exports now fail loudly on import instead of silently
mis-parsing."
```

---

## Definition of Done

- A secret value containing a double quote, a comma, and a newline together
  round-trips through `ExportSecrets`(csv) → `ImportSecrets`(csv) with exact
  equality — pinned by
  `TestExportImportCSV_RoundTripsQuoteCommaNewlineValueAndCommaTag`.
- A tag containing a comma round-trips through the same path intact.
- A CSV row with the wrong number of fields is reported in
  `ImportResult.Errors` and excluded from the import — never silently
  mis-parsed or partially imported with data loss — pinned by
  `TestImportSecretsCSV_FieldCountMismatch_IsReportedNotSilentlyDropped`.
- A CSV export written by the pre-fix code still imports correctly for the
  common case (no embedded quote/comma/newline) — pinned by
  `TestImportSecretsCSV_ParsesOldPreFixExportForCommonCase`.
- A pre-fix export that already contained an embedded quote fails loudly on
  import (a reported error) rather than silently misreading — pinned by
  `TestImportSecretsCSV_OldFormatWithEmbeddedQuote_FailsLoudlyNotSilently`.
- `parseCSVLine` is deleted; `grep -rn "parseCSVLine"` across the tree is
  empty.
- `go build ./...`, `go test ./...`, `gofmt -l`, `go vet` all clean.
- No new module dependency in `go.mod` (`encoding/csv` is standard library).
- `.claude/known-bugs.md` § B42 reads Fixed with the commit hash.

## Out of scope, deliberately

- **Re-processing or repairing CSV exports already written before this fix.**
  There is no tooling for it and none is planned. A value already corrupted
  by the old writer (containing an unescaped quote or a truncated embedded
  newline) cannot be recovered from that file; only exports written after
  this fix are affected by it.
- **JSON export/import.** `ExportSecrets`'s JSON branch already uses
  `encoding/json`, which does not have this defect; it is untouched.
- **Any CLI or HTTP-layer change.** B42's filed root cause and fix sketch are
  entirely inside `internal/services/secrets/secret_service.go`; no flag, help
  text, or API handler needs to change for this fix.
- **B36's passphrase-sealing work.** Independent, as established above; not
  touched or blocked by this plan either direction.
