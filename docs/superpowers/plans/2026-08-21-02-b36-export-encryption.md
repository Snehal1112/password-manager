# B36 — Encrypted Secret Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `secrets export --encrypt` (default `true`) actually encrypt, fail loudly when it cannot, and make `secrets import` read the result back — so no invocation ever writes plaintext while claiming otherwise.

**Architecture:** `ExportSecretsRequest` gains `Encrypt` and `Passphrase`; `ExportSecrets` formats exactly as it does today and then seals the marshaled bytes with `common.SealExport`, refusing to return anything when encryption was asked for without a passphrase. The CLI resolves the passphrase through `common.ResolvePassphrase` (file → env → prompt) *after* the authorization check and *before* any file is written, so a missing passphrase aborts the command with nothing on disk. Import auto-detects a sealed file with `common.IsSealedExport`, opens it in the CLI (the only layer that may prompt), and hands plaintext bytes to the service, which refuses a sealed payload outright.

**Tech Stack:** Go 1.24.2, Cobra, `common` (argon2id + AES-256-GCM envelope from plan 00), testify.

**Spec:** `docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`

## Global Constraints

- Go 1.24.2. Do not raise the version floor.
- **No new module dependencies.** `golang.org/x/crypto` v0.48.0 and `golang.org/x/term` are already in `go.mod`/`go.sum` and were verified to compile and run offline on 2026-08-21.
- Comments are short, full sentences ending in a punctuation mark.
- Never log, print, or include a passphrase or plaintext secret in an error message.
- Argon2id parameters are fixed by plan 00: `time=1`, `memory=65536`, `threads=4`, `keyLen=32`, `saltLen=16`. Do not restate or re-derive them here.
- Every fix starts with a failing test.
- Any flag added must be registered on its command, or `cmd/help_examples_test.go` fails the build.
- Help text follows `.claude/cli-help-conventions.md`: `Long` wrapped at 78 columns, two-space-indented `Example` blocks, no credential flags in leaf examples, no invented flags.
- Never fall through to writing plaintext when encryption was requested. Failing the command is always the correct outcome.
- **Depends on plan `docs/superpowers/plans/2026-08-21-00-shared-foundations.md` being complete.** `common.SealExport`, `common.OpenExport`, `common.IsSealedExport`, `common.ResolvePassphrase`, `common.ErrWrongPassphrase`, `common.ErrUnsupportedExportVersion` and `common.ErrNoPassphraseAvailable` must exist and pass their tests before Task 1 starts.

## Interfaces consumed from plan 00 (verbatim, do not redefine)

```go
func SealExport(plaintext []byte, passphrase string) ([]byte, error)
func OpenExport(data []byte, passphrase string) ([]byte, error)
func IsSealedExport(data []byte) bool

var ErrWrongPassphrase error
var ErrUnsupportedExportVersion error

type PassphraseSource struct {
    File    string
    EnvVar  string
    Prompt  string
    Confirm bool
}

func ResolvePassphrase(src PassphraseSource) (string, error)

var ErrNoPassphraseAvailable error
```

## Design notes settled before implementation

Read these before Task 1; each one is a decision the spec left implicit and the
code below depends on.

1. **Two fields, not one.** The spec text says `ExportSecretsRequest` gains
   `Passphrase string`. That alone cannot express "encryption was requested and
   the passphrase is empty", which is exactly the state that must be an error.
   The request therefore gains `Encrypt bool` **and** `Passphrase string`. The
   service seals when either is set and errors when `Encrypt` is set with an
   empty passphrase, so the invariant is enforced in the service and not only in
   the CLI.
2. **Sealing happens after formatting, so CSV is sealed too.** The spec does not
   discuss CSV. `ExportSecrets` builds either a JSON document or a CSV string and
   then seals whichever it built. A sealed export is therefore **always a JSON
   envelope on disk, whatever `--format` says** — the format governs the payload
   *inside* the envelope. Import already takes `--format` for the payload, so a
   sealed CSV export is imported with `--format csv`; the envelope is detected
   independently of that flag. This is documented in both commands' help text and
   covered by a test.
3. **Decryption lives in the CLI, not the service.** Only the CLI can prompt for
   a passphrase. `ImportSecrets` therefore never decrypts; it detects a sealed
   payload and refuses it with a clear error, so an API caller gets a useful
   message rather than "failed to parse JSON".
4. **The real export flag is `--file`/`-o`, not `--output`.** The spec and
   `.claude/known-bugs.md` both write `secrets export --output f.json`; that flag
   does not exist on the command (`--output` is a rootCmd persistent flag for
   table/json/yaml rendering). Every example and release-note line in this plan
   uses `--file`.
5. **Order of operations in `export`'s `RunE`:** authorization check first, then
   passphrase resolution, then the service call, then the write. An unauthorized
   caller must never be prompted for a passphrase, and a caller with no
   passphrase must never reach `os.WriteFile`.

---

### Task 1: Seal the export in the service layer

**Files:**
- Modify: `internal/services/secrets/secret_service.go`
  - imports, l.3-18 (add `"rocketvault/common"`)
  - new sentinel next to `ErrSecretLifecycleDenied`, l.24-26
  - `ExportSecretsRequest`, l.89-95
  - `ExportSecrets`, l.604-679 (seal just before the audit log at l.669)
- Modify: `internal/services/secrets/secret_service_test.go` (append; test package is `secrets_test`)

**Interfaces:**
- Consumes: `common.SealExport(plaintext []byte, passphrase string) ([]byte, error)`, `common.IsSealedExport(data []byte) bool`, `common.OpenExport(data []byte, passphrase string) ([]byte, error)`.
- Produces:
  ```go
  type ExportSecretsRequest struct {
      Scope       model.Scope
      Format      string
      FilterTags  []string
      IncludeTags bool
      Encrypt     bool   // NEW
      Passphrase  string // NEW
  }

  var ErrExportPassphraseRequired = errors.New("export encryption requested but no passphrase was supplied")
  ```

- [ ] **Step 1: Write the failing tests**

Append to `internal/services/secrets/secret_service_test.go`, directly after
`TestExportSecrets_VaultScoped_UsesListSecretsInVault` (which ends around l.556).
Add `"encoding/json"`, `"strings"` and `"rocketvault/common"` to that file's
import block.

```go
func TestExportSecrets_WithPassphrase_SealsAndLeaksNoPlaintext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1"}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("hunter2", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{"production"}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:       model.NewVaultScope(vaultID, userID),
		Format:      "json",
		IncludeTags: true,
		Encrypt:     true,
		Passphrase:  "correct horse battery staple",
	})
	require.NoError(t, err)

	// The sealed file must not parse as the plain export document.
	var plain []struct {
		Name  string   `json:"name"`
		Value string   `json:"value"`
		Tags  []string `json:"tags"`
	}
	require.Error(t, json.Unmarshal(data, &plain), "sealed export still parses as the plain export JSON")

	assert.NotContains(t, string(data), "db-password", "sealed export contains a secret name")
	assert.NotContains(t, string(data), "hunter2", "sealed export contains a secret value")
	assert.NotContains(t, string(data), "production", "sealed export contains a tag")
	assert.True(t, common.IsSealedExport(data), "sealed export is not a recognisable envelope")
}

func TestExportSecrets_EncryptWithoutPassphrase_FailsAndReturnsNoData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1"}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil).Maybe()
	crypto.On("DecryptSecret", "enc-v1").Return("hunter2", nil).Maybe()
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil).Maybe()

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:   model.NewVaultScope(vaultID, userID),
		Format:  "json",
		Encrypt: true,
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrExportPassphraseRequired), "got %v", err)
	assert.Nil(t, data, "a failed encrypted export must return no bytes at all")
}

func TestExportSecrets_CSVWithPassphrase_IsSealedEnvelope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1"}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("hunter2", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:      model.NewVaultScope(vaultID, userID),
		Format:     "csv",
		Encrypt:    true,
		Passphrase: "pw",
	})
	require.NoError(t, err)

	// A sealed CSV export is a JSON envelope on disk; the CSV lives inside it.
	assert.True(t, common.IsSealedExport(data))
	assert.False(t, strings.Contains(string(data), "name,value"), "CSV header leaked outside the envelope")
	assert.NotContains(t, string(data), "hunter2")

	opened, err := common.OpenExport(data, "pw")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(opened), "name,value"), "payload inside the envelope is not the CSV")
}

func TestExportSecrets_SealedRoundTripsThroughImport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "db-password", Value: "enc-v1"}}
	repo.On("List", ctx, model.NewVaultScope(vaultID, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("hunter2", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	sealed, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		Scope:      model.NewVaultScope(vaultID, userID),
		Format:     "json",
		Encrypt:    true,
		Passphrase: "pw",
	})
	require.NoError(t, err)

	opened, err := common.OpenExport(sealed, "pw")
	require.NoError(t, err)

	// Import the opened payload into a second service and assert the value
	// survived the round trip intact.
	importRepo := &testutils.MockSecretRepository{}
	importCrypto := &testutils.MockCryptographyService{}
	importCrypto.On("EncryptSecret", "hunter2").Return("enc-imported", nil)

	var created *model.Secret
	importRepo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Secret) }).
		Return(nil)

	importSvc := newService(importRepo, importCrypto, &testutils.MockVersioningService{}, &testutils.MockTagService{}, t)
	result, err := importSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, userID),
		Data:   opened,
		Format: "json",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, result.ImportedCount)
	require.NotNil(t, created, "import did not create a secret")
	assert.Equal(t, "db-password", created.Name)
	assert.Equal(t, "enc-imported", created.Value)
	assert.Equal(t, vaultID, created.VaultID)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
go test ./internal/services/secrets/ -run 'TestExportSecrets_WithPassphrase|TestExportSecrets_EncryptWithout|TestExportSecrets_CSVWithPassphrase|TestExportSecrets_SealedRoundTrips' -v
```
Expected: FAIL to compile — `unknown field Encrypt in struct literal of type secrets.ExportSecretsRequest` and `undefined: secrets.ErrExportPassphraseRequired`.

- [ ] **Step 3: Add the sentinel error and the request fields**

In `internal/services/secrets/secret_service.go`, add `"rocketvault/common"` to
the import block (after `"rocketvault/internal/repositories"`), then add the
sentinel below `ErrSecretLifecycleDenied` (l.26):

```go
// ErrExportPassphraseRequired is returned when an export asks for encryption
// without supplying a passphrase. The export fails rather than quietly writing
// plaintext under a flag that promises encryption.
var ErrExportPassphraseRequired = errors.New("export encryption requested but no passphrase was supplied")
```

Replace `ExportSecretsRequest` (l.89-95) with:

```go
// ExportSecretsRequest represents a request to export secrets.
type ExportSecretsRequest struct {
	Scope       model.Scope // Authorization scope for the listing and the audit actor.
	Format      string      // "json" or "csv"
	FilterTags  []string    // Optional tag filter
	IncludeTags bool        // Include tags in export
	// Encrypt asks for a passphrase-sealed export. Passphrase must then be
	// non-empty; the export fails rather than falling back to plaintext.
	Encrypt bool
	// Passphrase seals the formatted export via common.SealExport. It is never
	// logged and never appears in an error message.
	Passphrase string
}
```

- [ ] **Step 4: Seal the formatted bytes**

In `ExportSecrets`, insert this block after the `if req.Format == "json" { ... }
else { ... }` formatting branch closes and before the
`s.logger.LogAuditInfo(...)` call at l.669:

```go
	// Seal after formatting, so a CSV export is sealed too. The file on disk is
	// then the JSON envelope and the chosen format describes its payload.
	if req.Encrypt || req.Passphrase != "" {
		if req.Passphrase == "" {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed",
				"Encryption requested without a passphrase", nil)
			return nil, ErrExportPassphraseRequired
		}
		sealed, sealErr := common.SealExport(data, req.Passphrase)
		if sealErr != nil {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed",
				"Failed to seal export", sealErr)
			return nil, fmt.Errorf("failed to encrypt export: %w", sealErr)
		}
		data = sealed
	}
```

Then add the encryption state to the closing log call, replacing the existing
`logrus.WithFields` block at l.671-675:

```go
	logrus.WithFields(logrus.Fields{
		"user_id":      req.Scope.ActorID().String(),
		"format":       req.Format,
		"secret_count": len(secretsList),
		"encrypted":    req.Encrypt || req.Passphrase != "",
	}).Info("Secrets exported successfully")
```

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
go test ./internal/services/secrets/ -run 'TestExportSecrets_WithPassphrase|TestExportSecrets_EncryptWithout|TestExportSecrets_CSVWithPassphrase|TestExportSecrets_SealedRoundTrips' -v
```
Expected: PASS, all four tests.

- [ ] **Step 6: Run the whole secrets service package**

Run: `go test ./internal/services/secrets/ && gofmt -l internal/services/secrets && go vet ./internal/services/secrets/`
Expected: pass, `gofmt` silent. The pre-existing
`TestExportSecrets_VaultScoped_UsesListSecretsInVault` must still pass unchanged —
it sets neither new field, so it takes the plaintext path exactly as before.

- [ ] **Step 7: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_service_test.go
git commit -m "feat(secrets): seal exports under a passphrase (B36)

ExportSecretsRequest gains Encrypt and Passphrase. ExportSecrets formats
as before and then seals the bytes with common.SealExport. Asking for
encryption without a passphrase is an error, never a plaintext export."
```

---

### Task 2: `ImportSecrets` refuses a sealed payload

**Files:**
- Modify: `internal/services/secrets/secret_service.go` (new sentinel beside `ErrExportPassphraseRequired`; guard inside `ImportSecrets`, l.692, after the format validation that ends around l.714)
- Modify: `internal/services/secrets/secret_service_test.go` (append)

**Interfaces:**
- Consumes: `common.IsSealedExport(data []byte) bool`, `common.SealExport`.
- Produces:
  ```go
  var ErrImportDataIsSealed = errors.New("import data is an encrypted RocketVault export: decrypt it before importing")
  ```

Rationale: only the CLI can prompt for a passphrase, so the service never
decrypts. Without this guard a sealed file handed to `ImportSecrets` fails with
"failed to parse JSON", which sends the reader after the wrong problem.

- [ ] **Step 1: Write the failing test**

Append to `internal/services/secrets/secret_service_test.go`:

```go
func TestImportSecrets_SealedPayload_IsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	sealed, err := common.SealExport([]byte(`[{"name":"n1","value":"v1"}]`), "pw")
	require.NoError(t, err)

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewVaultScope(vaultID, uuid.New()),
		Data:   sealed,
		Format: "json",
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrImportDataIsSealed), "got %v", err)
	assert.Nil(t, result)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/secrets/ -run TestImportSecrets_SealedPayload -v`
Expected: FAIL — `undefined: secrets.ErrImportDataIsSealed`.

- [ ] **Step 3: Add the sentinel and the guard**

In `internal/services/secrets/secret_service.go`, below
`ErrExportPassphraseRequired`:

```go
// ErrImportDataIsSealed is returned when import data is a passphrase-sealed
// export envelope. The caller must open it first; the service holds no
// passphrase and must never prompt for one.
var ErrImportDataIsSealed = errors.New("import data is an encrypted RocketVault export: decrypt it before importing")
```

In `ImportSecrets`, immediately after the format validation block and before the
`type importSecret struct { ... }` declaration:

```go
	// A sealed export is opened by the caller, which is the only layer that can
	// prompt for a passphrase. Refusing here beats a confusing parse error.
	if common.IsSealedExport(req.Data) {
		s.logger.LogAuditError(req.Scope.ActorID().String(), "import_secrets", "failed",
			"Import data is an encrypted export", nil)
		return nil, ErrImportDataIsSealed
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/services/secrets/ -run TestImportSecrets -v`
Expected: PASS, including the pre-existing
`TestImportSecrets_VaultScoped_ThreadsVaultIDIntoCreatedSecrets`.

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_service_test.go
git commit -m "feat(secrets): refuse a sealed payload in ImportSecrets (B36)

The service never holds a passphrase, so a sealed export reaching it is a
caller error. Returning ErrImportDataIsSealed points at the real problem
instead of failing with a JSON parse error."
```

---

### Task 3: `secrets export` resolves a passphrase and warns on plaintext

**Files:**
- Modify: `cmd/secrets/export.go`
  - imports, l.25-38 (add `"errors"`)
  - package vars, l.40-46 (add `exportPassphraseFile`, add the env-var constant)
  - `Long`, l.51-65 and `Example`, l.66-74
  - `RunE`, l.75-134
  - `InitSecretsExport`, l.138-146 (register `--passphrase-file`)
- Modify: `cmd/secrets/export_test.go` (add the helper and three new tests; add `exportPassphraseFile` resets to the two existing tests)
- Modify: `cmd/secrets/secrets_cmd_test.go` (add `exportPassphraseFile`/`exportEncrypt` resets to `TestExportCmd_NoServiceContainer` l.659 and `TestExportCmd_ServiceError` l.685)

**Interfaces:**
- Consumes: `common.ResolvePassphrase(src common.PassphraseSource) (string, error)`, `common.ErrNoPassphraseAvailable`, `secretServices.ExportSecretsRequest{Encrypt, Passphrase}`.
- Produces:
  ```go
  // exportPassphraseEnvVar names the environment variable both export and
  // import read a passphrase from when no --passphrase-file is given.
  const exportPassphraseEnvVar = "ROCKETVAULT_EXPORT_PASSPHRASE"

  var exportPassphraseFile string // --passphrase-file
  ```

- [ ] **Step 1: Write the failing tests**

Add to `cmd/secrets/export_test.go`. Add `"os"`, `"path/filepath"` and
`"github.com/stretchr/testify/require"` to its import block.

```go
// newExportTestCmd builds a standalone command sharing the real export RunE, so
// the flag set matches what InitSecretsExport registers.
func newExportTestCmd(file string) *cobra.Command {
	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", file, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", exportEncrypt, "")
	cmd.Flags().StringVar(&exportPassphraseFile, "passphrase-file", exportPassphraseFile, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	return cmd
}

func TestExportCommand_EncryptWithNoPassphraseSource_FailsAndWritesNoFile(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService).Maybe()

	// go test runs with stdin detached, so ResolvePassphrase takes its
	// non-terminal branch and returns ErrNoPassphraseAvailable.
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "")

	tmpFile := filepath.Join(t.TempDir(), "export.json")
	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = true
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no passphrase")
	assert.NoFileExists(t, tmpFile, "a failed encrypted export must leave nothing on disk")
	tc.MockSecretService.AssertNotCalled(t, "ExportSecrets", mock.Anything, mock.Anything)
}

func TestExportCommand_PassphraseFileIsPlumbedIntoRequest(t *testing.T) {
	tc := testutils.NewTestContext(t)

	dir := t.TempDir()
	passFile := filepath.Join(dir, "pass.txt")
	require.NoError(t, os.WriteFile(passFile, []byte("s3cret\n"), 0o600))
	tmpFile := filepath.Join(dir, "export.json")

	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return r.Encrypt && r.Passphrase == "s3cret"
	})).Return([]byte(`{"rocketvault_export":1}`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = true
	exportPassphraseFile = passFile
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	assert.FileExists(t, tmpFile)
	tc.MockSecretService.AssertExpectations(t)
}

func TestExportCommand_EnvPassphraseIsPlumbedIntoRequest(t *testing.T) {
	tc := testutils.NewTestContext(t)
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "from-env")

	tmpFile := filepath.Join(t.TempDir(), "export.json")

	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return r.Encrypt && r.Passphrase == "from-env"
	})).Return([]byte(`{"rocketvault_export":1}`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = true
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	tc.MockSecretService.AssertExpectations(t)
}

func TestExportCommand_PlaintextStillWorksAndRequestCarriesNoPassphrase(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tmpFile := filepath.Join(t.TempDir(), "export.json")

	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return !r.Encrypt && r.Passphrase == ""
	})).Return([]byte(`[]`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = false
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	assert.FileExists(t, tmpFile)
	tc.MockSecretService.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/secrets/ -run TestExportCommand -v`
Expected: FAIL to compile — `undefined: exportPassphraseFile`.

- [ ] **Step 3: Add the flag variable, the env-var constant and the registration**

In `cmd/secrets/export.go`, replace the var block at l.40-46:

```go
var (
	exportFormat         string
	exportFile           string
	exportEncrypt        bool
	exportPassphraseFile string
	exportTags           []string
	exportFilterTags     []string
)

// exportPassphraseEnvVar names the environment variable that supplies an export
// passphrase without a terminal. Import reads the same variable.
const exportPassphraseEnvVar = "ROCKETVAULT_EXPORT_PASSPHRASE"
```

In `InitSecretsExport`, after the `--encrypt` registration (l.142):

```go
	secretsExportCmd.Flags().StringVar(&exportPassphraseFile, "passphrase-file", "",
		"Read the export passphrase from the first line of this file")
```

- [ ] **Step 4: Resolve the passphrase in `RunE`**

Add `"errors"` to the import block. In `RunE`, insert this immediately after the
`vaultcli.RequireDataAction` block (l.100-103) and before `allTags` (l.105):

```go
		// Resolve the passphrase after the authorization check and before any
		// write, so an unauthorized caller is never prompted and a caller with
		// no passphrase never reaches os.WriteFile.
		var passphrase string
		if exportEncrypt {
			passphrase, err = common.ResolvePassphrase(common.PassphraseSource{
				File:    exportPassphraseFile,
				EnvVar:  exportPassphraseEnvVar,
				Prompt:  "Export passphrase: ",
				Confirm: true,
			})
			if err != nil {
				if errors.Is(err, common.ErrNoPassphraseAvailable) {
					return fmt.Errorf("export encryption is on but no passphrase is available: "+
						"pass --passphrase-file, set %s, or pass --encrypt=false to write plaintext deliberately",
						exportPassphraseEnvVar)
				}
				return fmt.Errorf("failed to resolve export passphrase: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stderr,
				"Warning: --encrypt=false — %s will hold every exported secret's name, "+
					"plaintext value and tags in the clear.\n", exportFile) //nolint:errcheck
		}
```

- [ ] **Step 5: Pass the new fields to the service and report the encryption state**

Replace the `ExportSecrets` call (l.112-117) with:

```go
		data, err := sc.GetSecretService().ExportSecrets(ctx, secretServices.ExportSecretsRequest{
			Scope:       model.NewVaultScope(vaultID, userID),
			Format:      format,
			FilterTags:  allTags,
			IncludeTags: true,
			Encrypt:     exportEncrypt,
			Passphrase:  passphrase,
		})
```

Replace the success line (l.132) with:

```go
		encryption := "none (plaintext)"
		if exportEncrypt {
			encryption = "passphrase (argon2id + AES-256-GCM)"
		}
		fmt.Printf("Secrets exported successfully\nFormat: %s\nEncryption: %s\nFile: %s\n",
			format, encryption, exportFile)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./cmd/secrets/ -run TestExportC -v`
Expected: PASS, including the pre-existing
`TestExportCommand_CallsServiceExport` and `TestExportCommand_Forbidden`, which
set `exportEncrypt = false` and so take the plaintext path.

- [ ] **Step 7: Reset the new variable in the pre-existing tests**

The package-level flag variables leak between tests in this package. Add
`exportPassphraseFile = ""` next to the existing `exportEncrypt = false` lines
in:
- `cmd/secrets/export_test.go`: `TestExportCommand_CallsServiceExport` (l.52),
  `TestExportCommand_Forbidden` (l.83).
- `cmd/secrets/secrets_cmd_test.go`: `TestExportCmd_NoServiceContainer` (l.659),
  `TestExportCmd_ServiceError` (l.685) — these two never set `exportEncrypt`
  explicitly, so also add `exportEncrypt = false` there; without it a leaked
  `true` from another test turns them into passphrase-resolution failures.

Run: `go test ./cmd/secrets/`
Expected: PASS.

- [ ] **Step 8: Rewrite the help text**

Replace `Long` (l.51-65) and `Example` (l.66-74) in `cmd/secrets/export.go`:

```go
	Long: `Export the target vault's secrets to a JSON or CSV file holding each
secret's name, plaintext value and tags.

The file is encrypted by default. --encrypt (default true) seals it under a
passphrase with argon2id key derivation and AES-256-GCM. The passphrase is
read from --passphrase-file, then the ROCKETVAULT_EXPORT_PASSPHRASE
environment variable, then an interactive prompt asking twice. If none of
those yields a passphrase the command fails and writes no file at all.

A sealed export is always a JSON envelope on disk, whatever --format says;
the format describes the payload inside it, so a sealed CSV export is read
back with "secrets import --format csv".

--encrypt=false writes the export in the clear and prints a warning naming
what is exposed. Use it only when something downstream needs a readable
file, and delete that file promptly.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/getSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default". The export
is vault scoped, so it includes secrets created by other members of that
vault, not only the caller's own.

--tags and --filter-tags are merged into one tag filter. Passing neither
exports every secret in the vault. The file is written with 0600
permissions, and any missing parent directories are created.`,
	Example: `  # Export every secret in the default vault, prompting for a passphrase
  rocketvault secrets export --file secrets.json

  # Export non-interactively, reading the passphrase from a file
  rocketvault secrets export --file secrets.json \
    --passphrase-file /run/secrets/export-pass

  # Export a named vault as CSV, restricted to secrets tagged production
  rocketvault secrets export --format csv --file payments.csv \
    --tags production --vault <vault-name>

  # Write plaintext deliberately, accepting the warning
  rocketvault secrets export --file secrets.json --encrypt=false`,
```

- [ ] **Step 9: Verify the help-text guard**

Run: `go test ./cmd/ -run 'TestExampleFlagsAreRegistered|TestLeafExamplesDoNotShowCredentials|TestExamplesDoNotAdvertiseUnsupportedRemoteFlags' -v`
Expected: PASS. `--passphrase-file` is now registered, so the example using it
resolves.

- [ ] **Step 10: Commit**

```bash
git add cmd/secrets/export.go cmd/secrets/export_test.go cmd/secrets/secrets_cmd_test.go
git commit -m "feat(secrets): make secrets export --encrypt real (B36)

--encrypt keeps its true default and now seals the file under a
passphrase read from --passphrase-file, ROCKETVAULT_EXPORT_PASSPHRASE or
an interactive prompt. With no passphrase available the command fails and
writes nothing. --encrypt=false writes plaintext and says exactly what
that exposes."
```

---

### Task 4: `secrets import` auto-detects and opens a sealed export

**Files:**
- Modify: `cmd/secrets/import.go`
  - imports, l.25-37 (add `"errors"`)
  - package vars, l.39-44 (add `importPassphraseFile`)
  - `Long`, l.50-64 and `Example`, l.65-72
  - `RunE`, l.73-129 (open the envelope after `RequireDataAction`, l.107-110)
  - `InitSecretsImport`, l.132-139 (deprecate `--encrypted`, register `--passphrase-file`)
- Modify: `cmd/secrets/import_cmd_test.go` (add the helper and three new tests; add `importPassphraseFile` resets)

**Interfaces:**
- Consumes: `common.IsSealedExport`, `common.OpenExport`, `common.ResolvePassphrase`, `common.ErrNoPassphraseAvailable`, `common.ErrWrongPassphrase`, `exportPassphraseEnvVar` (same package, from Task 3).
- Produces:
  ```go
  var importPassphraseFile string // --passphrase-file
  ```

- [ ] **Step 1: Write the failing tests**

Add to `cmd/secrets/import_cmd_test.go`. Add `"path/filepath"`,
`"github.com/stretchr/testify/require"` and `"rocketvault/common"` to its import
block.

```go
// newImportTestCmd builds a standalone command sharing the real import RunE.
func newImportTestCmd(file string) *cobra.Command {
	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", file, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().StringVar(&importPassphraseFile, "passphrase-file", importPassphraseFile, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	return cmd
}

func TestImportCommand_SealedFileIsDecryptedBeforeTheService(t *testing.T) {
	tc := testutils.NewTestContext(t)
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "pw")

	plain := []byte(`[{"name":"db-password","value":"hunter2"}]`)
	sealed, err := common.SealExport(plain, "pw")
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, sealed, 0o600))

	// The service must receive the opened payload, never the envelope.
	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ImportSecretsRequest) bool {
		return string(r.Data) == string(plain)
	})).Return(&secretServices.ImportResult{ImportedCount: 1}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	tc.MockSecretService.AssertExpectations(t)
}

func TestImportCommand_SealedFileWithNoPassphraseSource_Fails(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService).Maybe()
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "")

	sealed, err := common.SealExport([]byte(`[{"name":"n","value":"v"}]`), "pw")
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, sealed, 0o600))

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no passphrase")
	tc.MockSecretService.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}

func TestImportCommand_SealedFileWithWrongPassphrase_Fails(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService).Maybe()
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "not-the-passphrase")

	sealed, err := common.SealExport([]byte(`[{"name":"n","value":"v"}]`), "pw")
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, sealed, 0o600))

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong passphrase")
	tc.MockSecretService.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}

func TestImportCommand_PlaintextFileNeedsNoPassphrase(t *testing.T) {
	tc := testutils.NewTestContext(t)
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "")

	plain := []byte(`[{"name":"n","value":"v"}]`)
	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, plain, 0o600))

	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ImportSecretsRequest) bool {
		return string(r.Data) == string(plain)
	})).Return(&secretServices.ImportResult{ImportedCount: 1}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	tc.MockSecretService.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/secrets/ -run TestImportCommand -v`
Expected: FAIL to compile — `undefined: importPassphraseFile`.

- [ ] **Step 3: Add the flag variable and registration, deprecate `--encrypted`**

In `cmd/secrets/import.go`, replace the var block at l.39-44:

```go
var (
	importFormat         string
	importFile           string
	importEncrypted      bool
	importPassphraseFile string
	importOverwrite      bool
)
```

Replace `InitSecretsImport`'s body (l.133-138) with:

```go
	parentCmd.AddCommand(secretsImportCmd)
	secretsImportCmd.Flags().StringVarP(&importFormat, "format", "f", "json", "Import format (json or csv)")
	secretsImportCmd.Flags().StringVarP(&importFile, "file", "i", "", "Input file path (required)")
	secretsImportCmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", true, "File is encrypted (deprecated: detected automatically)")
	// Kept rather than removed: detection makes it redundant, but deleting it
	// would break existing invocations for no benefit.
	secretsImportCmd.Flags().MarkDeprecated("encrypted", //nolint:errcheck,gosec
		"encryption is detected automatically and this flag is ignored")
	secretsImportCmd.Flags().StringVar(&importPassphraseFile, "passphrase-file", "",
		"Read the import passphrase from the first line of this file")
	secretsImportCmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "Overwrite existing secrets")
	secretsImportCmd.MarkFlagRequired("file") //nolint:errcheck,gosec
```

- [ ] **Step 4: Open the envelope in `RunE`**

Add `"errors"` to the import block. Insert this immediately after the
`vaultcli.RequireDataAction` block (l.107-110) and before the `ImportSecrets`
call:

```go
		// A sealed export is opened here, not in the service: the CLI is the
		// only layer that can prompt for a passphrase. Detection is by content,
		// so --format and the file extension are irrelevant to it.
		if common.IsSealedExport(data) {
			passphrase, phErr := common.ResolvePassphrase(common.PassphraseSource{
				File:   importPassphraseFile,
				EnvVar: exportPassphraseEnvVar,
				Prompt: "Import passphrase: ",
			})
			if phErr != nil {
				if errors.Is(phErr, common.ErrNoPassphraseAvailable) {
					return fmt.Errorf("%s is an encrypted export but no passphrase is available: "+
						"pass --passphrase-file or set %s", importFile, exportPassphraseEnvVar)
				}
				return fmt.Errorf("failed to resolve import passphrase: %w", phErr)
			}

			opened, openErr := common.OpenExport(data, passphrase)
			if openErr != nil {
				if errors.Is(openErr, common.ErrWrongPassphrase) {
					return fmt.Errorf("failed to decrypt %s: wrong passphrase or corrupted file", importFile)
				}
				return fmt.Errorf("failed to decrypt %s: %w", importFile, openErr)
			}
			data = opened
		}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/secrets/ -run TestImport -v`
Expected: PASS, including the three pre-existing import tests.

- [ ] **Step 6: Reset the new variable in the pre-existing tests**

Add `importPassphraseFile = ""` next to each existing `importEncrypted = false`
line in `cmd/secrets/import_cmd_test.go` (l.53, l.75, l.103) and in any
`cmd/secrets/secrets_cmd_test.go` import test that sets the import flag
variables. Find them with:

```bash
grep -n "importEncrypted" cmd/secrets/*_test.go
```

Run: `go test ./cmd/secrets/`
Expected: PASS.

- [ ] **Step 7: Rewrite the help text**

Replace `Long` (l.50-64) and `Example` (l.65-72) in `cmd/secrets/import.go`:

```go
	Long: `Import secrets into the target vault from a file in the layout
"secrets export" produces.

An encrypted export is detected by its contents, not by a flag or a file
extension. When the file is encrypted the passphrase is read from
--passphrase-file, then the ROCKETVAULT_EXPORT_PASSPHRASE environment
variable, then an interactive prompt. A plaintext file needs no passphrase
and is never prompted for. --encrypted is deprecated and ignored.

--format describes the payload, not the file: an encrypted CSV export is a
JSON envelope on disk, so it is still imported with --format csv.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/setSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default". The caller
becomes the owner of every imported secret.

Records missing a name or a value are skipped rather than failing the run,
and the imported and skipped counts are printed when the run finishes.`,
	Example: `  # Import an encrypted export, prompting for the passphrase
  rocketvault secrets import --file secrets.json

  # Import non-interactively, reading the passphrase from a file
  rocketvault secrets import --file secrets.json \
    --passphrase-file /run/secrets/export-pass

  # Import a CSV export into a named vault
  rocketvault secrets import --format csv --file payments.csv \
    --vault <vault-name>`,
```

Note the `Long` no longer claims every record is created at version 1 — leave
that claim out here; B38's plan owns the `--overwrite` behavior and its help
text. Do not describe `--overwrite` in this pass.

- [ ] **Step 8: Verify the help-text guard**

Run: `go test ./cmd/ -run TestExampleFlagsAreRegistered -v`
Expected: PASS. A deprecated flag stays registered, so nothing regresses there.

- [ ] **Step 9: Commit**

```bash
git add cmd/secrets/import.go cmd/secrets/import_cmd_test.go cmd/secrets/secrets_cmd_test.go
git commit -m "feat(secrets): import an encrypted export by detection (B36)

secrets import detects a sealed envelope by content and opens it with a
passphrase from --passphrase-file, ROCKETVAULT_EXPORT_PASSPHRASE or a
prompt. --encrypted is now redundant and is marked deprecated rather than
removed, so existing invocations keep working."
```

---

### Task 5: Stop the HTTP export handler accepting a dead `encrypt` field

**Files:**
- Modify: `api/secrets.go`, `exportSecrets` (l.171-207) — reject `encrypt: true` right after the format validation at l.180-183
- Modify: `api/secrets_handlers_test.go` (append next to `TestExportSecrets_InvalidFormat_Returns400`, l.986)

**Interfaces:**
- Consumes: `model.ExportSecretsRequest.Encrypt` (already declared at `model/secret.go:228`), `Context.SetInvalidParam(string)`.
- Produces: nothing new.

**Beyond the spec's file list — flag for approval before implementing.** The
spec scopes B36 to the CLI, but `model.ExportSecretsRequest` has an `Encrypt
bool` that no code reads, so `POST /secrets/export` with `{"encrypt": true}`
returns plaintext under exactly the false assurance B36 is about. There is no
safe channel for a passphrase over that request body, so the honest fix is a
400, not an implementation. If the reviewer prefers to leave the API untouched,
skip this task and say so in the release note instead.

- [ ] **Step 1: Write the failing test**

Append to `api/secrets_handlers_test.go` after
`TestExportSecrets_InvalidFormat_Returns400`:

```go
// The API has no passphrase channel, so it must refuse "encrypt": true rather
// than return plaintext under it (B36).
func TestExportSecrets_EncryptRequested_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "json", "encrypt": true})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./api/ -run TestExportSecrets_EncryptRequested -v`
Expected: FAIL — got 500 (the nil service short-circuits) or 200, not 400.

- [ ] **Step 3: Add the rejection**

In `api/secrets.go`, immediately after the format validation block (l.180-183):

```go
	// Encrypted export needs a passphrase, and a request body is the wrong
	// place to carry one. Refusing is honest; returning plaintext under
	// "encrypt": true is the bug this replaces (B36).
	if exportReq.Encrypt {
		c.SetInvalidParam("encrypt: encrypted export is available only through the CLI (rocketvault secrets export)")
		return
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./api/ -run TestExportSecrets -v`
Expected: PASS, including the three pre-existing export handler tests, none of
which sets `encrypt`.

- [ ] **Step 5: Commit**

```bash
git add api/secrets.go api/secrets_handlers_test.go
git commit -m "fix(api): reject the export request's dead encrypt field (B36)

POST /secrets/export accepted \"encrypt\": true and returned plaintext.
There is no safe channel for a passphrase in a request body, so the
handler now returns 400 and points at the CLI."
```

---

### Task 6: Release note and bug-status update

**Files:**
- Create: `docs/release-notes/v4.2.0-encrypted-exports.md`
- Modify: `scripts/docsgen/docs.go`, the explicit render list (l.39 area)
- Modify: `.claude/known-bugs.md`, B36 entry (l.1794 onwards)

**Interfaces:** none.

If a sibling B35–B41 plan has already created a `v4.2.0-*.md` note in this
directory, append the sections below to that file instead of creating a second
one, and keep the existing heading.

- [ ] **Step 1: Write the release note**

Create `docs/release-notes/v4.2.0-encrypted-exports.md`. The format follows
`docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`: an H1 with the version
and a short subject, a two-or-three-sentence summary linking the design doc, then
H2 sections per change with **Breaking** called out in the heading.

```markdown
# v4.2.0 — Encrypted secret exports

`rocketvault secrets export` now encrypts. The `--encrypt` flag has defaulted to
`true` since it was introduced and was never read by any code, so every export
written under it was plaintext (`.claude/known-bugs.md` § B36).
Full design: `docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`.

## What an encrypted export is

A JSON envelope carrying an argon2id salt, the KDF parameters, and the export
document sealed with AES-256-GCM under a key derived from your passphrase. The
key is derived from the passphrase alone, never from the instance's master key,
so an export can be opened by any RocketVault installation given the passphrase
and survives a `master-key rotate`.

The envelope is JSON whatever `--format` you asked for; the format describes the
payload inside it. A `--format csv` export is still imported with `--format csv`.

## Where the passphrase comes from

In order: `--passphrase-file <path>` (first line, trimmed), then the
`ROCKETVAULT_EXPORT_PASSPHRASE` environment variable, then an interactive prompt
(asked twice on export, once on import).

## Breaking: an export with no passphrase source now fails

A scripted export that supplies no passphrase and has no terminal — the common
`rocketvault secrets export --file secrets.json` in a CI job or a cron entry —
now **fails and writes no file**, where it previously wrote plaintext. This is
deliberate: the previous behavior is the bug.

Two non-interactive escape hatches:

```bash
# 1. A passphrase file, e.g. mounted from your own secret store
rocketvault secrets export --file secrets.json \
  --passphrase-file /run/secrets/export-pass

# 2. The environment variable
ROCKETVAULT_EXPORT_PASSPHRASE=… rocketvault secrets export --file secrets.json
```

If a downstream tool genuinely needs a readable file, ask for plaintext
explicitly with `--encrypt=false`. The command then prints a warning naming what
the file exposes — every secret's name, plaintext value and tags — and writes it
anyway.

## `secrets import` detects encryption

Import inspects the file's contents, so no flag tells it whether a file is
encrypted. `--encrypted` is now redundant; it is **deprecated and ignored**, not
removed, so existing invocations keep working. It will be removed in a later
release.

## Breaking: `POST /secrets/export` rejects `"encrypt": true`

The API's `encrypt` field was dead in the same way the CLI flag was. A request
body is the wrong place to carry a passphrase, so the field is now rejected with
400 rather than silently returning plaintext. Encrypted export is CLI-only.

## Exports written before this release

They are plaintext. Nothing in this release can change that retroactively —
find them, treat every value in them as disclosed, and rotate accordingly.
`secrets import` still reads them: a plaintext export is imported exactly as
before, with no passphrase.
```

- [ ] **Step 2: Check the note renders in the docs site**

Run: `grep -n "release-notes" scripts/docsgen/docs.go`

The list is explicit, one `{markdown, html}` pair per line, and currently names
only `v4.0.0-azure-rbac.md` — `v4.1.0-role-parity-and-authz-fix.md` was never
added, so it does not render. Add both the new note and the missed v4.1.0 one:

```go
	{"docs/release-notes/v4.1.0-role-parity-and-authz-fix.md", "docs/release-notes/v4.1.0-role-parity-and-authz-fix.html"},
	{"docs/release-notes/v4.2.0-encrypted-exports.md", "docs/release-notes/v4.2.0-encrypted-exports.html"},
```

Then run `./scripts/docs.sh build` and confirm it exits 0 and both HTML files
appear under `docs/release-notes/`.

- [ ] **Step 3: Update the B36 entry**

In `.claude/known-bugs.md`, change B36's status lines (the `**Status**` and
`**Severity**` lines under `### B36`, l.1796-1798) to the fixed form used by B1
and B2:

```markdown
**Status**: Fixed in commit `<hash>` (2026-08-21)
**Severity**: Resolved
```

Then replace the "**Fix decision required**" paragraph with:

```markdown
**Fix taken**: export encryption is implemented, not deleted.
`ExportSecretsRequest` gained `Encrypt`/`Passphrase`; `ExportSecrets` seals the
formatted bytes with `common.SealExport` (argon2id over the existing
AES-256-GCM primitives) and errors rather than returning plaintext when
encryption was requested without a passphrase. The CLI resolves the passphrase
from `--passphrase-file`, `ROCKETVAULT_EXPORT_PASSPHRASE` or a prompt, after the
authorization check and before any write. Import detects the envelope by content
and opens it; `--encrypted` is deprecated rather than removed. The API's dead
`encrypt` field is now a 400.

**Breaking**: a scripted export with no passphrase source now fails instead of
writing plaintext. See `docs/release-notes/v4.2.0-encrypted-exports.md`.
```

Fill `<hash>` in after the Task 3 commit exists —
`git log --oneline -n 10 | grep 'make secrets export --encrypt real'`.

- [ ] **Step 4: Commit**

```bash
git add docs/release-notes/v4.2.0-encrypted-exports.md .claude/known-bugs.md scripts/docsgen/docs.go
git commit -m "docs(release-notes): document encrypted exports and the breaking change (B36)

A scripted export with no passphrase source now fails rather than writing
plaintext. Names both non-interactive escape hatches and marks B36 fixed."
```

---

### Task 7: Whole-tree verification and a real end-to-end round trip

**Files:** none modified.

**Interfaces:** none.

- [ ] **Step 1: Build, vet and format the whole tree**

Run:
```bash
go build ./...
gofmt -l cmd common internal api
go vet ./cmd/... ./common/... ./internal/services/secrets/... ./api/...
```
Expected: all clean, `gofmt` silent.

- [ ] **Step 2: Run the full test suite**

Run: `go test ./...`
Expected: PASS. Pay particular attention to `./cmd/`, `./cmd/secrets/`,
`./internal/services/secrets/`, `./api/` and `./internal/cache/` (the cached
secret service delegates `ExportSecrets` and must still compile against the
widened request struct).

- [ ] **Step 3: Round-trip a real export against a scratch instance**

Use an isolated config and database so the run does not touch
`dev-rocketvault.db`:

```bash
cd /tmp && rm -f rv-b36.db rv-b36.yaml
cp "$OLDPWD/.rocketvault.yaml.example" rv-b36.yaml
# Fill both GENERATE_WITH placeholders in rv-b36.yaml with: openssl rand -base64 32
# Point its database path at /tmp/rv-b36.db, then from the repo root:
go run . --config /tmp/rv-b36.yaml users admin --admin-username admin --admin-password '<pw>' --bootstrap-token '<token from rv-b36.yaml>'
go run . --config /tmp/rv-b36.yaml users login --username admin
go run . --config /tmp/rv-b36.yaml secrets create --name db-password --value hunter2 --tags production
ROCKETVAULT_EXPORT_PASSPHRASE=pw go run . --config /tmp/rv-b36.yaml secrets export --file /tmp/rv-b36-export.json
grep -c hunter2 /tmp/rv-b36-export.json    # expect 0 and exit status 1
head -c 200 /tmp/rv-b36-export.json        # expect the rocketvault_export envelope
```

Expected: the file contains neither `hunter2` nor `db-password`, and the command
printed `Encryption: passphrase (argon2id + AES-256-GCM)`.

- [ ] **Step 4: Confirm the failure and plaintext paths by hand**

```bash
rm -f /tmp/rv-b36-none.json
go run . --config /tmp/rv-b36.yaml secrets export --file /tmp/rv-b36-none.json < /dev/null
ls /tmp/rv-b36-none.json
```
Expected: the command exits non-zero naming `--passphrase-file`,
`ROCKETVAULT_EXPORT_PASSPHRASE` and `--encrypt=false`, and `ls` reports no such
file.

```bash
go run . --config /tmp/rv-b36.yaml secrets export --file /tmp/rv-b36-plain.json --encrypt=false
```
Expected: a warning on stderr naming names, plaintext values and tags, and a
readable JSON file.

- [ ] **Step 5: Confirm import round-trips both files**

```bash
ROCKETVAULT_EXPORT_PASSPHRASE=pw go run . --config /tmp/rv-b36.yaml secrets import --file /tmp/rv-b36-export.json
go run . --config /tmp/rv-b36.yaml secrets import --file /tmp/rv-b36-plain.json
go run . --config /tmp/rv-b36.yaml secrets list
```
Expected: both imports report `Imported: 1`; the plaintext file needs no
passphrase and is not prompted for. Then clean up:
`rm -f /tmp/rv-b36.db /tmp/rv-b36.yaml /tmp/rv-b36-*.json`.

- [ ] **Step 6: Commit nothing, report**

There is nothing to commit here. If any step failed, fix it in the task that
owns the file and re-run this task from Step 1.

---

## Definition of Done

- `secrets export` with a passphrase writes a file that does not parse as the
  plain export JSON and contains neither a secret name, a value, nor a tag as a
  substring.
- `secrets import` round-trips that file, by detection, with no flag telling it
  the file is encrypted.
- `secrets export` with no passphrase source and no terminal exits non-zero and
  leaves **no file on disk** — asserted by a test, not only by hand.
- `--encrypt=false` still works and prints a warning naming secret names,
  plaintext values and tags.
- `--encrypted` still parses and is marked deprecated.
- `docs/release-notes/v4.2.0-encrypted-exports.md` documents the breaking change
  and both non-interactive escape hatches.
- `.claude/known-bugs.md` § B36 reads Fixed with the commit hash.
- `go build ./...`, `go test ./...`, `gofmt -l`, `go vet` all clean.
- No new module dependency in `go.mod`.

## Out of scope, deliberately

- **`import --overwrite`** stays a no-op here; B38 owns it. Do not describe
  `--overwrite` in this pass's help text.
- **The CSV writer's quoting.** `ExportSecrets` builds CSV with
  `fmt.Sprintf("\"%s\",\"%s\"", name, value)` and `parseCSVLine` toggles on every
  `"`, so a secret whose value contains a double quote or a newline round-trips
  wrong. That is a pre-existing defect independent of encryption — sealing a
  malformed CSV yields the same malformed CSV on the way back — and it is not
  filed. Raise it as a new bug rather than fixing it inside this plan.
- **Re-encrypting exports already written in plaintext.** There is no tooling for
  it and none is planned; the release note tells operators to treat those values
  as disclosed.
- **`docs/cli-guide.md` and the other prose docs**, per the spec's non-goals.
