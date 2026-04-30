# CMD Service Container Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate all 8 cmd files that bypass the service container to call the correct service layer, eliminating direct repository construction, duplicate DB connections, plaintext secret storage, and encrypted version data returned to the user.

**Architecture:** Every cmd handler must obtain the service container from context via `ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)` and call the appropriate service method. No cmd file may import `rocketvault/internal/db` (except `cmd/migrate.go`) or construct repositories directly.

**Tech Stack:** Go 1.24, Cobra, testify/mock, existing service interfaces in `internal/services/`

---

## Background: The Correct Pattern

Every well-implemented cmd file follows this pattern. Reference it throughout:

```go
// 1. Get service container from context
sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
if !ok || sc == nil {
    return fmt.Errorf("service container not available in context")
}

// 2. Get the specific service needed
svc := sc.GetSecretService()

// 3. Call service with a request struct — never touch repos or DB directly
err := svc.UpdateSecret(ctx, secretServices.UpdateSecretRequest{...})
```

---

## Files Changed or Created

| File | Action | Reason |
|---|---|---|
| `internal/services/keys/key_service.go` | **Modify** | Add `Revoked *bool` to `UpdateKeyRequest`; handle it in `UpdateKey()` |
| `cmd/secrets/update.go` | **Rewrite** | Use `SecretService.UpdateSecret()` instead of direct repo |
| `cmd/secrets/export.go` | **Rewrite** | Use `SecretService.ExportSecrets()` instead of own DB init + repo |
| `cmd/secrets/import.go` | **Rewrite** | Use `SecretService.ImportSecrets()` instead of own DB init + repo |
| `cmd/keys/update.go` | **Rewrite** | Use `KeyService.UpdateKey()` instead of direct repo + raw tag repo |
| `cmd/users/admin.go` | **Rewrite** | Use service container from context instead of creating its own |
| `cmd/rotation.go` | **Rewrite** | Use `RotationService` for all 9 sub-commands (one already correct) |
| `cmd/version.go` | **Rewrite** | Use `SecretService.GetSecretVersions/GetSecretVersion/GetLatestSecretVersion()` |
| `cmd/testutils/test_utils.go` | **Modify** | Add `GetRotationService` and `GetKeyService` mocks that accept `.On(...)` calls |

---

## Task 1: Add `Revoked` field to `UpdateKeyRequest` and `UpdateKey()`

The current `UpdateKeyRequest` has no `Revoked` field, but `cmd/keys/update.go` exposes `--revoked` as a user-facing flag. The service layer must own this.

**Files:**
- Modify: `internal/services/keys/key_service.go`

- [ ] **Step 1: Write the failing test**

Add to the existing test file or create `internal/services/keys/key_service_update_test.go`:

```go
package keys

import (
    "context"
    "testing"

    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/internal/domain"
    "rocketvault/internal/logging"
    "github.com/sirupsen/logrus"
)

func boolPtr(b bool) *bool { return &b }

type mockKeyRepoForUpdate struct{ mock.Mock }

func (m *mockKeyRepoForUpdate) Read(ctx context.Context, id uuid.UUID) (*domain.Key, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*domain.Key), args.Error(1)
}
func (m *mockKeyRepoForUpdate) Update(ctx context.Context, key *domain.Key) error {
    args := m.Called(ctx, key)
    return args.Error(0)
}
// Remaining interface methods as no-ops:
func (m *mockKeyRepoForUpdate) Create(ctx context.Context, key *domain.Key) error { return nil }
func (m *mockKeyRepoForUpdate) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockKeyRepoForUpdate) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]domain.Key, error) { return nil, nil }
func (m *mockKeyRepoForUpdate) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error { return nil }
func (m *mockKeyRepoForUpdate) SoftDelete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockKeyRepoForUpdate) GetSoftDeleted(ctx context.Context, userID uuid.UUID) ([]domain.Key, error) { return nil, nil }
func (m *mockKeyRepoForUpdate) HardDelete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockKeyRepoForUpdate) Restore(ctx context.Context, id uuid.UUID) error { return nil }

func TestUpdateKey_SetsRevoked(t *testing.T) {
    repo := &mockKeyRepoForUpdate{}
    logger := &logging.Logger{Logger: logrus.New()}
    svc := &keyService{keyRepo: repo, logger: logger}

    ownerID := uuid.New()
    keyID := uuid.New()
    existing := &domain.Key{ID: keyID, UserID: ownerID, Name: "old-name", Type: "RSA", Revoked: false}

    repo.On("Read", mock.Anything, keyID).Return(existing, nil)
    repo.On("Update", mock.Anything, mock.MatchedBy(func(k *domain.Key) bool {
        return k.Revoked == true
    })).Return(nil)

    err := svc.UpdateKey(context.Background(), UpdateKeyRequest{
        KeyID:   keyID,
        UserID:  ownerID,
        Revoked: boolPtr(true),
    })

    assert.NoError(t, err)
    repo.AssertExpectations(t)
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./internal/services/keys/... -run TestUpdateKey_SetsRevoked -v
```

Expected: `FAIL — cannot use boolPtr(true) (type *bool) as UpdateKeyRequest.Revoked does not exist`

- [ ] **Step 3: Add `Revoked *bool` to `UpdateKeyRequest` and handle it in `UpdateKey()`**

In `internal/services/keys/key_service.go`, change `UpdateKeyRequest`:

```go
type UpdateKeyRequest struct {
    KeyID   uuid.UUID
    Name    *string   // Optional - nil means no change
    Tags    []string  // Optional - empty means no change
    Revoked *bool     // Optional - nil means no change
    UserID  uuid.UUID // For access control
}
```

In `UpdateKey()`, add after the tags block (before the `keyRepo.Update` call):

```go
// Update revocation status if provided
if req.Revoked != nil {
    updatedKey.Revoked = *req.Revoked
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/services/keys/... -run TestUpdateKey_SetsRevoked -v
```

Expected: `PASS`

- [ ] **Step 5: Run full test suite to confirm no regressions**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`, no `FAIL`.

- [ ] **Step 6: Commit**

```bash
git add internal/services/keys/key_service.go
git commit -m "feat(keys): add Revoked field to UpdateKeyRequest"
```

---

## Task 2: Fix `cmd/users/admin.go` — use context service container

**The bug:** `admin.go` ignores the context and creates its own `db.NewRepository` + `container.NewServiceContainer`, resulting in a duplicate DB connection and a container missing retry/cache config.

**Files:**
- Modify: `cmd/users/admin.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/users/admin_test.go`:

```go
package users

import (
    "context"
    "testing"

    "github.com/google/uuid"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/cmd/testutils"
    "rocketvault/internal/domain"
    userServices "rocketvault/internal/services/users"
)

func TestAdminCommand_UsesContextContainer(t *testing.T) {
    tc := testutils.NewTestContext(t)

    // Expect ValidateBootstrapToken called on the container's user service
    tc.MockUserService.On("ValidateBootstrapToken", mock.Anything, "test-token").
        Return(true, nil)
    tc.MockUserService.On("CreateUser", mock.Anything, mock.MatchedBy(func(r userServices.CreateUserRequest) bool {
        return r.Username == "newadmin" && r.Role == domain.RoleAdmin
    })).Return(&userServices.CreateUserResult{
        UserID:     uuid.New(),
        Username:   "newadmin",
        Role:       domain.RoleAdmin,
        TOTPSecret: "otpauth://totp/...?secret=ABCDEF",
    }, nil)
    tc.MockUserService.On("InvalidateBootstrapToken", mock.Anything, "test-token").
        Return(nil)

    // Wire mock container to return the mock user service
    tc.MockContainer.On("GetUserService").Return(tc.MockUserService)

    cmd := &cobra.Command{Use: "admin", RunE: registerAdminCmd.RunE}
    cmd.Flags().String("admin-username", "newadmin", "")
    cmd.Flags().String("admin-password", "pass123", "")
    cmd.Flags().String("bootstrap-token", "test-token", "")
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    tc.MockUserService.AssertExpectations(t)
}

func TestAdminCommand_InvalidToken(t *testing.T) {
    tc := testutils.NewTestContext(t)

    tc.MockContainer.On("GetUserService").Return(tc.MockUserService)
    tc.MockUserService.On("ValidateBootstrapToken", mock.Anything, "bad-token").
        Return(false, nil)

    cmd := &cobra.Command{Use: "admin", RunE: registerAdminCmd.RunE}
    cmd.Flags().String("admin-username", "newadmin", "")
    cmd.Flags().String("admin-password", "pass123", "")
    cmd.Flags().String("bootstrap-token", "bad-token", "")
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "invalid or used bootstrap token")
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/users/... -run TestAdminCommand -v
```

Expected: `FAIL` — test calls `registerAdminCmd.RunE` which ignores context and creates its own DB.

- [ ] **Step 3: Rewrite `cmd/users/admin.go`**

Replace the entire `RunE` body with:

```go
RunE: func(cmd *cobra.Command, args []string) error {
    ctx := cmd.Context()

    username, _ := cmd.Flags().GetString("admin-username")
    token, _ := cmd.Flags().GetString("bootstrap-token")
    password, _ := cmd.Flags().GetString("admin-password")

    if username == "" || token == "" || password == "" {
        return fmt.Errorf("admin-username, bootstrap-token, and admin-password are required")
    }

    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }

    userSvc := sc.GetUserService()

    valid, err := userSvc.ValidateBootstrapToken(ctx, token)
    if err != nil {
        return fmt.Errorf("failed to validate bootstrap token: %w", err)
    }
    if !valid {
        return fmt.Errorf("invalid or used bootstrap token")
    }

    result, err := userSvc.CreateUser(ctx, userService.CreateUserRequest{
        Username: username,
        Password: password,
        Role:     domain.RoleAdmin,
    })
    if err != nil {
        return fmt.Errorf("failed to create admin user: %w", err)
    }

    if err := userSvc.InvalidateBootstrapToken(ctx, token); err != nil {
        return fmt.Errorf("failed to invalidate bootstrap token: %w", err)
    }

    fmt.Printf("Admin user %s created successfully with ID: %s\n", result.Username, result.UserID)
    fmt.Printf("TOTP Secret: %s\n", result.TOTPSecret)
    fmt.Printf("Configure the TOTP secret in your authenticator app for MFA.\n")
    return nil
},
```

Remove the imports for `"rocketvault/internal/db"` and `"github.com/google/uuid"` (no longer used). Keep: `"fmt"`, `"rocketvault/common"`, `"rocketvault/internal/container"`, `"rocketvault/internal/domain"`, `userService "rocketvault/internal/services/users"`, `"github.com/spf13/cobra"`.

Also change `InitUsersRegisterAdmin` to use `cmd.Flags()` directly instead of `viper.BindPFlag`:

```go
func InitUsersRegisterAdmin(usersCmd *cobra.Command) *cobra.Command {
    usersCmd.AddCommand(registerAdminCmd)
    registerAdminCmd.Flags().String("admin-username", "", "Username for the admin user")
    registerAdminCmd.Flags().String("bootstrap-token", "", "Bootstrap token for initial admin registration")
    registerAdminCmd.Flags().String("admin-password", "", "Password for the admin user")
    return usersCmd
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./cmd/users/... -run TestAdminCommand -v
```

Expected: `PASS`

- [ ] **Step 5: Run full test suite**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add cmd/users/admin.go cmd/users/admin_test.go
git commit -m "fix(cmd/users): admin uses context service container instead of creating its own"
```

---

## Task 3: Fix `cmd/secrets/update.go` — use `SecretService.UpdateSecret()`

**The bug:** Constructs repo directly, stores the new value as **plaintext**, and manually increments the version number without writing a version history entry.

**Files:**
- Modify: `cmd/secrets/update.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/secrets/update_test.go`:

```go
package secrets

import (
    "context"
    "testing"

    "github.com/google/uuid"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/cmd/testutils"
    secretServices "rocketvault/internal/services/secrets"
)

func TestUpdateCommand_CallsServiceUpdate(t *testing.T) {
    tc := testutils.NewTestContext(t)
    secretID := uuid.New()
    newValue := "new-secret-value"

    tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.UpdateSecretRequest) bool {
        return r.SecretID == secretID &&
            r.UserID == tc.TestUserID &&
            r.Value != nil && *r.Value == newValue
    })).Return(nil)
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    cmd := &cobra.Command{
        Use:  "update [id] [value]",
        Args: cobra.ExactArgs(2),
        RunE: updateCmd.RunE,
    }
    cmd.Flags().StringSlice("tags", []string{}, "")
    cmd.SetArgs([]string{secretID.String(), newValue})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    tc.MockSecretService.AssertExpectations(t)
}

func TestUpdateCommand_WithTags(t *testing.T) {
    tc := testutils.NewTestContext(t)
    secretID := uuid.New()
    tags := []string{"env:prod", "team:backend"}

    tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.UpdateSecretRequest) bool {
        return r.SecretID == secretID && r.Tags != nil && len(*r.Tags) == 2
    })).Return(nil)
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    cmd := &cobra.Command{
        Use:  "update [id] [value]",
        Args: cobra.ExactArgs(2),
        RunE: updateCmd.RunE,
    }
    cmd.Flags().StringSlice("tags", []string{}, "")
    cmd.SetArgs([]string{secretID.String(), "value", "--tags=env:prod,team:backend"})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    tc.MockSecretService.AssertExpectations(t)
}

func TestUpdateCommand_ServiceError(t *testing.T) {
    tc := testutils.NewTestContext(t)
    secretID := uuid.New()

    tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.Anything).
        Return(fmt.Errorf("update failed"))
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    cmd := &cobra.Command{
        Use:  "update [id] [value]",
        Args: cobra.ExactArgs(2),
        RunE: updateCmd.RunE,
    }
    cmd.Flags().StringSlice("tags", []string{}, "")
    cmd.SetArgs([]string{secretID.String(), "value"})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "failed to update secret")
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/secrets/... -run TestUpdateCommand -v
```

Expected: `FAIL` — current code creates a repo directly.

- [ ] **Step 3: Rewrite `cmd/secrets/update.go`**

```go
package secrets

import (
    "fmt"

    "github.com/google/uuid"
    "github.com/spf13/cobra"

    "rocketvault/common"
    "rocketvault/internal/container"
    secretServices "rocketvault/internal/services/secrets"
)

var updateCmd = &cobra.Command{
    Use:   "update [id] [value]",
    Short: "Update a secret",
    Long:  `Update a secret's value and tags by its ID for the authenticated user.`,
    Args:  cobra.ExactArgs(2),
    RunE: func(cmd *cobra.Command, args []string) error {
        secretID, err := uuid.Parse(args[0])
        if err != nil {
            return fmt.Errorf("invalid secret ID: %w", err)
        }
        value := args[1]
        tags, _ := cmd.Flags().GetStringSlice("tags")

        ctx := cmd.Context()
        userID := ctx.Value(common.UserIDKey).(uuid.UUID)

        sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
        if !ok || sc == nil {
            return fmt.Errorf("service container not available in context")
        }

        req := secretServices.UpdateSecretRequest{
            SecretID: secretID,
            UserID:   userID,
            Value:    &value,
        }
        if len(tags) > 0 {
            req.Tags = &tags
        }

        if err := sc.GetSecretService().UpdateSecret(ctx, req); err != nil {
            return fmt.Errorf("failed to update secret: %w", err)
        }

        fmt.Printf("Secret %s updated successfully\n", secretID)
        return nil
    },
}

func InitSecretsUpdate(secretsCmd *cobra.Command) *cobra.Command {
    secretsCmd.AddCommand(updateCmd)
    updateCmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")
    return secretsCmd
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./cmd/secrets/... -run TestUpdateCommand -v
```

Expected: `PASS`

- [ ] **Step 5: Run full test suite**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add cmd/secrets/update.go cmd/secrets/update_test.go
git commit -m "fix(cmd/secrets): update uses SecretService.UpdateSecret — fixes plaintext storage"
```

---

## Task 4: Fix `cmd/secrets/export.go` — use `SecretService.ExportSecrets()`

**The bug:** Opens its own separate DB connection (bypassing the context one), calls a deprecated repository method, and loses the authenticated user ID from context.

**Files:**
- Modify: `cmd/secrets/export.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/secrets/export_test.go`:

```go
package secrets

import (
    "testing"

    "github.com/google/uuid"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/cmd/testutils"
    secretServices "rocketvault/internal/services/secrets"
)

func TestExportCommand_CallsServiceExport(t *testing.T) {
    tc := testutils.NewTestContext(t)

    tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
        return r.UserID == tc.TestUserID && r.Format == "json"
    })).Return([]byte(`{"secrets":[]}`), nil)
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    tmpFile := t.TempDir() + "/export.json"

    cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
    cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
    cmd.Flags().StringVarP(&exportFile, "file", "o", tmpFile, "")
    cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
    cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
    cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
    cmd.SetArgs([]string{"--file=" + tmpFile})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    tc.MockSecretService.AssertExpectations(t)
}

func TestExportCommand_UsesAuthenticatedUserID(t *testing.T) {
    tc := testutils.NewTestContext(t)
    capturedUserID := uuid.Nil

    tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
        capturedUserID = r.UserID
        return true
    })).Return([]byte(`{}`), nil)
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    tmpFile := t.TempDir() + "/export.json"
    cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
    cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
    cmd.Flags().StringVarP(&exportFile, "file", "o", tmpFile, "")
    cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
    cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
    cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
    cmd.SetArgs([]string{"--file=" + tmpFile})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    assert.Equal(t, tc.TestUserID, capturedUserID, "export must use the authenticated user ID from context")
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/secrets/... -run TestExportCommand -v
```

Expected: `FAIL` — current code initialises its own DB.

- [ ] **Step 3: Rewrite `cmd/secrets/export.go`**

```go
package secrets

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/google/uuid"
    "github.com/spf13/cobra"

    "rocketvault/common"
    "rocketvault/internal/container"
    secretServices "rocketvault/internal/services/secrets"
)

var (
    exportFormat     string
    exportFile       string
    exportEncrypt    bool
    exportTags       []string
    exportFilterTags []string
)

var secretsExportCmd = &cobra.Command{
    Use:   "export",
    Short: "Export secrets to a file",
    Long: `Export secrets to an encrypted JSON or CSV file.
The export includes all secrets for the authenticated user with optional tag filtering.`,
    Example: `  secrets export --format json --file secrets.json
  secrets export --format csv  --file secrets.csv --tags production`,
    RunE: func(cmd *cobra.Command, args []string) error {
        ctx := cmd.Context()

        userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
        if !ok {
            return fmt.Errorf("user not authenticated")
        }

        sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
        if !ok || sc == nil {
            return fmt.Errorf("service container not available in context")
        }

        format := strings.ToLower(exportFormat)
        if format != "json" && format != "csv" {
            return fmt.Errorf("unsupported format: %s (supported: json, csv)", exportFormat)
        }

        allTags := append(exportTags, exportFilterTags...)

        data, err := sc.GetSecretService().ExportSecrets(ctx, secretServices.ExportSecretsRequest{
            UserID:      userID,
            Format:      format,
            FilterTags:  allTags,
            IncludeTags: true,
        })
        if err != nil {
            return fmt.Errorf("failed to export secrets: %w", err)
        }

        dir := filepath.Dir(exportFile)
        if dir != "." {
            if err := os.MkdirAll(dir, 0o755); err != nil {
                return fmt.Errorf("failed to create output directory: %w", err)
            }
        }
        if err := os.WriteFile(exportFile, data, 0o600); err != nil {
            return fmt.Errorf("failed to write export file: %w", err)
        }

        fmt.Printf("Secrets exported successfully\nFormat: %s\nFile: %s\n", format, exportFile)
        return nil
    },
}

func InitSecretsExport(parentCmd *cobra.Command) {
    parentCmd.AddCommand(secretsExportCmd)
    secretsExportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "Export format (json or csv)")
    secretsExportCmd.Flags().StringVarP(&exportFile, "file", "o", "", "Output file path (required)")
    secretsExportCmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", true, "Encrypt the export file")
    secretsExportCmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "Include only secrets with these tags")
    secretsExportCmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "Filter secrets by these tags")
    secretsExportCmd.MarkFlagRequired("file")
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./cmd/secrets/... -run TestExportCommand -v
```

Expected: `PASS`

- [ ] **Step 5: Run full test suite**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add cmd/secrets/export.go cmd/secrets/export_test.go
git commit -m "fix(cmd/secrets): export uses SecretService — removes duplicate DB connection"
```

---

## Task 5: Fix `cmd/secrets/import.go` — use `SecretService.ImportSecrets()`

**The bug:** Opens its own DB connection and uses a placeholder `uuid.New()` for the importing user — imported secrets are attributed to a random UUID, not the authenticated user.

**Files:**
- Modify: `cmd/secrets/import.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/secrets/import_cmd_test.go`:

```go
package secrets

import (
    "testing"

    "github.com/google/uuid"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/cmd/testutils"
    secretServices "rocketvault/internal/services/secrets"
)

func TestImportCommand_UsesAuthenticatedUserID(t *testing.T) {
    tc := testutils.NewTestContext(t)
    capturedUserID := uuid.Nil

    tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ImportSecretsRequest) bool {
        capturedUserID = r.UserID
        return true
    })).Return(&secretServices.ImportResult{ImportedCount: 2}, nil)
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    // Write a temp import file
    tmpFile := t.TempDir() + "/import.json"
    os.WriteFile(tmpFile, []byte(`{}`), 0o600)

    cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
    cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
    cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
    cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
    cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
    cmd.SetArgs([]string{"--file=" + tmpFile})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    assert.Equal(t, tc.TestUserID, capturedUserID, "import must use authenticated user ID, not a random UUID")
    tc.MockSecretService.AssertExpectations(t)
}
```

Note: add `"os"` to the import block of the test file.

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/secrets/... -run TestImportCommand -v
```

Expected: `FAIL` — current code uses `uuid.New()` as the user ID.

- [ ] **Step 3: Rewrite `cmd/secrets/import.go`**

```go
package secrets

import (
    "fmt"
    "os"
    "strings"

    "github.com/google/uuid"
    "github.com/spf13/cobra"

    "rocketvault/common"
    "rocketvault/internal/container"
    secretServices "rocketvault/internal/services/secrets"
)

var (
    importFormat    string
    importFile      string
    importEncrypted bool
    importOverwrite bool
)

var secretsImportCmd = &cobra.Command{
    Use:   "import",
    Short: "Import secrets from a file",
    Long: `Import secrets from a JSON or CSV file.
The file must be compatible with the export format produced by the export command.`,
    Example: `  secrets import --file secrets.json
  secrets import --file secrets.json --overwrite`,
    RunE: func(cmd *cobra.Command, args []string) error {
        ctx := cmd.Context()

        userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
        if !ok {
            return fmt.Errorf("user not authenticated")
        }

        sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
        if !ok || sc == nil {
            return fmt.Errorf("service container not available in context")
        }

        format := strings.ToLower(importFormat)
        if format != "json" && format != "csv" {
            return fmt.Errorf("unsupported format: %s (supported: json, csv)", importFormat)
        }

        if _, err := os.Stat(importFile); os.IsNotExist(err) {
            return fmt.Errorf("import file does not exist: %s", importFile)
        }

        data, err := os.ReadFile(importFile)
        if err != nil {
            return fmt.Errorf("failed to read import file: %w", err)
        }

        result, err := sc.GetSecretService().ImportSecrets(ctx, secretServices.ImportSecretsRequest{
            UserID:    userID,
            Data:      data,
            Format:    format,
            Overwrite: importOverwrite,
        })
        if err != nil {
            return fmt.Errorf("failed to import secrets: %w", err)
        }

        fmt.Printf("Secrets imported successfully\nImported: %d\nSkipped: %d\n",
            result.ImportedCount, result.SkippedCount)
        return nil
    },
}

func InitSecretsImport(parentCmd *cobra.Command) {
    parentCmd.AddCommand(secretsImportCmd)
    secretsImportCmd.Flags().StringVarP(&importFormat, "format", "f", "json", "Import format (json or csv)")
    secretsImportCmd.Flags().StringVarP(&importFile, "file", "i", "", "Input file path (required)")
    secretsImportCmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", true, "File is encrypted")
    secretsImportCmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "Overwrite existing secrets")
    secretsImportCmd.MarkFlagRequired("file")
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./cmd/secrets/... -run TestImportCommand -v
```

Expected: `PASS`

- [ ] **Step 5: Run full test suite**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add cmd/secrets/import.go cmd/secrets/import_cmd_test.go
git commit -m "fix(cmd/secrets): import uses authenticated user ID — removes random UUID bug"
```

---

## Task 6: Fix `cmd/keys/update.go` — use `KeyService.UpdateKey()`

**The bug:** Creates key repository and tag repository directly; manual ownership check won't benefit from future service-layer changes.

**Files:**
- Modify: `cmd/keys/update.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/keys/update_test.go`:

```go
package keys

import (
    "context"
    "fmt"
    "testing"

    "github.com/google/uuid"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/cmd/testutils"
    keyServices "rocketvault/internal/services/keys"
)

type MockKeyServiceForUpdate struct{ mock.Mock }

func (m *MockKeyServiceForUpdate) UpdateKey(ctx context.Context, req keyServices.UpdateKeyRequest) error {
    args := m.Called(ctx, req)
    return args.Error(0)
}
// Satisfy interface with no-ops:
func (m *MockKeyServiceForUpdate) CreateRSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) { return nil, nil }
func (m *MockKeyServiceForUpdate) CreateECDSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) { return nil, nil }
func (m *MockKeyServiceForUpdate) GetKey(ctx context.Context, keyID, userID uuid.UUID) (*domain.Key, error) { return nil, nil }
func (m *MockKeyServiceForUpdate) ListKeys(ctx context.Context, userID uuid.UUID) ([]domain.Key, error) { return nil, nil }
func (m *MockKeyServiceForUpdate) ListKeysWithFilters(ctx context.Context, userID *uuid.UUID, keyType string, tags []string, isAdmin bool) ([]domain.Key, error) { return nil, nil }
func (m *MockKeyServiceForUpdate) DeleteKey(ctx context.Context, keyID, userID uuid.UUID) error { return nil }
func (m *MockKeyServiceForUpdate) RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*keyServices.CreateKeyResult, error) { return nil, nil }
func (m *MockKeyServiceForUpdate) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error { return nil }

func strPtr(s string) *string { return &s }
func boolPtrTest(b bool) *bool { return &b }

func TestUpdateKeyCommand_CallsServiceUpdate(t *testing.T) {
    tc := testutils.NewTestContext(t)
    mockKeySvc := &MockKeyServiceForUpdate{}
    keyID := uuid.New()

    mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
        return r.KeyID == keyID &&
            r.UserID == tc.TestUserID &&
            r.Name != nil && *r.Name == "new-name"
    })).Return(nil)
    tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

    cmd := &cobra.Command{
        Use:  "update <id>",
        Args: cobra.ExactArgs(1),
        RunE: updateCmd.RunE,
    }
    cmd.Flags().String("name", "", "")
    cmd.Flags().Bool("revoked", false, "")
    cmd.Flags().String("tags", "", "")
    cmd.SetArgs([]string{keyID.String(), "--name=new-name"})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    mockKeySvc.AssertExpectations(t)
}

func TestUpdateKeyCommand_SetsRevoked(t *testing.T) {
    tc := testutils.NewTestContext(t)
    mockKeySvc := &MockKeyServiceForUpdate{}
    keyID := uuid.New()

    mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
        return r.Revoked != nil && *r.Revoked == true
    })).Return(nil)
    tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

    cmd := &cobra.Command{
        Use:  "update <id>",
        Args: cobra.ExactArgs(1),
        RunE: updateCmd.RunE,
    }
    cmd.Flags().String("name", "", "")
    cmd.Flags().Bool("revoked", false, "")
    cmd.Flags().String("tags", "", "")
    cmd.SetArgs([]string{keyID.String(), "--revoked=true"})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    mockKeySvc.AssertExpectations(t)
}

func TestUpdateKeyCommand_NoFieldsProvided(t *testing.T) {
    tc := testutils.NewTestContext(t)
    keyID := uuid.New()

    cmd := &cobra.Command{
        Use:  "update <id>",
        Args: cobra.ExactArgs(1),
        RunE: updateCmd.RunE,
    }
    cmd.Flags().String("name", "", "")
    cmd.Flags().Bool("revoked", false, "")
    cmd.Flags().String("tags", "", "")
    cmd.SetArgs([]string{keyID.String()})
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "at least one update field")
}
```

Also add `"rocketvault/internal/domain"` to the import block.

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/keys/... -run TestUpdateKeyCommand -v
```

Expected: `FAIL` — current code creates repo directly.

- [ ] **Step 3: Update `cmd/testutils/test_utils.go` to support `GetKeyService`**

The mock container currently returns `nil` for `GetKeyService`. Change it to support `.On("GetKeyService", ...)`:

```go
func (m *MockServiceContainer) GetKeyService() keyServices.KeyService {
    args := m.Called()
    if len(args) == 0 || args.Get(0) == nil {
        return nil
    }
    return args.Get(0).(keyServices.KeyService)
}
```

- [ ] **Step 4: Rewrite `cmd/keys/update.go`**

```go
package keys

import (
    "fmt"
    "strings"
    "time"

    "github.com/google/uuid"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"

    "rocketvault/common"
    "rocketvault/internal/container"
    "rocketvault/internal/domain"
    keyServices "rocketvault/internal/services/keys"
)

var updateCmd = &cobra.Command{
    Use:     "update <id>",
    Short:   "Update a cryptographic key",
    Long:    `Update a cryptographic key's name, revocation status, or tags by its UUID.`,
    Example: `rocketvault keys update <key-id> --username admin --password admin123 --totp-code <code> --name newkey --revoked true`,
    Args:    cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        ctx := cmd.Context()
        claims, ok := ctx.Value(common.ClaimsKey).(*domain.Claims)
        if !ok {
            return fmt.Errorf("unauthorized: missing authentication claims")
        }

        keyID, err := uuid.Parse(args[0])
        if err != nil {
            return fmt.Errorf("invalid key ID: %w", err)
        }

        sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
        if !ok || sc == nil {
            return fmt.Errorf("service container not available in context")
        }

        newName := viper.GetString("name")
        tagsStr := viper.GetString("tags")

        req := keyServices.UpdateKeyRequest{
            KeyID:  keyID,
            UserID: claims.UserID,
        }

        hasUpdate := false

        if newName != "" {
            req.Name = &newName
            hasUpdate = true
        }
        if tagsStr != "" {
            tags := strings.Split(tagsStr, ",")
            for i, t := range tags {
                tags[i] = strings.TrimSpace(t)
            }
            req.Tags = tags
            hasUpdate = true
        }
        if cmd.Flags().Changed("revoked") {
            revoked := viper.GetBool("revoked")
            req.Revoked = &revoked
            hasUpdate = true
        }

        if !hasUpdate {
            return fmt.Errorf("at least one update field (name, revoked, tags) must be provided")
        }

        if err := sc.GetKeyService().UpdateKey(ctx, req); err != nil {
            return fmt.Errorf("failed to update key: %w", err)
        }

        fmt.Printf("Key %s updated successfully at %s\n", keyID, time.Now().Format(time.RFC3339))
        return nil
    },
}

func InitKeysUpdate(keysCmd *cobra.Command) *cobra.Command {
    keysCmd.AddCommand(updateCmd)
    updateCmd.Flags().String("name", "", "New name for the key")
    updateCmd.Flags().Bool("revoked", false, "Set key revocation status")
    updateCmd.Flags().String("tags", "", "Comma-separated tags to replace existing tags")
    viper.BindPFlag("name", updateCmd.Flags().Lookup("name"))
    viper.BindPFlag("revoked", updateCmd.Flags().Lookup("revoked"))
    viper.BindPFlag("tags", updateCmd.Flags().Lookup("tags"))
    return keysCmd
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
go test ./cmd/keys/... -run TestUpdateKeyCommand -v
```

Expected: `PASS`

- [ ] **Step 6: Run full test suite**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 7: Commit**

```bash
git add cmd/keys/update.go cmd/keys/update_test.go cmd/testutils/test_utils.go internal/services/keys/key_service.go
git commit -m "fix(cmd/keys): update uses KeyService.UpdateKey including Revoked support"
```

---

## Task 7: Fix `cmd/version.go` — use `SecretService` version methods

**The bug:** Calls deprecated repository methods directly, returning **encrypted ciphertext** to the user instead of decrypted values.

**Files:**
- Modify: `cmd/version.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/version_test.go`:

```go
package cmd

import (
    "bytes"
    "context"
    "fmt"
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/cmd/testutils"
    "rocketvault/common"
    "rocketvault/internal/domain"
)

func TestVersionListCommand_ReturnsDecryptedVersions(t *testing.T) {
    tc := testutils.NewTestContext(t)
    secretID := uuid.New()

    versions := []domain.SecretVersion{
        {SecretID: secretID, Version: 1, Name: "my-secret", Value: "plaintext-value-1", CreatedAt: time.Now()},
        {SecretID: secretID, Version: 2, Name: "my-secret", Value: "plaintext-value-2", CreatedAt: time.Now()},
    }
    tc.MockSecretService.On("GetSecretVersions", mock.Anything, secretID, tc.TestUserID).
        Return(versions, nil)
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    var out bytes.Buffer
    cmd := &cobra.Command{Use: "list", RunE: versionListCmd.RunE}
    cmd.Flags().StringVar(&versionSecretID, "secret-id", secretID.String(), "")
    cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))
    cmd.SetOut(&out)

    err := cmd.Execute()
    assert.NoError(t, err)
    assert.Contains(t, out.String(), "plaintext-value-1")
    tc.MockSecretService.AssertExpectations(t)
}

func TestVersionGetCommand_ReturnsDecryptedVersion(t *testing.T) {
    tc := testutils.NewTestContext(t)
    secretID := uuid.New()

    version := &domain.SecretVersion{
        SecretID: secretID, Version: 2,
        Name: "my-secret", Value: "decrypted-value", CreatedAt: time.Now(),
    }
    tc.MockSecretService.On("GetSecretVersion", mock.Anything, secretID, 2, tc.TestUserID).
        Return(version, nil)
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    var out bytes.Buffer
    cmd := &cobra.Command{Use: "get", RunE: versionGetCmd.RunE}
    cmd.Flags().StringVar(&versionSecretID, "secret-id", secretID.String(), "")
    cmd.Flags().IntVar(&versionNumber, "version", 2, "")
    cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))
    cmd.SetOut(&out)

    err := cmd.Execute()
    assert.NoError(t, err)
    assert.Contains(t, out.String(), "decrypted-value")
    tc.MockSecretService.AssertExpectations(t)
}

func TestVersionLatestCommand_ReturnsDecryptedLatest(t *testing.T) {
    tc := testutils.NewTestContext(t)
    secretID := uuid.New()

    version := &domain.SecretVersion{
        SecretID: secretID, Version: 3,
        Name: "my-secret", Value: "latest-decrypted-value", CreatedAt: time.Now(),
    }
    tc.MockSecretService.On("GetLatestSecretVersion", mock.Anything, secretID, tc.TestUserID).
        Return(version, nil)
    tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

    var out bytes.Buffer
    cmd := &cobra.Command{Use: "latest", RunE: versionLatestCmd.RunE}
    cmd.Flags().StringVar(&versionSecretID, "secret-id", secretID.String(), "")
    cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))
    cmd.SetOut(&out)

    err := cmd.Execute()
    assert.NoError(t, err)
    assert.Contains(t, out.String(), "latest-decrypted-value")
    tc.MockSecretService.AssertExpectations(t)
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/... -run TestVersion -v
```

Expected: `FAIL` — current code calls repo methods directly (deprecated, encrypted data).

- [ ] **Step 3: Rewrite the three `runVersion*` functions in `cmd/version.go`**

Replace `runVersionList`, `runVersionGet`, and `runVersionLatest` with:

```go
func runVersionList(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)

    secretID, err := uuid.Parse(versionSecretID)
    if err != nil {
        return fmt.Errorf("invalid secret ID: %w", err)
    }

    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }

    versions, err := sc.GetSecretService().GetSecretVersions(ctx, secretID, userID)
    if err != nil {
        return fmt.Errorf("failed to get versions: %w", err)
    }

    if len(versions) == 0 {
        fmt.Fprintf(cmd.OutOrStdout(), "No versions found for secret %s\n", versionSecretID)
        return nil
    }

    w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "VERSION\tCREATED_AT\tNAME\tVALUE")
    fmt.Fprintln(w, "-------\t----------\t----\t-----")
    for _, v := range versions {
        fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
            v.Version, v.CreatedAt.Format("2006-01-02 15:04:05"), v.Name, v.Value)
    }
    w.Flush()
    fmt.Fprintf(cmd.OutOrStdout(), "\nFound %d versions for secret %s\n", len(versions), versionSecretID)
    return nil
}

func runVersionGet(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)

    secretID, err := uuid.Parse(versionSecretID)
    if err != nil {
        return fmt.Errorf("invalid secret ID: %w", err)
    }

    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }

    version, err := sc.GetSecretService().GetSecretVersion(ctx, secretID, versionNumber, userID)
    if err != nil {
        return fmt.Errorf("failed to get version: %w", err)
    }

    fmt.Fprintf(cmd.OutOrStdout(), "Secret ID: %s\nVersion:   %d\nName:      %s\nValue:     %s\nCreated:   %s\n",
        version.SecretID, version.Version, version.Name, version.Value,
        version.CreatedAt.Format("2006-01-02 15:04:05"))
    return nil
}

func runVersionLatest(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)

    secretID, err := uuid.Parse(versionSecretID)
    if err != nil {
        return fmt.Errorf("invalid secret ID: %w", err)
    }

    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }

    version, err := sc.GetSecretService().GetLatestSecretVersion(ctx, secretID, userID)
    if err != nil {
        return fmt.Errorf("failed to get latest version: %w", err)
    }

    fmt.Fprintf(cmd.OutOrStdout(), "Secret ID: %s\nVersion:   %d\nName:      %s\nValue:     %s\nCreated:   %s\n",
        version.SecretID, version.Version, version.Name, version.Value,
        version.CreatedAt.Format("2006-01-02 15:04:05"))
    return nil
}
```

Remove the imports `"rocketvault/internal/repositories"` and `"rocketvault/internal/logging"`. Add `"rocketvault/internal/container"` and `"text/tabwriter"`.

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./cmd/... -run TestVersion -v
```

Expected: `PASS`

- [ ] **Step 5: Run full test suite**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add cmd/version.go cmd/version_test.go
git commit -m "fix(cmd/version): use SecretService — fixes encrypted ciphertext returned to user"
```

---

## Task 8: Fix `cmd/rotation.go` — use `RotationService` for all 9 sub-commands

**The bug:** 8 of 9 sub-commands construct the rotation repository directly. Only `runRotationRotate` (the one that creates its own container) uses the service. All 9 must use the context service container.

**Files:**
- Modify: `cmd/rotation.go`

- [ ] **Step 1: Write the failing tests**

Create `cmd/rotation_service_test.go`:

```go
package cmd

import (
    "bytes"
    "context"
    "fmt"
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/spf13/cobra"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/cmd/testutils"
    "rocketvault/common"
    "rocketvault/internal/domain"
    secretServices "rocketvault/internal/services/secrets"
)

type MockRotationService struct{ mock.Mock }

func (m *MockRotationService) CreatePolicy(ctx context.Context, req secretServices.CreatePolicyRequest) (*domain.RotationPolicy, error) {
    args := m.Called(ctx, req)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}
func (m *MockRotationService) GetPolicy(ctx context.Context, id uuid.UUID) (*domain.RotationPolicy, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}
func (m *MockRotationService) UpdatePolicy(ctx context.Context, req secretServices.UpdatePolicyRequest) (*domain.RotationPolicy, error) {
    args := m.Called(ctx, req)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}
func (m *MockRotationService) DeletePolicy(ctx context.Context, id uuid.UUID) error {
    args := m.Called(ctx, id)
    return args.Error(0)
}
func (m *MockRotationService) ListUserPolicies(ctx context.Context, userID uuid.UUID) ([]domain.RotationPolicy, error) {
    args := m.Called(ctx, userID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).([]domain.RotationPolicy), args.Error(1)
}
func (m *MockRotationService) AssignPolicyToSecret(ctx context.Context, req secretServices.AssignPolicyRequest) error {
    args := m.Called(ctx, req)
    return args.Error(0)
}
func (m *MockRotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID) error {
    args := m.Called(ctx, secretID, policyID)
    return args.Error(0)
}
func (m *MockRotationService) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]domain.RotationPolicy, error) {
    args := m.Called(ctx, secretID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).([]domain.RotationPolicy), args.Error(1)
}
func (m *MockRotationService) PerformManualRotation(ctx context.Context, req secretServices.ManualRotationRequest) error {
    args := m.Called(ctx, req)
    return args.Error(0)
}
func (m *MockRotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID) ([]domain.RotationHistory, error) {
    args := m.Called(ctx, secretID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).([]domain.RotationHistory), args.Error(1)
}
func (m *MockRotationService) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]domain.SecretPolicy, error) {
    args := m.Called(ctx, userID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).([]domain.SecretPolicy), args.Error(1)
}
func (m *MockRotationService) CreateRotationReminder(ctx context.Context, req secretServices.CreateReminderRequest) error {
    return nil
}
func (m *MockRotationService) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]domain.RotationReminder, error) {
    args := m.Called(ctx, userID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).([]domain.RotationReminder), args.Error(1)
}
func (m *MockRotationService) AcknowledgeReminder(ctx context.Context, reminderID uuid.UUID) error {
    return nil
}

func setupRotationContext(t *testing.T) (*testutils.TestContext, *MockRotationService) {
    tc := testutils.NewTestContext(t)
    mockRotSvc := &MockRotationService{}
    tc.MockContainer.On("GetRotationService").Return(mockRotSvc)
    return tc, mockRotSvc
}

func TestRotationCreateCommand_UsesService(t *testing.T) {
    tc, mockRotSvc := setupRotationContext(t)
    policyID := uuid.New()

    mockRotSvc.On("CreatePolicy", mock.Anything, mock.MatchedBy(func(r secretServices.CreatePolicyRequest) bool {
        return r.Name == "test-policy" && r.IntervalDays == 30 && r.UserID == tc.TestUserID
    })).Return(&domain.RotationPolicy{ID: policyID, Name: "test-policy", IntervalDays: 30}, nil)

    policyName = "test-policy"
    policyInterval = 30
    policyReminder = 7
    policyAutoRotate = false

    var out bytes.Buffer
    cmd := &cobra.Command{Use: "create", RunE: rotationCreateCmd.RunE}
    cmd.SetContext(tc.Ctx)
    cmd.SetOut(&out)

    err := cmd.Execute()
    assert.NoError(t, err)
    assert.Contains(t, out.String(), "created successfully")
    mockRotSvc.AssertExpectations(t)
}

func TestRotationListCommand_UsesService(t *testing.T) {
    tc, mockRotSvc := setupRotationContext(t)

    mockRotSvc.On("ListUserPolicies", mock.Anything, tc.TestUserID).
        Return([]domain.RotationPolicy{
            {ID: uuid.New(), Name: "policy-1", IntervalDays: 30, AutoRotate: true, Enabled: true, CreatedAt: time.Now()},
        }, nil)

    var out bytes.Buffer
    cmd := &cobra.Command{Use: "list", RunE: rotationListCmd.RunE}
    cmd.SetContext(tc.Ctx)
    cmd.SetOut(&out)

    err := cmd.Execute()
    assert.NoError(t, err)
    assert.Contains(t, out.String(), "policy-1")
    mockRotSvc.AssertExpectations(t)
}

func TestRotationRotateCommand_UsesContextContainer(t *testing.T) {
    tc, mockRotSvc := setupRotationContext(t)
    sid := uuid.New()
    pid := uuid.New()

    mockRotSvc.On("PerformManualRotation", mock.Anything, mock.MatchedBy(func(r secretServices.ManualRotationRequest) bool {
        return r.SecretID == sid && r.PolicyID == pid && r.UserID == tc.TestUserID
    })).Return(nil)

    secretID = sid.String()
    policyID = pid.String()

    cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
    cmd.SetContext(tc.Ctx)

    err := cmd.Execute()
    assert.NoError(t, err)
    mockRotSvc.AssertExpectations(t)
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/... -run TestRotationCreateCommand -v
go test ./cmd/... -run TestRotationListCommand -v
go test ./cmd/... -run TestRotationRotateCommand -v
```

Expected: `FAIL` — commands use repos or create their own container.

- [ ] **Step 3: Update `cmd/testutils/test_utils.go` to support `GetRotationService`**

Change the existing `GetRotationService` mock method:

```go
func (m *MockServiceContainer) GetRotationService() secretServices.RotationServiceInterface {
    args := m.Called()
    if len(args) == 0 || args.Get(0) == nil {
        return nil
    }
    return args.Get(0).(secretServices.RotationServiceInterface)
}
```

- [ ] **Step 4: Rewrite all `runRotation*` functions in `cmd/rotation.go`**

Replace every function body. The pattern is identical: get `sc` from context, call `sc.GetRotationService()`, call the method.

```go
func runRotationCreate(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    policy, err := sc.GetRotationService().CreatePolicy(ctx, secrets.CreatePolicyRequest{
        UserID:       userID,
        Name:         policyName,
        Description:  policyDescription,
        IntervalDays: policyInterval,
        Enabled:      true,
        ReminderDays: policyReminder,
        AutoRotate:   policyAutoRotate,
    })
    if err != nil {
        return fmt.Errorf("failed to create rotation policy: %w", err)
    }
    fmt.Fprintf(cmd.OutOrStdout(), "Rotation policy created successfully\nPolicy ID: %s\nName: %s\nInterval: %d days\nAuto-rotate: %t\n",
        policy.ID, policy.Name, policy.IntervalDays, policy.AutoRotate)
    return nil
}

func runRotationList(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    policies, err := sc.GetRotationService().ListUserPolicies(ctx, userID)
    if err != nil {
        return fmt.Errorf("failed to list rotation policies: %w", err)
    }
    if len(policies) == 0 {
        fmt.Fprintln(cmd.OutOrStdout(), "No rotation policies found.")
        return nil
    }
    w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "ID\tNAME\tINTERVAL\tAUTO-ROTATE\tENABLED\tCREATED")
    fmt.Fprintln(w, "--\t----\t--------\t-----------\t-------\t-------")
    for _, p := range policies {
        fmt.Fprintf(w, "%s\t%s\t%d days\t%t\t%t\t%s\n",
            p.ID.String()[:8]+"...", p.Name, p.IntervalDays,
            p.AutoRotate, p.Enabled, p.CreatedAt.Format("2006-01-02"))
    }
    w.Flush()
    fmt.Fprintf(cmd.OutOrStdout(), "\nFound %d rotation policies\n", len(policies))
    return nil
}

func runRotationUpdate(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    pid, err := uuid.Parse(policyID)
    if err != nil {
        return fmt.Errorf("invalid policy ID: %w", err)
    }
    existing, err := sc.GetRotationService().GetPolicy(ctx, pid)
    if err != nil {
        return fmt.Errorf("failed to read policy: %w", err)
    }
    req := secrets.UpdatePolicyRequest{
        ID:           pid,
        UserID:       userID,
        Name:         existing.Name,
        Description:  existing.Description,
        IntervalDays: existing.IntervalDays,
        Enabled:      existing.Enabled,
        ReminderDays: existing.ReminderDays,
        AutoRotate:   existing.AutoRotate,
    }
    if cmd.Flags().Changed("name")        { req.Name = policyName }
    if cmd.Flags().Changed("description") { req.Description = policyDescription }
    if cmd.Flags().Changed("interval")    { req.IntervalDays = policyInterval }
    if cmd.Flags().Changed("reminder")    { req.ReminderDays = policyReminder }
    if cmd.Flags().Changed("auto-rotate") { req.AutoRotate = policyAutoRotate }
    if _, err := sc.GetRotationService().UpdatePolicy(ctx, req); err != nil {
        return fmt.Errorf("failed to update rotation policy: %w", err)
    }
    fmt.Fprintln(cmd.OutOrStdout(), "Rotation policy updated successfully.")
    return nil
}

func runRotationDelete(cmd *cobra.Command) error {
    ctx := cmd.Context()
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    pid, err := uuid.Parse(policyID)
    if err != nil {
        return fmt.Errorf("invalid policy ID: %w", err)
    }
    if err := sc.GetRotationService().DeletePolicy(ctx, pid); err != nil {
        return fmt.Errorf("failed to delete rotation policy: %w", err)
    }
    fmt.Fprintln(cmd.OutOrStdout(), "Rotation policy deleted successfully.")
    return nil
}

func runRotationAssign(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    pid, err := uuid.Parse(policyID)
    if err != nil {
        return fmt.Errorf("invalid policy ID: %w", err)
    }
    sid, err := uuid.Parse(secretID)
    if err != nil {
        return fmt.Errorf("invalid secret ID: %w", err)
    }
    if err := sc.GetRotationService().AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{
        SecretID: sid,
        PolicyID: pid,
        UserID:   userID,
    }); err != nil {
        return fmt.Errorf("failed to assign policy to secret: %w", err)
    }
    fmt.Fprintln(cmd.OutOrStdout(), "Policy assigned to secret successfully.")
    return nil
}

func runRotationUnassign(cmd *cobra.Command) error {
    ctx := cmd.Context()
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    pid, err := uuid.Parse(policyID)
    if err != nil {
        return fmt.Errorf("invalid policy ID: %w", err)
    }
    sid, err := uuid.Parse(secretID)
    if err != nil {
        return fmt.Errorf("invalid secret ID: %w", err)
    }
    if err := sc.GetRotationService().RemovePolicyFromSecret(ctx, sid, pid); err != nil {
        return fmt.Errorf("failed to remove policy from secret: %w", err)
    }
    fmt.Fprintln(cmd.OutOrStdout(), "Policy removed from secret successfully.")
    return nil
}

func runRotationRotate(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    sid, err := uuid.Parse(secretID)
    if err != nil {
        return fmt.Errorf("invalid secret ID: %w", err)
    }
    pid, err := uuid.Parse(policyID)
    if err != nil {
        return fmt.Errorf("invalid policy ID: %w", err)
    }
    if err := sc.GetRotationService().PerformManualRotation(ctx, secrets.ManualRotationRequest{
        SecretID: sid,
        PolicyID: pid,
        UserID:   userID,
    }); err != nil {
        return fmt.Errorf("failed to rotate secret: %w", err)
    }
    fmt.Fprintln(cmd.OutOrStdout(), "Secret rotated successfully.")
    return nil
}

func runRotationHistory(cmd *cobra.Command) error {
    ctx := cmd.Context()
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    sid, err := uuid.Parse(secretID)
    if err != nil {
        return fmt.Errorf("invalid secret ID: %w", err)
    }
    history, err := sc.GetRotationService().GetRotationHistory(ctx, sid)
    if err != nil {
        return fmt.Errorf("failed to get rotation history: %w", err)
    }
    if len(history) == 0 {
        fmt.Fprintf(cmd.OutOrStdout(), "No rotation history found for secret %s\n", secretID)
        return nil
    }
    w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "ROTATED_AT\tTRIGGERED_BY\tPREV_VERSION\tNEW_VERSION\tNOTES")
    fmt.Fprintln(w, "----------\t------------\t------------\t-----------\t-----")
    for _, h := range history {
        notes := h.Notes
        if len(notes) > 30 {
            notes = notes[:27] + "..."
        }
        fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n",
            h.RotatedAt.Format("2006-01-02 15:04"), h.TriggeredBy,
            h.PreviousVersion, h.NewVersion, notes)
    }
    w.Flush()
    fmt.Fprintf(cmd.OutOrStdout(), "\nFound %d rotation events\n", len(history))
    return nil
}

func runRotationStatus(cmd *cobra.Command) error {
    ctx := cmd.Context()
    userID := ctx.Value(common.UserIDKey).(uuid.UUID)
    sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || sc == nil {
        return fmt.Errorf("service container not available in context")
    }
    rotSvc := sc.GetRotationService()

    due, err := rotSvc.GetDueRotations(ctx, userID)
    if err != nil {
        return fmt.Errorf("failed to get due rotations: %w", err)
    }
    reminders, err := rotSvc.GetUpcomingReminders(ctx, userID)
    if err != nil {
        return fmt.Errorf("failed to get upcoming reminders: %w", err)
    }
    policies, err := rotSvc.ListUserPolicies(ctx, userID)
    if err != nil {
        return fmt.Errorf("failed to list policies: %w", err)
    }

    fmt.Fprintln(cmd.OutOrStdout(), "Rotation Status")
    fmt.Fprintln(cmd.OutOrStdout(), "────────────────────────────────────────")
    if len(due) > 0 {
        fmt.Fprintln(cmd.OutOrStdout(), "Secrets due for rotation:")
        for _, d := range due {
            nextRotation := "Unknown"
            if d.NextRotationAt != nil {
                nextRotation = d.NextRotationAt.Format("2006-01-02")
            }
            fmt.Fprintf(cmd.OutOrStdout(), "  - Secret %s (next: %s)\n", d.SecretID.String()[:8]+"...", nextRotation)
        }
    } else {
        fmt.Fprintln(cmd.OutOrStdout(), "No secrets are currently due for rotation.")
    }
    if len(reminders) > 0 {
        fmt.Fprintln(cmd.OutOrStdout(), "\nUpcoming reminders:")
        for _, r := range reminders {
            fmt.Fprintf(cmd.OutOrStdout(), "  - Secret %s (%s reminder)\n", r.SecretID.String()[:8]+"...", r.ReminderType)
        }
    }
    if len(policies) > 0 {
        fmt.Fprintln(cmd.OutOrStdout(), "\nActive rotation policies:")
        for _, p := range policies {
            if p.Enabled {
                line := fmt.Sprintf("  - %s: every %d days", p.Name, p.IntervalDays)
                if p.AutoRotate {
                    line += " (auto-rotate enabled)"
                }
                fmt.Fprintln(cmd.OutOrStdout(), line)
            }
        }
    }
    return nil
}
```

Remove the imports `"rocketvault/internal/repositories"` and `"rocketvault/internal/logging"` and `"database/sql"`. Add `"rocketvault/internal/container"` and `"text/tabwriter"`. Remove `container.NewServiceContainer` call in `runRotationRotate` since we now use the context container.

- [ ] **Step 5: Run all rotation tests**

```bash
go test ./cmd/... -run TestRotation -v
```

Expected: `PASS`

- [ ] **Step 6: Run full test suite**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`.

- [ ] **Step 7: Commit**

```bash
git add cmd/rotation.go cmd/rotation_service_test.go cmd/testutils/test_utils.go
git commit -m "fix(cmd/rotation): all sub-commands use RotationService from context container"
```

---

## Task 9: Final verification

- [ ] **Step 1: Confirm no cmd file (except migrate.go) imports internal/db or constructs repositories directly**

```bash
grep -rn "rocketvault/internal/db\|rocketvault/internal/repositories\|repositories\.New" \
  /home/numericlabs/data/Golang/rocketvault/cmd/ \
  --include="*.go" | grep -v "_test.go" | grep -v "migrate"
```

Expected: **zero output**.

- [ ] **Step 2: Run the full test suite one final time**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok"
```

Expected: all `ok`, no `FAIL`.

- [ ] **Step 3: Verify the build is clean**

```bash
go build ./...
```

Expected: no output (clean build).

- [ ] **Step 4: Final commit**

```bash
git add .
git commit -m "chore: post-migration cleanup — all cmd files use service container"
```
