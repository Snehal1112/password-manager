# Certificate Import (PFX/PEM) & CSR Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a caller bring an externally-issued certificate into a vault — either a complete PFX/PEM cert+key bundle, or a CA-signed certificate completing a CSR the vault's own key generated — over both the CLI and the REST API.

**Architecture:** A new `internal/crypto/cert_import.go` holds pure parsing functions (`ParsePFX`, `ParsePEMBundle`) that turn caller-supplied bytes into a certificate PEM + private key PEM, using the new `go-pkcs12` dependency for PFX. `CertificateService.ImportCertificate` and `CertificateService.MergeCertificate` orchestrate: parse/validate, store the certificate the same way `CreateSelfSignedCertificate` already does, and — for import — also insert a linked `model.Key` row directly via the already-injected `KeyRepositoryInterface`, so every certificate keeps a meaningful `KeyID` the same as a generated one. CSR merge is a single-call operation (caller resupplies the CSR alongside the signed cert); there is no persisted pending-operation state.

**Tech Stack:** Go 1.24, `software.sslmate.com/src/go-pkcs12` (new dependency), Cobra, testify/mock.

**Spec:** `docs/superpowers/specs/2026-08-25-certificate-import-merge-design.md`

## Global Constraints

- New dependency: `software.sslmate.com/src/go-pkcs12` — Go's stdlib has no PKCS12 support.
- The import route is collection-level, `POST /certificates/import` (a new name is being created — matches Key Import's precedent). The merge route is sub-resource-shaped, `POST /certificates/{id}/pending/merge`, matching Azure's literal path.
- CSR merge is single-call only in v1 — no persisted pending-certificate-operation state (spec Design §2.1). Do not build pending-operation tracking as part of this plan.
- **Deviation from the design doc, made explicit here:** the design doc's Design §1.4 proposed reusing `KeyService.ImportKey` (from the sibling key-import plan) to create the linked `model.Key`. This plan instead has `CertificateService.ImportCertificate` insert the `model.Key` row directly via the `KeyRepositoryInterface` already injected into `CertificateServiceConfig` (`common.EncryptSecret`-encrypted PEM, matching exactly how `CreateSelfSignedCertificate` already stores a certificate's own `PrivateKey` field). Reasoning: no service in this codebase currently depends on another service (`internal/container/service_container.go` wires every service against repositories, never against a peer service) — introducing `CertificateService → KeyService` coupling for this one feature would be a bigger, unprecedented architectural change than the feature needs. **Consequence, stated plainly:** an imported certificate's linked key is always software-backed (`common.EncryptSecret`-encrypted PEM in `keys.value`), even when the target vault is HSM-configured — `CertificateService` has no `crypto.KeyProvider` to produce a PKCS#11 handle with. HSM-backed certificate-key import is out of scope for this plan; flag as a known v1 limitation if raised later.
- Follow existing conventions exactly: `internal/services/certificates/certificate_service.go`'s `CreateSelfSignedCertificate` shape, `cmd/certificates/create.go`'s CLI shape, `api/certificates.go`'s `createCertificate` handler shape.
- **This plan depends on nothing else being implemented first.** (The sibling key-import plan is not a prerequisite, per the deviation above.)

---

### Task 1: Add the `go-pkcs12` dependency and PFX/PEM parsing helpers

**Files:**
- Modify: `go.mod`, `go.sum` (new dependency)
- Create: `internal/crypto/cert_import.go`
- Test: `internal/crypto/cert_import_test.go`

**Interfaces:**
- Consumes: `software.sslmate.com/src/go-pkcs12`, stdlib `crypto/x509`, `encoding/pem`
- Produces: `func ParsePFX(pfxData []byte, password string) (certPEM string, keyPEM string, err error)` and `func ParsePEMBundle(certPEM, keyPEM []byte) (validatedCertPEM string, validatedKeyPEM string, err error)`, both in package `crypto` — consumed by Task 3 (`CertificateService.ImportCertificate`)

- [ ] **Step 1: Add the dependency**

Run: `go get software.sslmate.com/src/go-pkcs12@latest`
Expected: `go.mod`/`go.sum` gain the new module; `go build ./...` still succeeds (nothing references it yet).

- [ ] **Step 2: Write the failing tests**

```go
// internal/crypto/cert_import_test.go
package crypto_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
)

func makeTestCertAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-import"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, priv, der
}

func TestParsePFX_ValidWithPassphrase(t *testing.T) {
	cert, priv, _ := makeTestCertAndKey(t)
	pfxData, err := pkcs12.Encode(rand.Reader, priv, cert, nil, "test-passphrase")
	require.NoError(t, err)

	certPEM, keyPEM, err := crypto.ParsePFX(pfxData, "test-passphrase")
	require.NoError(t, err)
	assert.Contains(t, certPEM, "CERTIFICATE")
	assert.Contains(t, keyPEM, "PRIVATE KEY")

	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, cert.SerialNumber, parsedCert.SerialNumber)
}

func TestParsePFX_ValidNoPassphrase(t *testing.T) {
	cert, priv, _ := makeTestCertAndKey(t)
	pfxData, err := pkcs12.Encode(rand.Reader, priv, cert, nil, "")
	require.NoError(t, err)

	_, _, err = crypto.ParsePFX(pfxData, "")
	require.NoError(t, err)
}

func TestParsePFX_WrongPassphrase_ReturnsError(t *testing.T) {
	cert, priv, _ := makeTestCertAndKey(t)
	pfxData, err := pkcs12.Encode(rand.Reader, priv, cert, nil, "correct-passphrase")
	require.NoError(t, err)

	_, _, err = crypto.ParsePFX(pfxData, "wrong-passphrase")
	require.Error(t, err)
}

func TestParsePFX_CorruptData_ReturnsError(t *testing.T) {
	_, _, err := crypto.ParsePFX([]byte("not a pfx file"), "")
	require.Error(t, err)
}

func TestParsePEMBundle_Valid(t *testing.T) {
	cert, priv, certDER := makeTestCertAndKey(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	validatedCertPEM, validatedKeyPEM, err := crypto.ParsePEMBundle(certPEM, keyPEM)
	require.NoError(t, err)
	assert.Contains(t, validatedCertPEM, "CERTIFICATE")
	assert.Contains(t, validatedKeyPEM, "PRIVATE KEY")
	_ = cert
}

func TestParsePEMBundle_MismatchedKey_ReturnsError(t *testing.T) {
	_, _, certDER := makeTestCertAndKey(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKeyDER, err := x509.MarshalPKCS8PrivateKey(otherPriv)
	require.NoError(t, err)
	otherKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherKeyDER})

	_, _, err = crypto.ParsePEMBundle(certPEM, otherKeyPEM)
	require.Error(t, err)
}

func TestParsePEMBundle_InvalidCertPEM_ReturnsError(t *testing.T) {
	_, _, err := crypto.ParsePEMBundle([]byte("not pem"), []byte("also not pem"))
	require.Error(t, err)
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/crypto/... -run 'TestParsePFX|TestParsePEMBundle' -v`
Expected: FAIL — `crypto.ParsePFX`/`crypto.ParsePEMBundle` undefined (compile error).

- [ ] **Step 4: Write the implementation**

```go
// internal/crypto/cert_import.go
package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ParsePFX decodes a PFX/PKCS12 bundle into a certificate PEM and a private
// key PEM. password may be empty for an unencrypted PFX.
func ParsePFX(pfxData []byte, password string) (certPEM string, keyPEM string, err error) {
	privateKey, cert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return "", "", fmt.Errorf("decode pfx: %w", err)
	}

	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal pfx private key: %w", err)
	}
	keyBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}

	return string(pem.EncodeToMemory(certBlock)), string(pem.EncodeToMemory(keyBlock)), nil
}

// ParsePEMBundle validates a caller-supplied certificate PEM and private key
// PEM: both must parse, and the key's public component must match the
// certificate's. Returns the input unchanged (as strings) once validated, so
// callers can store exactly what they received.
func ParsePEMBundle(certPEM, keyPEM []byte) (validatedCertPEM string, validatedKeyPEM string, err error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return "", "", fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return "", "", fmt.Errorf("invalid private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", "", fmt.Errorf("unsupported private key type %T", key)
	}
	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("unsupported certificate public key type %T", cert.PublicKey)
	}
	if rsaKey.N.Cmp(certPub.N) != 0 || rsaKey.E != certPub.E {
		return "", "", fmt.Errorf("private key does not match certificate public key")
	}

	return string(certPEM), string(keyPEM), nil
}
```

Note: this v1 only supports RSA cert/key pairs for `ParsePEMBundle`'s ownership check — extend the type switch to `*ecdsa.PrivateKey`/`*ecdsa.PublicKey` in a follow-up if ECDSA certificate import is requested; RSA is the overwhelmingly common format for externally-issued TLS certificates, so this is a reasonable v1 scope cut, not an oversight.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/crypto/... -run 'TestParsePFX|TestParsePEMBundle' -v`
Expected: PASS, all seven tests.

- [ ] **Step 6: Run the full crypto package suite**

Run: `go build ./... && go test ./internal/crypto/... -v 2>&1 | tail -100`
Expected: no FAIL.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/crypto/cert_import.go internal/crypto/cert_import_test.go
git commit -m "feat(crypto): add ParsePFX and ParsePEMBundle for certificate import"
```

---

### Task 2: `CertificateService.ImportCertificate`

**Files:**
- Modify: `internal/services/certificates/certificate_service.go`
- Test: `internal/services/certificates/certificate_service_extended_test.go`

**Interfaces:**
- Consumes: `crypto.ParsePFX`/`ParsePEMBundle` (Task 1), `certificateService.applyCreatePurgeProtection` (`certificate_service.go:180`, existing — widened in Step 3 below), `extractExpiresAt` (`certificate_service.go:1063`, existing, package-private), `keyRepo.Create` (`KeyRepositoryInterface`, already injected via `CertificateServiceConfig.KeyRepository`)
- Produces: `CertificateService.ImportCertificate(ctx context.Context, req ImportCertificateRequest) (*CreateCertificateResult, error)` and `type ImportCertificateRequest struct{...}` / `type ImportCertificateFormat string` — consumed by Task 4 (retry decorator), Task 6 (API handler), Task 7 (CLI)

- [ ] **Step 1: Write the failing tests**

Locate the existing `mockCertRepository` (`internal/services/certificates/cert_soft_delete_test.go:27`) and a `mockKeyRepository`-equivalent for the certificates package (check whether one already exists in this package's test files — e.g. search `grep -rn "mockKeyRepo" internal/services/certificates/*_test.go`; if none exists, add a minimal one to `certificate_service_extended_test.go` matching `internal/services/keys/key_soft_delete_test.go`'s `mockKeyRepository` shape, implementing only `Create` for this test's purposes if the interface requires more, stub the rest to `panic("not implemented")` since these tests never call them).

Add to `internal/services/certificates/certificate_service_extended_test.go`:

```go
func TestImportCertificate_ValidPFX_Success(t *testing.T) {
	cert, priv, certDER := makeTestCertAndKeyForImport(t)
	pfxData, err := pkcs12.Encode(rand.Reader, priv, cert, nil, "test-pass")
	require.NoError(t, err)
	_ = certDER

	certRepo := &mockCertRepository{}
	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdCert = args.Get(1).(*model.Certificate) }).
		Return(nil)

	keyRepo := &mockCertImportKeyRepository{}
	var createdKey *model.Key
	keyRepo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:          keyRepo,
		Logger:                 newCertLogger(),
	})

	result, err := svc.ImportCertificate(context.Background(), ImportCertificateRequest{
		Name:          "imported-cert",
		Format:        ImportFormatPFX,
		PFX:           pfxData,
		PFXPassphrase: "test-pass",
		UserID:        uuid.New(),
	})
	require.NoError(t, err)
	assert.Equal(t, "imported-cert", result.Name)

	require.NotNil(t, createdCert)
	assert.Contains(t, createdCert.Certificate, "CERTIFICATE")
	assert.NotEmpty(t, createdCert.PrivateKey)
	assert.NotEqual(t, uuid.Nil, createdCert.KeyID)

	require.NotNil(t, createdKey)
	assert.Equal(t, createdCert.KeyID, createdKey.ID)
	assert.Equal(t, model.KeyTypeRSA, createdKey.Type)
	certRepo.AssertExpectations(t)
	keyRepo.AssertExpectations(t)
}

func TestImportCertificate_InvalidPFXPassphrase_Rejected(t *testing.T) {
	cert, priv, _ := makeTestCertAndKeyForImport(t)
	pfxData, err := pkcs12.Encode(rand.Reader, priv, cert, nil, "correct-pass")
	require.NoError(t, err)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: &mockCertRepository{},
		KeyRepository:          &mockCertImportKeyRepository{},
		Logger:                 newCertLogger(),
	})

	_, err = svc.ImportCertificate(context.Background(), ImportCertificateRequest{
		Name:          "bad-import",
		Format:        ImportFormatPFX,
		PFX:           pfxData,
		PFXPassphrase: "wrong-pass",
		UserID:        uuid.New(),
	})
	require.Error(t, err)
}

func TestImportCertificate_ValidPEM_Success(t *testing.T) {
	_, priv, certDER := makeTestCertAndKeyForImport(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	certRepo := &mockCertRepository{}
	certRepo.On("Create", mock.Anything, mock.Anything).Return(nil)
	keyRepo := &mockCertImportKeyRepository{}
	keyRepo.On("Create", mock.Anything, mock.Anything).Return(nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:          keyRepo,
		Logger:                 newCertLogger(),
	})

	result, err := svc.ImportCertificate(context.Background(), ImportCertificateRequest{
		Name:           "imported-pem-cert",
		Format:         ImportFormatPEM,
		PEMCertificate: certPEM,
		PEMPrivateKey:  keyPEM,
		UserID:         uuid.New(),
	})
	require.NoError(t, err)
	assert.Equal(t, "imported-pem-cert", result.Name)
}

func TestImportCertificate_MismatchedPEMPair_Rejected(t *testing.T) {
	_, _, certDER := makeTestCertAndKeyForImport(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKeyDER, err := x509.MarshalPKCS8PrivateKey(otherPriv)
	require.NoError(t, err)
	otherKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherKeyDER})

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: &mockCertRepository{},
		KeyRepository:          &mockCertImportKeyRepository{},
		Logger:                 newCertLogger(),
	})

	_, err = svc.ImportCertificate(context.Background(), ImportCertificateRequest{
		Name:           "mismatched",
		Format:         ImportFormatPEM,
		PEMCertificate: certPEM,
		PEMPrivateKey:  otherKeyPEM,
		UserID:         uuid.New(),
	})
	require.Error(t, err)
}

// makeTestCertAndKeyForImport mirrors internal/crypto/cert_import_test.go's
// makeTestCertAndKey -- duplicated here since this is a different package and
// the two test suites should not share a non-exported test helper across
// package boundaries.
func makeTestCertAndKeyForImport(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-import"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, priv, der
}

// mockCertImportKeyRepository is a minimal testify mock for
// KeyRepositoryInterface, covering only what ImportCertificate calls.
type mockCertImportKeyRepository struct {
	mock.Mock
}

func (m *mockCertImportKeyRepository) Create(ctx context.Context, key *model.Key) error {
	return m.Called(ctx, key).Error(0)
}
func (m *mockCertImportKeyRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) Update(ctx context.Context, key *model.Key, scope model.Scope) error {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) List(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) RecoverKey(ctx context.Context, id uuid.UUID) error {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) PurgeKey(ctx context.Context, id uuid.UUID) error {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	panic("not implemented for this test suite")
}
func (m *mockCertImportKeyRepository) ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	panic("not implemented for this test suite")
}
```

Before finalizing this step, run `go vet ./internal/services/certificates/...` once the mock is added and compare its method set against `internal/repositories/key_repository.go`'s full `KeyRepositoryInterface` (`key_repository.go:24-`, has more methods than `Create`/`Read`/`Update`/`List`/`Delete`/`UpdateRevocationStatus`/`SoftDelete`/`RecoverKey`/`PurgeKey`/`SetPurgeProtection`/`ReadDeleted` per the earlier research pass, e.g. `CreateVersion`) — add any remaining methods as `panic("not implemented for this test suite")` stubs so the mock fully satisfies the interface; the exact full method list must be read from the interface definition at implementation time since it may have grown since this plan was written.

Add missing imports to `certificate_service_extended_test.go`: `crypto/rand`, `crypto/rsa`, `crypto/x509`, `crypto/x509/pkix`, `encoding/pem`, `math/big`, `pkcs12 "software.sslmate.com/src/go-pkcs12"`, `"rocketvault/internal/repositories"` (if not already imported).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/services/certificates/... -run TestImportCertificate -v`
Expected: FAIL — `ImportCertificateRequest`, `ImportFormatPFX`, `svc.ImportCertificate` undefined (compile error).

- [ ] **Step 3: Widen `applyCreatePurgeProtection`**

Same reasoning as the key-import plan's Task 4 Step 4 — this function currently takes a full `CreateCertificateRequest` but only reads `PurgeProtection`. Change its signature in `internal/services/certificates/certificate_service.go` (`certificate_service.go:180`):

```go
func (s *certificateService) applyCreatePurgeProtection(ctx context.Context, purgeProtection *bool, certID uuid.UUID, action string, userID uuid.UUID) error {
	if purgeProtection == nil || !*purgeProtection {
		return nil
	}
	if err := s.certRepo.SetPurgeProtection(ctx, certID, true); err != nil {
		s.logger.LogAuditError(userID.String(), action, "failed", "failed to set purge protection", err)
		return fmt.Errorf("failed to set purge protection: %w", err)
	}
	return nil
}
```

Update the two existing call sites (`CreateSelfSignedCertificate`, `CreateCASignedCertificate`) from
`s.applyCreatePurgeProtection(ctx, req, cert.ID, "create_self_signed_cert")` to
`s.applyCreatePurgeProtection(ctx, req.PurgeProtection, cert.ID, "create_self_signed_cert", req.UserID)` (and the CA-signed equivalent).

- [ ] **Step 4: Add `ImportCertificateRequest`/`ImportCertificateFormat` and the interface method**

In `internal/services/certificates/certificate_service.go`, add next to `CreateCertificateRequest` (after its closing brace):

```go
// ImportCertificateFormat disambiguates which fields of
// ImportCertificateRequest are populated.
type ImportCertificateFormat string

const (
	ImportFormatPFX ImportCertificateFormat = "pfx"
	ImportFormatPEM ImportCertificateFormat = "pem"
)

// ImportCertificateRequest represents a request to import an externally-issued
// certificate. Format selects which field group is read: PFX+PFXPassphrase,
// or PEMCertificate+PEMPrivateKey.
type ImportCertificateRequest struct {
	Name            string
	Format          ImportCertificateFormat
	PFX             []byte
	PFXPassphrase   string
	PEMCertificate  []byte
	PEMPrivateKey   []byte
	Tags            []string
	UserID          uuid.UUID
	VaultID         uuid.UUID
	Enabled         *bool
	PurgeProtection *bool
}
```

In the `CertificateService` interface (after `CreateCASignedCertificate`, around line 92):

```go
	// ImportCertificate stores an externally-issued certificate and its
	// private key, supplied as either a PFX bundle or a separate PEM
	// cert/key pair. A linked model.Key is created for the imported private
	// key, stored as software-encrypted PEM (see this plan's Global
	// Constraints for why HSM-backed import is out of scope).
	ImportCertificate(ctx context.Context, req ImportCertificateRequest) (*CreateCertificateResult, error)
```

- [ ] **Step 5: Implement `certificateService.ImportCertificate`**

Add to `internal/services/certificates/certificate_service.go`, after `CreateCASignedCertificate`:

```go
// ImportCertificate stores an externally-issued certificate and its private
// key. Format selects PFX or PEM parsing; the result is stored exactly like a
// generated certificate -- a plaintext cert PEM and an
// common.EncryptSecret-encrypted key PEM -- and a linked model.Key row is
// created directly so KeyID stays meaningful, matching every other
// certificate-creation path.
func (s *certificateService) ImportCertificate(ctx context.Context, req ImportCertificateRequest) (*CreateCertificateResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"format":  req.Format,
		"user_id": req.UserID.String(),
	}).Info("Importing certificate")

	var certPEM, keyPEM string
	var err error
	switch req.Format {
	case ImportFormatPFX:
		certPEM, keyPEM, err = crypto.ParsePFX(req.PFX, req.PFXPassphrase)
	case ImportFormatPEM:
		certPEM, keyPEM, err = crypto.ParsePEMBundle(req.PEMCertificate, req.PEMPrivateKey)
	default:
		err = fmt.Errorf("unsupported import format: %q", req.Format)
	}
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_certificate", "failed", "failed to parse certificate material", err)
		return nil, fmt.Errorf("failed to parse certificate material: %w", err)
	}

	expiresAt, err := extractExpiresAt(certPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_certificate", "failed", "failed to parse certificate expiry", err)
		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
	}

	encryptedCertKey, err := common.EncryptSecret(keyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_certificate", "failed", "failed to encrypt private key", err)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}
	encryptedLinkedKey, err := common.EncryptSecret(keyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_certificate", "failed", "failed to encrypt linked key", err)
		return nil, fmt.Errorf("failed to encrypt linked key: %w", err)
	}

	vaultID := resolveVaultID(req.VaultID)

	linkedKey := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   vaultID,
		Name:      req.Name + "-imported-key",
		Type:      model.KeyTypeRSA,
		Value:     encryptedLinkedKey,
		CreatedAt: time.Now(),
		Enabled:   true,
	}
	if err := s.keyRepo.Create(ctx, linkedKey); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_certificate", "failed", "failed to store linked key", err)
		return nil, fmt.Errorf("failed to store linked key: %w", err)
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      req.UserID,
		VaultID:     vaultID,
		KeyID:       linkedKey.ID,
		Name:        req.Name,
		Certificate: certPEM,
		PrivateKey:  encryptedCertKey,
		CreatedAt:   time.Now(),
		Tags:        req.Tags,
		ExpiresAt:   expiresAt,
		RenewalDays: 30,
		Enabled:     enabled,
	}
	if err := s.certRepo.Create(ctx, cert); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_certificate", "failed", "failed to store certificate", err)
		return nil, fmt.Errorf("failed to store imported certificate: %w", err)
	}

	if err := s.applyCreatePurgeProtection(ctx, req.PurgeProtection, cert.ID, "import_certificate", req.UserID); err != nil {
		return nil, err
	}

	s.logger.LogAuditInfo(req.UserID.String(), "import_certificate", "success", fmt.Sprintf("certificate imported: %s, ID: %s", req.Name, cert.ID))

	return &CreateCertificateResult{
		CertID:    cert.ID,
		Name:      cert.Name,
		Tags:      cert.Tags,
		CreatedAt: cert.CreatedAt,
		ExpiresAt: expiresAt,
	}, nil
}
```

Note: `linkedKey.Type` is hardcoded to `model.KeyTypeRSA` because `ParsePEMBundle`'s v1 scope (Task 1) only validates RSA cert/key pairs — when ECDSA support is added to the parser, this must switch on the actual parsed key type too. Flag this coupling with a `// TODO` comment in the code so it isn't missed independently.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/services/certificates/... -run TestImportCertificate -v`
Expected: PASS, all four tests.

- [ ] **Step 7: Run the full certificates package suite**

Run: `go build ./... && go test ./internal/services/certificates/... -v 2>&1 | tail -150`
Expected: no FAIL (confirms the `applyCreatePurgeProtection` signature change didn't break `CreateSelfSignedCertificate`/`CreateCASignedCertificate`'s existing tests).

- [ ] **Step 8: Commit**

```bash
git add internal/services/certificates/certificate_service.go internal/services/certificates/certificate_service_extended_test.go
git commit -m "feat(certificates): add CertificateService.ImportCertificate"
```

---

### Task 3: Retry decorator + mock regeneration for `ImportCertificate`

**Files:**
- Modify: `internal/services/retry/retry_certificate_service.go`
- Modify (generated): `internal/services/certificates/mocks/mock_CertificateService.go`

**Interfaces:**
- Consumes: `certificates.CertificateService.ImportCertificate`/`ImportCertificateRequest` (Task 2)
- Produces: `retryCertificateService` satisfies the widened `RetryCertificateService`; `mocks.MockCertificateService` gains an `ImportCertificate` expecter

- [ ] **Step 1: Confirm the compile break**

Run: `go build ./... 2>&1 | grep -i retrycertificateservice`
Expected: a "does not implement certificates.CertificateService (missing method ImportCertificate)" error.

- [ ] **Step 2: Add the passthrough**

In `internal/services/retry/retry_certificate_service.go`, matching the existing `CreateSelfSignedCertificate` shape exactly:

```go
// ImportCertificate imports a certificate with retry logic for database operations.
func (s *retryCertificateService) ImportCertificate(ctx context.Context, req certificates.ImportCertificateRequest) (*certificates.CreateCertificateResult, error) {
	return retried(ctx, s.retryService, func() (*certificates.CreateCertificateResult, error) {
		return s.baseService.ImportCertificate(ctx, req)
	})
}
```

- [ ] **Step 3: Verify the build is unblocked**

Run: `go build ./... 2>&1`
Expected: no `retrycertificateservice`/`ImportCertificate` errors. Other packages (mocks, api, cmd) will still fail until later tasks.

- [ ] **Step 4: Regenerate the `CertificateService` mock**

Run: `mockery` from the repo root (`.mockery.yaml` already lists `CertificateService` under `rocketvault/internal/services/certificates`).

Verify: `git diff --stat internal/services/certificates/mocks/mock_CertificateService.go` shows only `ImportCertificate`-related additions.

- [ ] **Step 5: Run the retry package suite**

Run: `go test ./internal/services/retry/... -v 2>&1 | tail -60`
Expected: no FAIL.

- [ ] **Step 6: Commit**

```bash
git add internal/services/retry/retry_certificate_service.go internal/services/certificates/mocks/mock_CertificateService.go
git commit -m "feat(certificates): retry passthrough and regenerated mock for ImportCertificate"
```

---

### Task 4: Authorization — `ActionCertificatesImport` and `mapCertificateAction` case

**Files:**
- Modify: `model/azure_roles.go`
- Modify: `internal/services/authorization/data_actions.go`
- Test: `internal/services/authorization/data_actions_test.go`

**Interfaces:**
- Consumes: nothing new
- Produces: `model.ActionCertificatesImport`, `mapCertificateAction("POST", "import")` → `(model.ActionCertificatesImport, RouteVaultData)` — consumed by Task 6 (API route authorization)

- [ ] **Step 1: Write the failing test**

Add a row to `TestMapRouteToDataAction`'s table (`internal/services/authorization/data_actions_test.go`), in the "Certificates" section, next to `{"create certificate", ...}` (locate that exact row first — read the file's Certificates section before inserting, since its exact existing rows weren't captured verbatim in this plan's research pass):

```go
		{"import certificate", http.MethodPost, "/api/v1/certificates/import", model.ActionCertificatesImport, RouteVaultData},
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/authorization/... -run TestMapRouteToDataAction -v`
Expected: FAIL — `model.ActionCertificatesImport` undefined (compile error) until Step 3.

- [ ] **Step 3: Add the `ActionCertificatesImport` constant**

In `model/azure_roles.go`, near the existing `ActionCertificatesRestore` (around line 90-91):

```go
	// ActionCertificatesImport permits importing an externally-issued
	// certificate (PFX or PEM) as a new certificate.
	ActionCertificatesImport DataAction = "Microsoft.KeyVault/vaults/certificates/import/action"
```

Grant it to the same roles that hold `ActionCertificatesCreate` today — find both `RoleKeyVaultAdministrator`'s certificate block (around line 164-166) and `RoleKeyVaultCertificatesOfficer`'s block (around line 197-200) in the `azureRoleDataActions` map, and add `ActionCertificatesImport` to each list, e.g.:

```go
		ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
		ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
		ActionCertificatesRecover, ActionCertificatesPurge, ActionCertificatesImport,
```

(apply the same trailing addition to both role blocks — re-grep for `ActionCertificatesPurge,` to find both exact locations, since line numbers shift once Task-4-preceding edits land).

- [ ] **Step 4: Add the `mapCertificateAction` case**

In `internal/services/authorization/data_actions.go`, `mapCertificateAction` (`data_actions.go:213-`), add a case alongside the existing `case "restore":`, inside the top-level `switch rest` block:

```go
	case "import":
		if method == http.MethodPost {
			return model.ActionCertificatesImport, RouteVaultData
		}
		return "", RouteVaultData
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/services/authorization/... -run TestMapRouteToDataAction -v`
Expected: PASS.

- [ ] **Step 6: Run the full authorization suite and the roles test (role-grant changes touch it)**

Run: `go test ./internal/services/authorization/... -v 2>&1 | tail -100`
Expected: no FAIL. If `roles_test.go` asserts an exact action count/list per role, it will need updating for the two widened role grants — update it to include `ActionCertificatesImport` in both roles' expected sets.

- [ ] **Step 7: Commit**

```bash
git add model/azure_roles.go internal/services/authorization/data_actions.go internal/services/authorization/data_actions_test.go internal/services/authorization/roles_test.go
git commit -m "feat(authz): route POST /certificates/import to ActionCertificatesImport"
```

---

### Task 5: (reserved — intentionally skipped)

This task number is skipped: the original outline had a separate "add role grants" task, folded into Task 4 Step 3 since it's the same file and the same reviewable unit as the constant it grants (per the plan's Task Right-Sizing rule — don't split a task a reviewer would approve or reject as one piece).

---

### Task 6: API — `POST /certificates/import`

**Files:**
- Modify: `api/certificates.go`
- Modify: `api/certificates_test.go` (existing file — has the hand-rolled `mockCertService` (`api/certificates_test.go:44`), `newCertCtx(svc, claims)` (`:293`), and `certAdminClaims()` (`:304`) this task reuses)

**Interfaces:**
- Consumes: `certificates.CertificateService.ImportCertificate`/`ImportCertificateRequest` (Task 2)
- Produces: `POST /certificates/import` (both legacy and vault-scoped routers)

- [ ] **Step 1: Add `ImportCertificate` to `mockCertService`**

`api/certificates_test.go`'s `mockCertService` (`api/certificates_test.go:44-`) implements `certServices.CertificateService` by hand. Add, matching its `CreateSelfSignedCertificate` shape exactly:

```go
func (m *mockCertService) ImportCertificate(ctx context.Context, req certServices.ImportCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}
```

- [ ] **Step 2: Write the failing tests**

Add to `api/certificates_test.go`, next to `TestCreateCertificate_Success_Returns201` (`api/certificates_test.go:407`), reusing `newCertCtx` and `certAdminClaims()` exactly as that test does:

```go
func TestImportCertificate_Success_Returns201(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("ImportCertificate", mock.Anything, mock.MatchedBy(func(req certServices.ImportCertificateRequest) bool {
		return req.Name == "imported-cert"
	})).Return(&certServices.CreateCertificateResult{CertID: certID, Name: "imported-cert"}, nil)

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":           "imported-cert",
		"format":         "pfx",
		"pfx":            base64.StdEncoding.EncodeToString([]byte("fake-pfx-bytes")),
		"pfx_passphrase": "test-pass",
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates/import", bytes.NewReader(body))

	importCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

func TestImportCertificate_MissingName_Returns400(t *testing.T) {
	svc := &mockCertService{}
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "pfx"})
	r := httptest.NewRequest(http.MethodPost, "/certificates/import", bytes.NewReader(body))

	importCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "ImportCertificate", mock.Anything, mock.Anything)
}

func TestImportCertificate_UnsupportedFormat_Returns400(t *testing.T) {
	svc := &mockCertService{}
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "x", "format": "der"})
	r := httptest.NewRequest(http.MethodPost, "/certificates/import", bytes.NewReader(body))

	importCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./api/... -run TestImportCertificate -v`
Expected: FAIL — `importCertificate` undefined (compile error).

- [ ] **Step 4: Add the route, request type, and handler**

In `api/certificates.go`, add near `CreateCertificateAPIRequest` (find its exact name/location — the earlier research referenced it as `CreateCertificateAPIRequest`, confirm before inserting nearby):

```go
// ImportCertificateAPIRequest represents the request structure for importing
// a certificate from PFX or PEM material. Binary fields are base64-encoded
// JSON strings, matching Azure's own pkcs12 field convention.
type ImportCertificateAPIRequest struct {
	Name          string `json:"name"`
	Format        string `json:"format"` // "pfx" or "pem"
	PFX           string `json:"pfx,omitempty"`
	PFXPassphrase string `json:"pfx_passphrase,omitempty"`
	PEMCertificate string `json:"pem_certificate,omitempty"`
	PEMPrivateKey  string `json:"pem_private_key,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
	PurgeProtection *bool  `json:"purge_protection,omitempty"`
}
```

Add the route in `registerCertificateRoutes`, next to the existing `POST ""`:

```go
	c.Handle("", ApiSessionRequired(api.App, createCertificate)).Methods("POST")
	c.Handle("/import", ApiSessionRequired(api.App, importCertificate)).Methods("POST")
```

Add the handler, templated off `createCertificate`:

```go
// importCertificate imports a certificate from caller-supplied PFX or PEM material.
func importCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	// Authorization happens in PolicyMiddleware: importing a certificate
	// requires the Microsoft.KeyVault/vaults/certificates/import/action data
	// action, granted by Key Vault Certificates Officer or Administrator.

	var req ImportCertificateAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Name == "" {
		c.SetInvalidParam("name is required")
		return
	}

	var format certServices.ImportCertificateFormat
	var pfxBytes, pemCertBytes, pemKeyBytes []byte
	var err error
	switch req.Format {
	case "pfx":
		format = certServices.ImportFormatPFX
		pfxBytes, err = base64.StdEncoding.DecodeString(req.PFX)
		if err != nil {
			c.SetInvalidParam("pfx: invalid base64")
			return
		}
	case "pem":
		format = certServices.ImportFormatPEM
		pemCertBytes, err = base64.StdEncoding.DecodeString(req.PEMCertificate)
		if err != nil {
			c.SetInvalidParam("pem_certificate: invalid base64")
			return
		}
		pemKeyBytes, err = base64.StdEncoding.DecodeString(req.PEMPrivateKey)
		if err != nil {
			c.SetInvalidParam("pem_private_key: invalid base64")
			return
		}
	default:
		c.SetInvalidParam("format: must be pfx or pem")
		return
	}

	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	result, err := certService.ImportCertificate(r.Context(), certServices.ImportCertificateRequest{
		Name:            req.Name,
		Format:          format,
		PFX:             pfxBytes,
		PFXPassphrase:   req.PFXPassphrase,
		PEMCertificate:  pemCertBytes,
		PEMPrivateKey:   pemKeyBytes,
		Tags:            req.Tags,
		UserID:          userID,
		VaultID:         vaultID,
		Enabled:         req.Enabled,
		PurgeProtection: req.PurgeProtection,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	cert, err := certService.GetCertificate(r.Context(), result.CertID, model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(certToDomainResponse(cert)) //nolint:errcheck,gosec
}
```

`c.certSvc()` is the confirmed real accessor (`api/context.go:263`), mirroring `c.keySvc()`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./api/... -run TestImportCertificate -v`
Expected: PASS.

- [ ] **Step 6: Run the full API package suite**

Run: `go build ./... && go test ./api/... -v 2>&1 | tail -150`
Expected: no FAIL.

- [ ] **Step 7: Commit**

```bash
git add api/certificates.go api/certificates_test.go
git commit -m "feat(api): add POST /certificates/import"
```

---

### Task 7: CLI — `rocketvault certificates import`

**Files:**
- Create: `cmd/certificates/import.go`
- Modify: `cmd/certificates.go` (register the new command)
- Modify: `cmd/certificates/certs_cmd_test.go` (existing file — has `TestMain`'s Init registrations at `:30`, the hand-rolled `certCmdCertService` mock at `:44`, `certsTestContainer` at `:142`, `newCertLogger`/`newCertFmtr`/`viperSetCert`/`newCertCmd` helpers at `:154-207`, and `testutils.NewTestContext(t)` for a pre-wired vault-authorized container, used by `TestCertCreateCmd_SelfSignedSuccess` at `:314`)

**Interfaces:**
- Consumes: `certServices.ImportCertificateRequest`/`ImportCertificate` (Task 2), `vaultcli.RequireDataAction`, `model.ActionCertificatesImport`
- Produces: `rocketvault certificates import` command

- [ ] **Step 1: Add `ImportCertificate` to `certCmdCertService` and register `InitCertificatesImport`**

Add to `cmd/certificates/certs_cmd_test.go`'s `certCmdCertService` (`:44-`), matching its `CreateSelfSignedCertificate` shape:

```go
func (m *certCmdCertService) ImportCertificate(ctx context.Context, req certServices.ImportCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}
```

Register in `TestMain` (`cmd/certificates/certs_cmd_test.go:30-37`), next to `InitCertificatesCreate(parent)`:

```go
	InitCertificatesCreate(parent)
	InitCertificatesImport(parent)
```

- [ ] **Step 2: Write the failing tests**

Add to `cmd/certificates/certs_cmd_test.go`, next to `TestCertCreateCmd_MissingName`/`TestCertCreateCmd_SelfSignedSuccess` (`:254`, `:314`), reusing the exact same helpers those tests use:

```go
func TestCertImportCmd_MissingName(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-import-name": "", "cert-import-pfx-file": "/tmp/x.pfx",
	})
	defer cleanup()
	cmd, _ := newCertCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name is required")
}

func TestCertImportCmd_MissingFormatFlags(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-import-name": "imported-cert",
	})
	defer cleanup()
	cmd, _ := newCertCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "is required")
}

func TestCertImportCmd_BothFormatsGiven_MutuallyExclusive(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-import-name": "imported-cert", "cert-import-pfx-file": "/tmp/x.pfx",
		"cert-import-cert-file": "/tmp/x.pem", "cert-import-key-file": "/tmp/x.key",
	})
	defer cleanup()
	cmd, _ := newCertCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "mutually exclusive")
}

func TestCertImportCmd_PFXSuccess(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	result := &certServices.CreateCertificateResult{CertID: uuid.New(), Name: "imported-cert", CreatedAt: time.Now()}
	certSvc.On("ImportCertificate", mock.Anything, mock.MatchedBy(func(r certServices.ImportCertificateRequest) bool {
		return r.Name == "imported-cert" && r.VaultID == tc.TestVaultID && r.Format == certServices.ImportFormatPFX
	})).Return(result, nil)

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	tmpFile, err := os.CreateTemp(t.TempDir(), "test-*.pfx")
	require.NoError(t, err)
	_, err = tmpFile.Write([]byte("fake-pfx-bytes"))
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	cleanup := viperSetCert(map[string]interface{}{
		"cert-import-name": "imported-cert", "cert-import-pfx-file": tmpFile.Name(), "cert-import-pfx-passphrase-file": "",
	})
	defer cleanup()

	cmd, buf := newCertCmd(importCmd.RunE, nil)
	cmd.SetContext(ctx)
	err = cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}
```

`require` must already be imported in this file — if not, add `"github.com/stretchr/testify/require"`.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./cmd/certificates/... -run TestCertImportCmd -v`
Expected: FAIL — `InitCertificatesImport`, `importCmd` undefined (compile error).

- [ ] **Step 4: Implement `cmd/certificates/import.go`**

```go
/*
Copyright © 2025 Snehal Dangroshiya
... (same license header as cmd/certificates/create.go — copy verbatim)
*/

package certificates

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an externally-issued certificate",
	Long: `Import a certificate and its private key into the target vault, supplied
either as a PFX/PKCS12 bundle or as a separate PEM certificate and key. A
linked key is created for the imported private key, stored as encrypted PEM.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/import/action data action in the
target vault.

--name and exactly one of (--pfx-file) or (--cert-file and --key-file) are
required.`,
	Example: `  # Import a PFX bundle
  rocketvault certificates import --name <name> --pfx-file ./cert.pfx --pfx-passphrase-file ./pass.txt

  # Import a PEM cert + key pair
  rocketvault certificates import --name <name> --cert-file ./cert.pem --key-file ./key.pem`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "import_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		name := viper.GetString("cert-import-name")
		pfxFile := viper.GetString("cert-import-pfx-file")
		pfxPassphraseFile := viper.GetString("cert-import-pfx-passphrase-file")
		certFile := viper.GetString("cert-import-cert-file")
		keyFile := viper.GetString("cert-import-key-file")
		tagsStr := viper.GetString("cert-import-tags")

		if name == "" {
			log.LogAuditError(claims.UserID.String(), "import_certificate", "failed", "name is required", nil)
			return fmt.Errorf("name is required")
		}

		pfxGiven := pfxFile != ""
		pemGiven := certFile != "" || keyFile != ""
		if pfxGiven && pemGiven {
			return fmt.Errorf("--pfx-file and --cert-file/--key-file are mutually exclusive")
		}
		if !pfxGiven && !pemGiven {
			return fmt.Errorf("one of --pfx-file or --cert-file plus --key-file is required")
		}
		if pemGiven && (certFile == "" || keyFile == "") {
			return fmt.Errorf("both --cert-file and --key-file are required for PEM import")
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "import_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesImport, model.OpCreate)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "import_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to import certificate: %w", err)
		}

		req := certServices.ImportCertificateRequest{
			Name:    name,
			Tags:    tags,
			UserID:  claims.UserID,
			VaultID: vaultID,
		}

		if pfxGiven {
			pfxData, readErr := os.ReadFile(pfxFile)
			if readErr != nil {
				return fmt.Errorf("failed to read pfx file: %w", readErr)
			}
			req.Format = certServices.ImportFormatPFX
			req.PFX = pfxData
			if pfxPassphraseFile != "" {
				passData, readErr := os.ReadFile(pfxPassphraseFile)
				if readErr != nil {
					return fmt.Errorf("failed to read pfx passphrase file: %w", readErr)
				}
				req.PFXPassphrase = strings.TrimSpace(string(passData))
			}
		} else {
			certData, readErr := os.ReadFile(certFile)
			if readErr != nil {
				return fmt.Errorf("failed to read cert file: %w", readErr)
			}
			keyData, readErr := os.ReadFile(keyFile)
			if readErr != nil {
				return fmt.Errorf("failed to read key file: %w", readErr)
			}
			req.Format = certServices.ImportFormatPEM
			req.PEMCertificate = certData
			req.PEMPrivateKey = keyData
		}

		result, err := certService.ImportCertificate(ctx, req)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "import_certificate", "failed", fmt.Sprintf("failed to import certificate: %s", err), err)
			return fmt.Errorf("failed to import certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "import_certificate", "success", fmt.Sprintf("certificate imported: %s, ID: %s", result.Name, result.CertID))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Created"}
		row := []string{
			result.CertID.String(),
			result.Name,
			result.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitCertificatesImport initializes the import command for certificates.
func InitCertificatesImport(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(importCmd)

	importCmd.Flags().String("name", "", "Name for the imported certificate")
	importCmd.Flags().String("pfx-file", "", "Path to a PFX/PKCS12 bundle")
	importCmd.Flags().String("pfx-passphrase-file", "", "Path to a file containing the PFX passphrase")
	importCmd.Flags().String("cert-file", "", "Path to a PEM certificate")
	importCmd.Flags().String("key-file", "", "Path to a PEM private key")
	importCmd.Flags().String("tags", "", "Comma-separated tags for the certificate")
	viper.BindPFlag("cert-import-name", importCmd.Flags().Lookup("name"))                                     //nolint:errcheck,gosec
	viper.BindPFlag("cert-import-pfx-file", importCmd.Flags().Lookup("pfx-file"))                              //nolint:errcheck,gosec
	viper.BindPFlag("cert-import-pfx-passphrase-file", importCmd.Flags().Lookup("pfx-passphrase-file"))        //nolint:errcheck,gosec
	viper.BindPFlag("cert-import-cert-file", importCmd.Flags().Lookup("cert-file"))                            //nolint:errcheck,gosec
	viper.BindPFlag("cert-import-key-file", importCmd.Flags().Lookup("key-file"))                              //nolint:errcheck,gosec
	viper.BindPFlag("cert-import-tags", importCmd.Flags().Lookup("tags"))                                      //nolint:errcheck,gosec

	return certificatesCmd
}
```

Register it in `cmd/certificates.go`, next to `certificates.InitCertificatesCreate(certificatesCmd)`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/certificates/... -run TestCertImportCmd -v`
Expected: PASS.

- [ ] **Step 6: Run the full CLI certificates package suite**

Run: `go build ./... && go test ./cmd/certificates/... -v 2>&1 | tail -100`
Expected: no FAIL.

- [ ] **Step 7: Commit**

```bash
git add cmd/certificates/import.go cmd/certificates.go cmd/certificates/certs_cmd_test.go
git commit -m "feat(cli): add certificates import command"
```

---

### Task 8: `CertificateService.MergeCertificate`

**Files:**
- Modify: `internal/services/certificates/certificate_service.go`
- Test: `internal/services/certificates/certificate_service_extended_test.go`

**Interfaces:**
- Consumes: `certificateService.keyRepo.Read` (existing), `extractExpiresAt` (existing), `common.EncryptSecret`/`DecryptSecret` (existing)
- Produces: `CertificateService.MergeCertificate(ctx context.Context, req MergeCertificateRequest) (*CreateCertificateResult, error)` and `type MergeCertificateRequest struct{...}` — consumed by Task 10 (API), Task 11 (CLI)

- [ ] **Step 1: Write the failing tests**

```go
func TestMergeCertificate_MatchingPublicKey_Success(t *testing.T) {
	cert, priv, certDER := makeTestCertAndKeyForImport(t)
	_ = cert
	csrDER := makeTestCSR(t, priv)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	signedCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyID := uuid.New()
	userID := uuid.New()
	encryptedKeyPEM := encryptTestKeyPEM(t, priv)

	certRepo := &mockCertRepository{}
	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdCert = args.Get(1).(*model.Certificate) }).
		Return(nil)

	keyRepo := &mockCertImportKeyRepository{}
	keyRepo.On("Read", mock.Anything, keyID, mock.Anything).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedKeyPEM}, nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:          keyRepo,
		Logger:                 newCertLogger(),
	})

	result, err := svc.MergeCertificate(context.Background(), MergeCertificateRequest{
		Name:       "merged-cert",
		CSR:        csrPEM,
		SignedCert: signedCertPEM,
		KeyID:      keyID,
		UserID:     userID,
	})
	require.NoError(t, err)
	assert.Equal(t, "merged-cert", result.Name)
	require.NotNil(t, createdCert)
	assert.Equal(t, keyID, createdCert.KeyID)
	certRepo.AssertExpectations(t)
}

func TestMergeCertificate_MismatchedPublicKey_Rejected(t *testing.T) {
	_, csrPriv, _ := makeTestCertAndKeyForImport(t)
	csrDER := makeTestCSR(t, csrPriv)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	_, otherPriv, otherCertDER := makeTestCertAndKeyForImport(t)
	signedCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCertDER})

	keyID := uuid.New()
	userID := uuid.New()
	encryptedKeyPEM := encryptTestKeyPEM(t, otherPriv)

	keyRepo := &mockCertImportKeyRepository{}
	keyRepo.On("Read", mock.Anything, keyID, mock.Anything).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedKeyPEM}, nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: &mockCertRepository{},
		KeyRepository:          keyRepo,
		Logger:                 newCertLogger(),
	})

	_, err := svc.MergeCertificate(context.Background(), MergeCertificateRequest{
		Name:       "mismatched-merge",
		CSR:        csrPEM,
		SignedCert: signedCertPEM,
		KeyID:      keyID,
		UserID:     userID,
	})
	require.Error(t, err)
}

// makeTestCSR builds a CSR PEM-block-ready DER for priv's public key.
func makeTestCSR(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr-test"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	require.NoError(t, err)
	return der
}

// encryptTestKeyPEM mirrors how KeyService stores a software key: PEM then
// common.EncryptSecret. Requires setupKeyTestMasterKey-equivalent for this
// package -- call the certificates package's own master-key test setup if one
// exists (grep for a certificates-package equivalent of
// internal/services/keys/key_service_extended_test.go's
// setupKeyTestMasterKey before assuming this package needs its own copy).
func encryptTestKeyPEM(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	encrypted, err := common.EncryptSecret(string(pemBytes))
	require.NoError(t, err)
	return encrypted
}
```

If this package's tests don't already set a deterministic `master_key` via viper (check `certificate_service_extended_test.go`'s `TestMain` or a per-test setup), add a `setupCertTestMasterKey()` helper matching the keys package's `setupKeyTestMasterKey()` (`internal/services/keys/key_service_extended_test.go:32-38`) and call it at the top of both new tests.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/services/certificates/... -run TestMergeCertificate -v`
Expected: FAIL — `MergeCertificateRequest`, `svc.MergeCertificate` undefined (compile error).

- [ ] **Step 3: Add `MergeCertificateRequest` and the interface method**

```go
// MergeCertificateRequest represents a request to complete a certificate
// signing request with an externally-issued certificate. The supplied
// certificate's public key must match the supplied CSR's public key -- this
// substitutes for persisted pending-operation state; see
// docs/superpowers/specs/2026-08-25-certificate-import-merge-design.md
// Section 2.1.
type MergeCertificateRequest struct {
	Name       string
	CSR        []byte // the original CSR, PEM
	SignedCert []byte // the CA-signed certificate, PEM
	KeyID      uuid.UUID
	Tags       []string
	UserID     uuid.UUID
	VaultID    uuid.UUID
}
```

In the `CertificateService` interface, after `ImportCertificate`:

```go
	// MergeCertificate completes a certificate signing request with an
	// externally-issued certificate.
	MergeCertificate(ctx context.Context, req MergeCertificateRequest) (*CreateCertificateResult, error)
```

- [ ] **Step 4: Implement `certificateService.MergeCertificate`**

```go
// MergeCertificate completes a certificate signing request with an
// externally-issued certificate, verifying the two share a public key before
// storing. See MergeCertificateRequest's doc comment for why this substitutes
// for persisted pending-operation state.
func (s *certificateService) MergeCertificate(ctx context.Context, req MergeCertificateRequest) (*CreateCertificateResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"key_id":  req.KeyID.String(),
		"user_id": req.UserID.String(),
	}).Info("Merging certificate")

	csrBlock, _ := pem.Decode(req.CSR)
	if csrBlock == nil {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}

	certBlock, _ := pem.Decode(req.SignedCert)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid signed certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signed certificate: %w", err)
	}

	csrPub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported CSR public key type %T", csr.PublicKey)
	}
	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported certificate public key type %T", cert.PublicKey)
	}
	if csrPub.N.Cmp(certPub.N) != 0 || csrPub.E != certPub.E {
		s.logger.LogAuditError(req.UserID.String(), "merge_certificate", "failed", "signed certificate public key does not match CSR", nil)
		return nil, fmt.Errorf("signed certificate public key does not match CSR")
	}

	keyScope := model.NewVaultScope(resolveVaultID(req.VaultID), req.UserID)
	key, err := s.keyRepo.Read(ctx, req.KeyID, keyScope)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "merge_certificate", "failed", "failed to read key", err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	expiresAt, err := extractExpiresAt(string(req.SignedCert))
	if err != nil {
		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
	}

	certModel := &model.Certificate{
		ID:          uuid.New(),
		UserID:      req.UserID,
		VaultID:     resolveVaultID(req.VaultID),
		KeyID:       req.KeyID,
		Name:        req.Name,
		Certificate: string(req.SignedCert),
		PrivateKey:  key.Value, // already common.EncryptSecret-encrypted PEM
		CreatedAt:   time.Now(),
		Tags:        req.Tags,
		ExpiresAt:   expiresAt,
		RenewalDays: 30,
		Enabled:     true,
	}
	if err := s.certRepo.Create(ctx, certModel); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "merge_certificate", "failed", "failed to store merged certificate", err)
		return nil, fmt.Errorf("failed to store merged certificate: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "merge_certificate", "success", fmt.Sprintf("certificate merged: %s, ID: %s", req.Name, certModel.ID))

	return &CreateCertificateResult{
		CertID:    certModel.ID,
		Name:      certModel.Name,
		Tags:      certModel.Tags,
		CreatedAt: certModel.CreatedAt,
		ExpiresAt: expiresAt,
	}, nil
}
```

Note: like `ParsePEMBundle`, this v1 only handles RSA. Same rationale as Task 1 Step 4's note.

Add `"crypto/rsa"`, `"crypto/x509"`, `"encoding/pem"` to `certificate_service.go`'s import block if not already present (check first — `extractExpiresAt` already uses `encoding/pem`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/services/certificates/... -run TestMergeCertificate -v`
Expected: PASS.

- [ ] **Step 6: Run the full certificates package suite**

Run: `go build ./... && go test ./internal/services/certificates/... -v 2>&1 | tail -150`
Expected: no FAIL.

- [ ] **Step 7: Commit**

```bash
git add internal/services/certificates/certificate_service.go internal/services/certificates/certificate_service_extended_test.go
git commit -m "feat(certificates): add CertificateService.MergeCertificate"
```

---

### Task 9: Retry decorator + mock regeneration for `MergeCertificate`

**Files:**
- Modify: `internal/services/retry/retry_certificate_service.go`
- Modify (generated): `internal/services/certificates/mocks/mock_CertificateService.go`

**Interfaces:**
- Consumes: `certificates.CertificateService.MergeCertificate`/`MergeCertificateRequest` (Task 8)
- Produces: retry passthrough + regenerated mock

- [ ] **Step 1: Confirm the compile break**

Run: `go build ./... 2>&1 | grep -i retrycertificateservice`

- [ ] **Step 2: Add the passthrough**

```go
// MergeCertificate merges a certificate with retry logic for database operations.
func (s *retryCertificateService) MergeCertificate(ctx context.Context, req certificates.MergeCertificateRequest) (*certificates.CreateCertificateResult, error) {
	return retried(ctx, s.retryService, func() (*certificates.CreateCertificateResult, error) {
		return s.baseService.MergeCertificate(ctx, req)
	})
}
```

- [ ] **Step 3: Verify the build is unblocked**

Run: `go build ./... 2>&1`
Expected: no `retrycertificateservice`/`MergeCertificate` errors.

- [ ] **Step 4: Regenerate the mock**

Run: `mockery` from the repo root. Verify: `git diff --stat internal/services/certificates/mocks/mock_CertificateService.go` shows only `MergeCertificate`-related additions.

- [ ] **Step 5: Run the retry package suite**

Run: `go test ./internal/services/retry/... -v 2>&1 | tail -60`
Expected: no FAIL.

- [ ] **Step 6: Commit**

```bash
git add internal/services/retry/retry_certificate_service.go internal/services/certificates/mocks/mock_CertificateService.go
git commit -m "feat(certificates): retry passthrough and regenerated mock for MergeCertificate"
```

---

### Task 10: Authorization + API — `POST /certificates/{id}/pending/merge`

**Files:**
- Modify: `model/azure_roles.go`
- Modify: `internal/services/authorization/data_actions.go`
- Modify: `api/certificates.go`
- Test: `internal/services/authorization/data_actions_test.go`, `api/certificates_test.go`

**Interfaces:**
- Consumes: `certificates.CertificateService.MergeCertificate`/`MergeCertificateRequest` (Task 8)
- Produces: `model.ActionCertificatesMergePending`, `mapCertificateAction`'s new sub-resource case, `POST /certificates/{id}/pending/merge`

- [ ] **Step 1: Write the failing authorization test**

Add to `TestMapRouteToDataAction`'s table:

```go
		{"merge pending certificate", http.MethodPost, "/api/v1/certificates/abc/pending/merge", model.ActionCertificatesMergePending, RouteVaultData},
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/authorization/... -run TestMapRouteToDataAction -v`
Expected: FAIL — `model.ActionCertificatesMergePending` undefined (compile error).

- [ ] **Step 3: Add the `ActionCertificatesMergePending` constant and grants**

In `model/azure_roles.go`, next to `ActionCertificatesImport` (added in Task 4):

```go
	// ActionCertificatesMergePending permits completing a certificate
	// signing request with an externally-issued certificate.
	ActionCertificatesMergePending DataAction = "Microsoft.KeyVault/vaults/certificates/mergepending/action"
```

Grant it to the same two roles `ActionCertificatesImport` was granted to in Task 4.

- [ ] **Step 4: Add the `mapCertificateAction` case**

`mapCertificateAction` (`data_actions.go:213-`) already splits `rest` on `/` for two-segment sub-resource routes (the `len(seg) == 2` block handling `policy`/`backup`/`renew`). Add a three-segment case for `pending/merge`, since the full sub-resource path has two segments after the certificate ID (`pending`, `merge`) — read the function's exact `seg := strings.Split(rest, "/")` handling for `len(seg) == 2` first (already captured above: it switches on `seg[1]` when `len(seg) == 2`, meaning `rest` here is `"{id}/pending"`-shaped... clarify by checking how the caller strips the certificate ID before calling this function, since `rest` in `mapCertificateAction`'s existing two-segment cases is `"{id}/policy"` not `"policy"` alone — re-read `data_actions.go:213-260` in full at implementation time to get the exact segment-counting right, since this plan's earlier capture may not show every case boundary). Add:

```go
	if len(seg) == 3 && seg[1] == "pending" && seg[2] == "merge" {
		if method == http.MethodPost {
			return model.ActionCertificatesMergePending, RouteVaultData
		}
		return "", RouteVaultData
	}
```

(Adjust the segment count/indices to match whatever `rest`'s actual shape is once verified — the design intent is unambiguous: `POST .../pending/merge` → `ActionCertificatesMergePending`; the exact `seg[N]` indices depend on whether `rest` includes the certificate ID as its first segment, which must be confirmed against the live function body, not assumed from this plan's earlier partial capture.)

- [ ] **Step 5: Run the authorization test to verify it passes**

Run: `go test ./internal/services/authorization/... -run TestMapRouteToDataAction -v`
Expected: PASS.

- [ ] **Step 6: Write the failing API test**

```go
func TestMergeCertificate_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("MergeCertificate", mock.Anything, mock.MatchedBy(func(req certServices.MergeCertificateRequest) bool {
		return req.Name == "merged-cert"
	})).Return(&certServices.CreateCertificateResult{CertID: certID, Name: "merged-cert"}, nil)

	c := newCertCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":        "merged-cert",
		"csr":         base64.StdEncoding.EncodeToString([]byte("fake-csr-pem")),
		"signed_cert": base64.StdEncoding.EncodeToString([]byte("fake-cert-pem")),
		"key_id":      uuid.New().String(),
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates/"+certID.String()+"/pending/merge", bytes.NewReader(body))

	mergeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}
```

- [ ] **Step 7: Run the API test to verify it fails**

Run: `go test ./api/... -run TestMergeCertificate -v`
Expected: FAIL — `mergeCertificate` undefined (compile error).

- [ ] **Step 8: Add the route, request type, and handler**

In `api/certificates.go`, add to `registerCertificateRoutes`:

```go
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/pending/merge", ApiSessionRequired(api.App, mergeCertificate)).Methods("POST")
```

```go
// MergeCertificateAPIRequest represents the request structure for merging a
// CSR with an externally-issued certificate.
type MergeCertificateAPIRequest struct {
	Name       string `json:"name"`
	CSR        string `json:"csr"`         // base64-encoded PEM
	SignedCert string `json:"signed_cert"` // base64-encoded PEM
	KeyID      string `json:"key_id"`
	Tags       []string `json:"tags,omitempty"`
}

// mergeCertificate completes a certificate signing request with an
// externally-issued certificate.
func mergeCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	var req MergeCertificateAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Name == "" || req.CSR == "" || req.SignedCert == "" || req.KeyID == "" {
		c.SetInvalidParam("name, csr, signed_cert, and key_id are required")
		return
	}

	csrBytes, err := base64.StdEncoding.DecodeString(req.CSR)
	if err != nil {
		c.SetInvalidParam("csr: invalid base64")
		return
	}
	signedCertBytes, err := base64.StdEncoding.DecodeString(req.SignedCert)
	if err != nil {
		c.SetInvalidParam("signed_cert: invalid base64")
		return
	}
	keyID, err := uuid.Parse(req.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	result, err := certService.MergeCertificate(r.Context(), certServices.MergeCertificateRequest{
		Name:       req.Name,
		CSR:        csrBytes,
		SignedCert: signedCertBytes,
		KeyID:      keyID,
		Tags:       req.Tags,
		UserID:     userID,
		VaultID:    vaultID,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	cert, err := certService.GetCertificate(r.Context(), result.CertID, model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(certToDomainResponse(cert)) //nolint:errcheck,gosec
}
```

- [ ] **Step 9: Run the API test to verify it passes**

Run: `go test ./api/... -run TestMergeCertificate -v`
Expected: PASS.

- [ ] **Step 10: Run the full authorization and API suites**

Run: `go build ./... && go test ./internal/services/authorization/... ./api/... -v 2>&1 | tail -150`
Expected: no FAIL.

- [ ] **Step 11: Commit**

```bash
git add model/azure_roles.go internal/services/authorization/data_actions.go internal/services/authorization/data_actions_test.go api/certificates.go api/certificates_test.go
git commit -m "feat(api): add POST /certificates/{id}/pending/merge"
```

---

### Task 11: CLI — `rocketvault certificates merge`

**Files:**
- Create: `cmd/certificates/merge.go`
- Modify: `cmd/certificates.go`
- Modify: `cmd/certificates/certs_cmd_test.go`

**Interfaces:**
- Consumes: `certServices.MergeCertificateRequest`/`MergeCertificate` (Task 8), `vaultcli.RequireDataAction`, `model.ActionCertificatesMergePending`

- [ ] **Step 1: Add `MergeCertificate` to `certCmdCertService` and register `InitCertificatesMerge`**

Add to `certCmdCertService` (`cmd/certificates/certs_cmd_test.go:44-`):

```go
func (m *certCmdCertService) MergeCertificate(ctx context.Context, req certServices.MergeCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}
```

Register in `TestMain`, next to `InitCertificatesImport(parent)` (added in Task 7):

```go
	InitCertificatesImport(parent)
	InitCertificatesMerge(parent)
```

- [ ] **Step 2: Write the failing test**

```go
func TestCertMergeCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	result := &certServices.CreateCertificateResult{CertID: uuid.New(), Name: "merged-cert", CreatedAt: time.Now()}
	certSvc.On("MergeCertificate", mock.Anything, mock.MatchedBy(func(r certServices.MergeCertificateRequest) bool {
		return r.Name == "merged-cert" && r.VaultID == tc.TestVaultID
	})).Return(result, nil)

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	csrFile, err := os.CreateTemp(t.TempDir(), "test-*.csr")
	require.NoError(t, err)
	_, err = csrFile.WriteString("fake-csr-pem")
	require.NoError(t, err)
	require.NoError(t, csrFile.Close())

	certFile, err := os.CreateTemp(t.TempDir(), "test-*.cert")
	require.NoError(t, err)
	_, err = certFile.WriteString("fake-signed-cert-pem")
	require.NoError(t, err)
	require.NoError(t, certFile.Close())

	keyID := uuid.New()
	cleanup := viperSetCert(map[string]interface{}{
		"cert-merge-name": "merged-cert", "cert-merge-csr-file": csrFile.Name(),
		"cert-merge-cert-file": certFile.Name(), "cert-merge-key-id": keyID.String(),
	})
	defer cleanup()

	cmd, buf := newCertCmd(mergeCmd.RunE, nil)
	cmd.SetContext(ctx)
	err = cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./cmd/certificates/... -run TestMergeCertCmd -v`
Expected: FAIL — `mergeCmd` undefined (compile error).

- [ ] **Step 4: Implement `cmd/certificates/merge.go`**

```go
/*
Copyright © 2025 Snehal Dangroshiya
... (same license header — copy verbatim from cmd/certificates/create.go)
*/

package certificates

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

var mergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Complete a CSR with an externally-issued certificate",
	Long: `Complete a certificate signing request by supplying both the original CSR
and the CA-signed certificate together. The signed certificate's public key
must match the CSR's public key. There is no persisted pending-request state
-- both pieces must be supplied in this one call.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/mergepending/action data action in
the target vault.

--name, --csr-file, --cert-file, and --key-id are all required.`,
	Example: `  rocketvault certificates merge --name <name> --csr-file ./req.csr \
    --cert-file ./signed.pem --key-id <key-id>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "merge_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		name := viper.GetString("cert-merge-name")
		csrFile := viper.GetString("cert-merge-csr-file")
		certFile := viper.GetString("cert-merge-cert-file")
		keyIDStr := viper.GetString("cert-merge-key-id")
		tagsStr := viper.GetString("cert-merge-tags")

		if name == "" || csrFile == "" || certFile == "" || keyIDStr == "" {
			log.LogAuditError(claims.UserID.String(), "merge_certificate", "failed", "name, csr-file, cert-file, and key-id are required", nil)
			return fmt.Errorf("name, csr-file, cert-file, and key-id are required")
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			return fmt.Errorf("invalid key ID: %w", err)
		}

		csrData, err := os.ReadFile(csrFile)
		if err != nil {
			return fmt.Errorf("failed to read csr file: %w", err)
		}
		certData, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("failed to read cert file: %w", err)
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesMergePending, model.OpCreate)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "merge_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to merge certificate: %w", err)
		}

		result, err := certService.MergeCertificate(ctx, certServices.MergeCertificateRequest{
			Name:       name,
			CSR:        csrData,
			SignedCert: certData,
			KeyID:      keyID,
			Tags:       tags,
			UserID:     claims.UserID,
			VaultID:    vaultID,
		})
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "merge_certificate", "failed", fmt.Sprintf("failed to merge certificate: %s", err), err)
			return fmt.Errorf("failed to merge certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "merge_certificate", "success", fmt.Sprintf("certificate merged: %s, ID: %s", result.Name, result.CertID))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Created"}
		row := []string{
			result.CertID.String(),
			result.Name,
			result.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitCertificatesMerge initializes the merge command for certificates.
func InitCertificatesMerge(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(mergeCmd)

	mergeCmd.Flags().String("name", "", "Name for the merged certificate")
	mergeCmd.Flags().String("csr-file", "", "Path to the original CSR (PEM)")
	mergeCmd.Flags().String("cert-file", "", "Path to the CA-signed certificate (PEM)")
	mergeCmd.Flags().String("key-id", "", "UUID of the vault key that generated the CSR")
	mergeCmd.Flags().String("tags", "", "Comma-separated tags for the certificate")
	viper.BindPFlag("cert-merge-name", mergeCmd.Flags().Lookup("name"))         //nolint:errcheck,gosec
	viper.BindPFlag("cert-merge-csr-file", mergeCmd.Flags().Lookup("csr-file")) //nolint:errcheck,gosec
	viper.BindPFlag("cert-merge-cert-file", mergeCmd.Flags().Lookup("cert-file")) //nolint:errcheck,gosec
	viper.BindPFlag("cert-merge-key-id", mergeCmd.Flags().Lookup("key-id"))     //nolint:errcheck,gosec
	viper.BindPFlag("cert-merge-tags", mergeCmd.Flags().Lookup("tags"))         //nolint:errcheck,gosec

	return certificatesCmd
}
```

Register in `cmd/certificates.go`, next to `InitCertificatesImport`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./cmd/certificates/... -run TestMergeCertCmd -v`
Expected: PASS.

- [ ] **Step 6: Run the full CLI certificates package suite**

Run: `go build ./... && go test ./cmd/certificates/... -v 2>&1 | tail -100`
Expected: no FAIL.

- [ ] **Step 7: Commit**

```bash
git add cmd/certificates/merge.go cmd/certificates.go cmd/certificates/certs_cmd_test.go
git commit -m "feat(cli): add certificates merge command"
```

---

### Task 12: Full build/test verification and documentation flip

**Files:**
- Modify: `.claude/azure-keyvault-parity.md`
- Modify: `.claude/roadmap-azure-parity-and-beyond.md`
- Modify: `README.md`
- Modify: `docs/cli-guide.md`
- Modify: `docs/api-developer-guide.md`
- Modify: `docs/integration-examples.md`

- [ ] **Step 1: Full build and test suite**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | tail -150`
Expected: builds clean, `go vet` clean, no FAIL anywhere.

- [ ] **Step 2: Flip the parity doc's two certificate rows**

In `.claude/azure-keyvault-parity.md` §4 (the "Import certificate (PFX/PEM)" and "Merge CSR (pending certificate)" rows added 2026-08-25): flip "Import certificate" to ✅, describing the shipped `POST /certificates/import`. Flip "Merge CSR" to 🟡 (not ✅ — this plan's v1 is single-call merge, not Azure's full pending-operation lifecycle), describing `POST /certificates/{id}/pending/merge` and citing the Section 2.1 scope decision inline.

- [ ] **Step 3: Update the Scorecard**

Move "§4. Certificate management" from `5 | 0 | 4 | 0` to `6 | 1 | 2 | 0` (one row ❌→✅, one row ❌→🟡). Update the Total row and the "genuinely closable ❌ rows" sentence to drop "certificate import" and "CSR merge" from that list (CSR merge stays 🟡, not fully closed, so consider whether it belongs in a "partially closable" note instead — use judgment here based on how the doc phrases other 🟡-parity items elsewhere).

- [ ] **Step 4: Mark the roadmap item closed**

In `.claude/roadmap-azure-parity-and-beyond.md` Phase 1, mark "Certificate import (PFX/PEM) & CSR merge" closed, noting the CSR-merge scope reduction inline (don't claim full parity there either).

- [ ] **Step 5: Update README's roadmap checklist**

Change `- [ ] Certificate import (PFX/PEM) / CSR merge` to `- [x]` in `README.md`'s Phase 1 checklist.

- [ ] **Step 6: Update the CLI, API, and integration-examples docs**

Add `certificates import` and `certificates merge` to `docs/cli-guide.md`. Add both new endpoints to `docs/api-developer-guide.md`. Add at least one worked PFX-import example to `docs/integration-examples.md` — per `.claude/known-bugs.md` § B51's lesson, examples drift independently of the guide doc, so update both.

- [ ] **Step 7: Commit**

```bash
git add .claude/azure-keyvault-parity.md .claude/roadmap-azure-parity-and-beyond.md README.md docs/cli-guide.md docs/api-developer-guide.md docs/integration-examples.md
git commit -m "docs: mark certificate import/merge shipped"
```
