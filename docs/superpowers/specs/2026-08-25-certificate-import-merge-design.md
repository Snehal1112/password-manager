# Certificate Import (PFX/PEM) & CSR Merge — Design

**Date**: 2026-08-25
**Status**: Proposed
**Scope**: `model/azure_roles.go`, `internal/services/authorization/data_actions.go`,
`internal/services/certificates/certificate_service.go`, `api/certificates.go`,
`cmd/certificates/import.go` (new), `cmd/certificates/merge.go` (new),
`internal/services/certificates/mocks/mock_CertificateService.go` (generated),
`go.mod` (new dependency: `software.sslmate.com/src/go-pkcs12`)
**Branch target**: v-4.0.0
**Source finding**: gap-audit review of the secrets/keys/certificates
import-export asymmetry — this gap has **no existing tracking**: no row in
`.claude/azure-keyvault-parity.md` §4 (7 rows today, lines 217-225, none for
import/merge), no roadmap line, no known-bugs entry.

**Dependency on another spec**: this doc's certificate-import path
(§ Design, Section 1.4) links each imported certificate to a `model.Key` by
calling `KeyService.ImportKey`, defined in
[2026-08-25-key-import-jwk-design.md](2026-08-25-key-import-jwk-design.md).
**Sequence that doc's implementation before this one's Section 1**, or this doc's
implementer will need to duplicate PEM-to-`model.Key` storage logic — not
recommended, since duplicating the `isPKCS11Handle`/`common.EncryptSecret` branch
in two places is exactly the kind of drift risk `.claude/known-bugs.md` catalogs
repeatedly for this codebase. CSR merge (Section 2) has no such dependency and
can land independently.

---

## Problem

Azure Key Vault supports two distinct ways to bring externally-issued certificate
material into a vault:

- `POST /certificates/{name}/import` — upload a complete PFX or PEM bundle
  (cert + private key), for migrating certificates issued elsewhere.
- `POST /certificates/{name}/pending/merge` — complete a certificate signing
  request the vault itself generated, once an external CA has signed it.

RocketVault has neither. Unlike key import
([2026-08-25-key-import-jwk-design.md](2026-08-25-key-import-jwk-design.md)),
which is at least *declared* in the authorization model and tracked in both the
parity doc and the roadmap, certificate import/merge is invisible everywhere:
`.claude/azure-keyvault-parity.md` §4 has exactly seven rows (create, get/list/
update/delete, policy, auto-renewal, backup/restore, public-CA integration,
ACME) and none of them is import or merge; `.claude/roadmap-azure-parity-and-beyond.md`
never mentions either; `.claude/known-bugs.md` has no entry for it. This is a
real Azure capability with no RocketVault equivalent and no record that anyone
decided not to build it — this doc closes that gap in tracking as well as in code.

## Non-goals

- No public-CA/ACME integration — that's a separately tracked ❌ in the parity
  doc (`.claude/azure-keyvault-parity.md:224-225`, "Public-CA integration" and
  "ACME / external CA enrollment"). Import/merge bring in certificates issued
  *outside* RocketVault by any means; they don't add a new issuance channel.
- No change to `CreateSelfSignedCertificate`/`CreateCASignedCertificate`'s
  existing flows.
- No full pending-certificate-operation lifecycle (create CSR via the vault,
  walk away, merge later without resupplying anything) — see the explicit scope
  decision in Section 2.1.

## Design

### Section 1 — Certificate import (PFX/PEM)

#### 1.1 New dependency: `software.sslmate.com/src/go-pkcs12`

Go's standard library has no PKCS12 support (confirmed: `pkcs12`/`PKCS12` do not
appear in `go.mod`/`go.sum` today — the only existing hit anywhere in the
codebase is the unrelated string `"application/x-pkcs12"` used as an allowed
content-type value for generic secrets,
`internal/services/secrets/secret_service.go:79`). Add
`software.sslmate.com/src/go-pkcs12` as a new direct dependency — it only
decodes/encodes PFX containers; PEM parsing stays on stdlib
`encoding/pem`/`crypto/x509`, unchanged.

#### 1.2 Storage boundary

`model.Certificate` (`model/certificate.go:11-34`) has no PFX/DER field and gets
none — PFX↔PEM conversion happens entirely at the service layer, on entry to the
new import method. The PFX is decoded via `pkcs12.Decode`/`DecodeChain` into an
`*x509.Certificate` + `crypto.PrivateKey` (+ chain), immediately PEM-encoded, and
stored exactly like `CreateSelfSignedCertificate` already stores a generated
cert (`certificate_service.go:202-321`): the `Certificate` field
(`model/certificate.go:22`) gets the leaf cert's PEM, the `PrivateKey` field
(`model/certificate.go:23`) gets `common.EncryptSecret`-wrapped private-key PEM.
No new DB column.

#### 1.3 `CertificateService.ImportCertificate`

`CertificateService` (`certificate_service.go:91-123`) has no import/export
methods today — this is greenfield. Add:

```go
type CertificateService interface {
	CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	// ImportCertificate stores an externally-issued certificate and its
	// private key, supplied as either a PFX bundle or a separate PEM
	// cert/key pair, disambiguated by req.Format.
	ImportCertificate(ctx context.Context, req ImportCertificateRequest) (*CreateCertificateResult, error)

	GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error)
	// ... rest unchanged
}
```

New request type, next to `CreateCertificateRequest` (`certificate_service.go:34-54`):

```go
// ImportCertificateFormat disambiguates which fields of ImportCertificateRequest
// are populated. Explicit, not sniffed — a mismatched upload fails loudly
// against the declared format rather than being guessed at.
type ImportCertificateFormat string

const (
	ImportFormatPFX ImportCertificateFormat = "pfx"
	ImportFormatPEM ImportCertificateFormat = "pem"
)

// ImportCertificateRequest represents a request to import an externally-issued
// certificate. Format selects which of the two field groups below is read:
// PFX+PFXPassphrase, or PEMCertificate+PEMPrivateKey.
type ImportCertificateRequest struct {
	Name           string
	Format         ImportCertificateFormat
	PFX            []byte
	PFXPassphrase  string // optional; empty means the PFX is unencrypted
	PEMCertificate []byte
	PEMPrivateKey  []byte
	Tags           []string
	UserID         uuid.UUID
	VaultID        uuid.UUID
	Enabled        *bool
	PurgeProtection *bool
}
```

**Format decision**: an explicit `Format` field, not content-sniffing. PFX is
binary/DER-derived and PEM is ASCII, so sniffing is easy to get right most of the
time — but "most of the time" is the wrong bar for a security-relevant upload
endpoint; an explicit field fails loudly on a mismatched upload (wrong flag, wrong
file) instead of guessing and either erroring confusingly deep in a decoder or,
worse, silently misparsing.

#### 1.4 Key linkage

Unlike `CreateSelfSignedCertificate`, which generates its own `model.Key` and
sets `Certificate.KeyID` to point at it, an imported certificate brings its own
private key. **Decision: `ImportCertificate` also creates a linked `model.Key`**,
by calling `KeyService.ImportKey` (from
[2026-08-25-key-import-jwk-design.md](2026-08-25-key-import-jwk-design.md)) with
the certificate's private key, and stores the returned key ID as
`Certificate.KeyID`. This keeps every certificate's `KeyID` FK meaningful — the
same invariant every other certificate-creation path maintains — and makes the
imported key independently usable for future operations (e.g. a subsequent
`RenewCertificate` call), rather than leaving `KeyID` pointing at nothing or
requiring certificate code to special-case a keyless certificate everywhere else
it appears.

#### 1.5 Authorization

No `ActionCertificatesImport` constant exists today (confirmed: grep of
`model/azure_roles.go` for `ActionCertificates` finds `Read`, `Create`, `Update`,
`Delete`, `Backup`, `Restore`, `Recover`, `Purge` — no `Import`/`Export`/`Merge`).
Add it near the existing `ActionCertificatesRestore` (`model/azure_roles.go:88-91`):

```go
// ActionCertificatesImport permits importing an externally-issued certificate
// (PFX or PEM) as a new certificate.
ActionCertificatesImport DataAction = "Microsoft.KeyVault/vaults/certificates/import/action"
```

Grant it to the same roles that hold `ActionCertificatesCreate` today —
`RoleKeyVaultAdministrator` (`model/azure_roles.go:155-166`) and
`RoleKeyVaultCertificatesOfficer` (`model/azure_roles.go:196-200`).

`mapCertificateAction` (`internal/services/authorization/data_actions.go:213`,
confirmed already exists — it follows the identical `switch rest` /
`strings.Split` shape as `mapKeyAction`) gets a new case, at the same
collection-level resolution as key import
([2026-08-25-key-import-jwk-design.md](2026-08-25-key-import-jwk-design.md)
Design §7) and for the same reason — a new name is being created, not an
existing one modified:

```go
case "import":
	if method == http.MethodPost {
		return model.ActionCertificatesImport, RouteVaultData
	}
	return "", RouteVaultData
```

#### 1.6 API

`registerCertificateRoutes` (`api/certificates.go:103-113`) gets a new route
alongside the existing `POST ""` create route:

```go
c.Handle("/import", ApiSessionRequired(api.App, importCertificate)).Methods("POST")
```

New `importCertificate` handler, templated off `createCertificate`
(`api/certificates.go:132-`): decode a JSON body carrying `format` +
(`pfx`/`pfx_passphrase` or `pem_certificate`/`pem_private_key`, all binary
fields base64-encoded — this matches Azure's own `pkcs12` base64-field
convention on its import endpoint, and keeps this API's plain-JSON style
consistent rather than introducing multipart just for this one route), resolve
`vaultID`, call `certService.ImportCertificate(...)`, respond `201` with the
same `CertificateResponse` shape `createCertificate` returns (via
`certToDomainResponse`, `api/certificates.go:118-130`).

#### 1.7 CLI — `cmd/certificates/import.go`

Template off `cmd/certificates/create.go`'s claims/role-gate and
`vaultcli.RequireDataAction` pattern (see
[2026-08-25-key-import-jwk-design.md](2026-08-25-key-import-jwk-design.md)
Design §9 for the exact shape this follows). New flags:
`--pfx-file`/`--pfx-passphrase-file` as one pair, `--cert-file`/`--key-file` as
the other, mutually exclusive — `--format` is inferred from which pair is set
(exactly one pair must be present; both or neither is a usage error surfaced
before any network call).

### Section 2 — CSR merge

#### 2.1 Scope decision: single-call merge, no pending-operation tracking (v1)

**Decision, stated explicitly rather than left implicit**: v1 CSR merge is a
single-call operation. The caller supplies the original CSR (or a reference to
the key that generated it) together with the CA-signed certificate in one
request; RocketVault verifies the two belong together and stores the result.
There is no persisted "pending certificate operation" state — no "create a CSR
via the vault, walk away, come back days later and merge with nothing but a
name" workflow, which is what Azure's full model supports.

Reasoning: `CertificateService`'s complete existing method list
(`CreateSelfSignedCertificate`, `CreateCASignedCertificate`, `GetCertificate`,
`ListCertificates`, `UpdateCertificate`, `DeleteCertificate`,
`RenewCertificate`, `ListDeletedCertificates`, `RecoverCertificate`,
`PurgeCertificate`, `ValidateCertificateAccess`, `ValidateKeyOwnership`,
`GetCertificatePolicy`, `UpsertCertificatePolicy`, `DeleteCertificatePolicy` —
`certificate_service.go:91-123`) has zero pending-operation/CSR-tracking
concept anywhere today. Building one means a new table, a new repository, new
lifecycle states, new soft-delete/purge interactions, and its own authorization
actions for the pending-operation's own CRUD — a multi-week feature in its own
right, disproportionate to "add merge," and one that would double this doc's
length past the house style's ~300-450 line norm.

The public-key-match check substitutes for persisted state: comparing the
supplied CSR's public key against the supplied CA-signed certificate's public
key is a stateless verification that the two pieces genuinely belong together,
sufficient for correctness without a database remembering "this CSR was issued
and is waiting."

**This reduces parity to 🟡, not ✅**, relative to Azure's full pending-operation
model — say so explicitly in the parity-doc row this doc's Documentation section
adds, with a footnote citing this decision, so a future reader doesn't have to
re-derive the scope reduction from this doc's prose. If real demand later
justifies the full model, it's a clean, separately-scoped follow-up spec (its
own file, citing this footnote as its source finding) — far easier to add later
than to retrofit if v1 had been forced to build throwaway pending-state
infrastructure now.

#### 2.2 `CertificateService.MergeCertificate`

```go
// MergeCertificate completes a certificate signing request with an
// externally-issued certificate. The supplied certificate's public key must
// match the supplied CSR's public key — this substitutes for persisted
// pending-operation state; see docs/superpowers/specs/
// 2026-08-25-certificate-import-merge-design.md Section 2.1.
MergeCertificate(ctx context.Context, req MergeCertificateRequest) (*CreateCertificateResult, error)
```

```go
type MergeCertificateRequest struct {
	Name        string // name for the resulting certificate
	CSR         []byte // the original CSR (PEM)
	SignedCert  []byte // the CA-signed certificate (PEM)
	KeyID       uuid.UUID // the vault key that generated the CSR — its private key becomes the merged certificate's PrivateKey
	Tags        []string
	UserID      uuid.UUID
	VaultID     uuid.UUID
}
```

Implementation: parse `CSR` and extract its public key; parse `SignedCert` and
extract its public key; compare — mismatch is a hard rejection, not a warning.
On match, read `KeyID`'s stored (encrypted) private key, and store via the same
path `CreateCASignedCertificate` uses (`certificate_service.go:334-511`) —
`Certificate` field gets `SignedCert`'s PEM, `PrivateKey` field gets the
existing key's already-encrypted PEM (no new encryption needed; it's already in
the right form).

#### 2.3 Authorization

New constant, same block as `ActionCertificatesImport` (§1.5):

```go
// ActionCertificatesMergePending permits completing a certificate signing
// request with an externally-issued certificate.
ActionCertificatesMergePending DataAction = "Microsoft.KeyVault/vaults/certificates/mergepending/action"
```

Granted to the same roles as `ActionCertificatesImport`. Unlike import, the
route shape here has no ambiguity to resolve — Azure's own route,
`POST /certificates/{name}/pending/merge`, is sub-resource-shaped, so
`mapCertificateAction` gets a case matching it exactly:

```go
if len(seg) == 2 && seg[0] == "pending" && seg[1] == "merge" && method == http.MethodPost {
	return model.ActionCertificatesMergePending, RouteVaultData
}
```

(Exact `seg` indexing to be confirmed against `mapCertificateAction`'s real
`strings.Split` structure at implementation time — the case shown here follows
`mapKeyAction`'s established two-segment sub-resource pattern,
`data_actions.go:169-201`.)

#### 2.4 API + CLI

`api/certificates.go`: new route
`c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/pending/merge", ApiSessionRequired(api.App, mergeCertificate)).Methods("POST")`
in `registerCertificateRoutes`, new handler templated off `createCertificate`.

`cmd/certificates/merge.go`: new CLI command, `--csr-file`, `--cert-file`
(the signed cert), `--key-id` (the vault key that generated the CSR), same
authz-gate pattern as import.

## Testing

Locate and follow the existing `CertificateService` test file's mock/table
pattern first (not yet identified in this doc's research pass — this is the
first task for whoever implements it, following the same general shape as
`internal/services/keys/key_service_extended_test.go` and
`internal/services/secrets`' test conventions).

Cases:
- Valid PFX import, with and without a passphrase.
- Invalid/corrupt PFX rejected before any storage write.
- Valid PEM cert+key import.
- Mismatched PEM cert/key pair rejected (public key in cert doesn't match key).
- Import creates a linked `model.Key` with a populated `KeyID` (verifies §1.4).
- Merge with matching CSR/cert public keys accepted.
- Merge with mismatched public keys rejected.
- Merge against a `KeyID` that doesn't belong to the caller's scope rejected
  (same authorization pattern every other `ValidateKeyOwnership`-gated
  operation already tests).

## Documentation

1. `.claude/azure-keyvault-parity.md` §4 (lines 217-225) — add two new rows:
   "Import certificate (PFX/PEM)" (✅ once shipped) and "Merge CSR (pending
   certificate)" (🟡, with a footnote citing the Section 2.1 scope decision —
   not ✅, since Azure's full pending-operation model isn't matched).
2. `.claude/azure-keyvault-parity.md`'s Summary/Scorecard (lines 467-499) —
   "§4. Certificate management" currently reads `5 | 0 | 2 | 0`; update to
   reflect the two new rows (one ✅, one 🟡): `6 | 1 | 2 | 0`.
3. `.claude/roadmap-azure-parity-and-beyond.md` — genuinely new addition
   (confirmed no existing "certificate import"/"PFX"/"merge" mention); add to
   Phase 1 alongside key import, matching that section's existing bullet format.
4. `README.md` roadmap checklist, if it exists and is relevant.
5. `docs/cli-guide.md` — add `certificates import` and `certificates merge`.
6. `docs/api-developer-guide.md` — add both new endpoints' request/response
   shapes. Per `.claude/known-bugs.md` § B51 (hand-written docs drifting from
   the actual contract after a prior export/import feature shipped), this step
   is mandatory, not optional.
7. `docs/integration-examples.md` — add at least one worked PFX-import example;
   B51's lesson is specifically that examples drift independently of the guide
   doc, so both need updating, not just one.
8. `CLAUDE.md` — if certificate operations are enumerated there, add
   import/merge.
