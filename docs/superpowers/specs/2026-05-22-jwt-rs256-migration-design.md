# JWT Signing: HS256 → RS256/ES256 Migration Design

**Date**: 2026-05-22
**Status**: Approved
**Scope**: Replace symmetric HS256 JWT signing with asymmetric RS256/ES256 via a pluggable
`SigningKeyProvider` interface. Publish a JWKS endpoint so external services can verify tokens.
Support zero-downtime migration with a backward-compatible HS256 fallback window.

---

## 1. Problem

RocketVault currently signs JWTs with HS256 (symmetric HMAC). The same secret that signs
tokens also verifies them. Any service holding `jwt_secret` can mint arbitrary tokens —
unacceptable for a vault product. Additionally, external services cannot independently verify
tokens without sharing the secret.

---

## 2. Goals

- Sign JWTs with RS256 or ES256 (asymmetric)
- Support three key sources: OS certificate store (default), RocketVault's own PKI, external PEM
- Publish `GET /jwks.json` so external services can verify tokens without calling RocketVault
- Zero forced logouts during migration — HS256 tokens remain valid for a configurable window
- `kid` header in all new tokens for key selection during rotation and migration

## 3. Non-Goals

- Full OIDC Discovery (`/.well-known/openid-configuration`) — can be added later on top of this
- AWS KMS / HashiCorp Vault / HSM backends — future providers, same interface
- Revocation list / `jti` tracking — separate milestone

---

## 4. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  jwt.key_source config: os_store | self_pki | external_pki  │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  internal/signing/provider.go — SigningKeyProvider interface │
│  ├── PrivateKey() crypto.Signer   — signs JWTs              │
│  ├── PublicKeys() []PublicKeyInfo — serves JWKS              │
│  └── Algorithm() string           — "RS256" or "ES256"      │
└──────┬────────────────┬──────────────────────┬──────────────┘
       ▼                ▼                      ▼
OSStoreProvider   SelfPKIProvider      ExternalPKIProvider
(default, RS256)  (ES256, DB-backed)   (RS256/ES256, PEM)
       │                │                      │
       └────────────────┴──────────────────────┘
                        │ injected into
                        ▼
          internal/services/auth/jwt_service.go
          (signs + verifies; HS256 fallback during migration)
                        │
                        ▼
              GET /jwks.json  (public)
              POST /api/v1/jwks/rotate  (admin only)
```

---

## 5. `SigningKeyProvider` Interface

**Package:** `internal/signing/`

```go
// SigningKeyProvider supplies the private key for JWT signing and the public
// keys for JWKS publication and token verification.
type SigningKeyProvider interface {
    PrivateKey() crypto.Signer    // used by JWTService to sign tokens
    PublicKeys() []PublicKeyInfo  // served at GET /jwks.json
    Algorithm() string            // "RS256" or "ES256"
    KeyID() string                // kid claim — SHA-256 thumbprint of public key
}

// PublicKeyInfo is one entry in the JWK Set.
type PublicKeyInfo struct {
    KeyID     string      // "kid"
    Algorithm string      // "RS256" or "ES256"
    PublicKey crypto.PublicKey
}
```

`PublicKeys()` returns **all active public keys** — during rotation overlap it returns both
old and new. `JWTService.ValidateToken` iterates them, matching by `kid`.

---

## 6. The Three Providers

### 6.1 `OSStoreProvider` (default, `key_source: os_store`)

**File:** `internal/signing/os_store.go`

Startup behaviour:
1. Search system certificate store for a certificate whose CN matches `jwt.key_cn`
   (default: `"rocketvault"`).
   - Linux: `/etc/ssl/certs/` + NSS store via `crypto/x509.SystemCertPool()`
   - macOS: system Keychain via `crypto/x509.SystemCertPool()`
2. If found: load the associated private key from the store. Algorithm: RS256.
3. If not found: auto-generate a self-signed RSA-2048 certificate + private key.
   - Attempt to write to `/etc/ssl/certs/rocketvault-jwt.pem` (requires root).
   - Fall back to `~/.local/share/rocketvault/jwt-signing.pem` if write fails.
   - Log a clear warning that a self-generated key is in use.
4. `KeyID()`: SHA-256 thumbprint of the public key, hex-encoded, first 16 chars.

### 6.2 `SelfPKIProvider` (`key_source: self_pki`)

**File:** `internal/signing/self_pki.go`

Uses RocketVault's own encrypted key store (existing `CryptographyService` +
`KeyRepository`). Algorithm: ES256 (ECDSA P-256).

Startup behaviour:
1. Look up a key named `_jwt_signing` in the key repository (reserved internal name).
2. If found: decrypt with `CryptographyService.DecryptSecret`, parse as ECDSA PEM.
3. If not found: generate a new ECDSA P-256 key pair via `crypto.GenerateECDSAKeyPEM("P-256")`,
   encrypt and store it, self-sign a certificate.
4. `PublicKeys()` returns both current and previous key during `jwt.rotation_overlap` window.

Rotation (`POST /api/v1/jwks/rotate`):
- Generate new key pair, store as `_jwt_signing_v{n+1}`.
- Promote to active. Keep previous key in `PublicKeys()` for `rotation_overlap` duration.
- After overlap: mark previous key as archived (not deleted — audit trail).

### 6.3 `ExternalPKIProvider` (`key_source: external_pki`)

**File:** `internal/signing/external_pki.go`

Reads a PEM private key at startup. Priority order:
1. `ROCKETVAULT_JWT_SIGNING_KEY` env var (base64-encoded PEM)
2. File at `jwt.signing_key_file` config path
3. Fails fast with a clear error if neither is set

Supports RSA (→ RS256) and ECDSA (→ ES256) — algorithm auto-detected from key type via
`internal/crypto.ParsePrivateKey()` (already exists).

No runtime rotation — operator replaces file/env var and restarts.

---

## 7. `JWTService` Changes

**File:** `internal/services/auth/jwt_service.go`

### 7.1 New constructor

```go
func NewJWTServiceWithProvider(config JWTConfig, provider signing.SigningKeyProvider) JWTService
```

Old `NewJWTService(config JWTConfig)` remains for HS256 backward compatibility during
migration window — **deleted after migration window support is removed**.

### 7.2 `GenerateToken` changes

- Sign with `provider.PrivateKey()` using `provider.Algorithm()`
- Add `kid` header claim: `provider.KeyID()`
- Add `jti` claim: `uuid.New().String()` (foundation for future revocation)

### 7.3 `ValidateToken` changes

```
1. Extract `kid` from token header (if present)
2. If kid present:
   a. Find matching PublicKeyInfo in provider.PublicKeys()
   b. Verify signature with that public key
3. If kid absent (old HS256 token) AND migration window still active:
   a. Fall back to HS256 verification with jwt_secret
   b. Log: "HS256 token accepted — migration window active"
4. If kid absent AND migration window expired:
   a. Reject with "token uses deprecated signing algorithm"
```

### 7.4 Migration window

Configured via `jwt.migration_window` (default `"24h"`). `JWTService` records
`migrationDeadline = time.Now().Add(migrationWindow)` at construction. When
`time.Now().After(migrationDeadline)`, the HS256 fallback code path returns an
error immediately without attempting verification.

---

## 8. JWKS Endpoint

**File:** `api/jwks.go`

### 8.1 `GET /jwks.json` (public, no auth)

Registered on `rootRouter` (same pattern as `/api/v1/config`). Returns RFC 7517 JWK Set.

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "a1b2c3d4e5f6a7b8",
      "n": "<base64url modulus>",
      "e": "AQAB"
    }
  ]
}
```

Response headers: `Cache-Control: public, max-age=3600` — clients may cache JWKS for 1 hour.

### 8.2 `POST /api/v1/jwks/rotate` (admin only, `SelfPKIProvider` only)

Returns `{"status": "ok", "new_kid": "...", "overlap_until": "<RFC3339>"}`.
Returns `400 Bad Request` if `key_source` is not `self_pki`.

**File:** `internal/signing/jwks.go` — JWK serialization helpers:
- `RSAPublicKeyToJWK(key *rsa.PublicKey, kid, alg string) map[string]any`
- `ECDSAPublicKeyToJWK(key *ecdsa.PublicKey, kid, alg string) map[string]any`

---

## 9. Configuration

New `jwt` section in `.rocketvault.yaml` (replaces bare `jwt_secret`):

```yaml
jwt:
  key_source: "os_store"        # os_store | self_pki | external_pki
  key_cn: "rocketvault"         # OSStoreProvider: CN to search for
  expiry: "1h"                  # token TTL (unchanged)
  rotation_overlap: "1h"        # how long old key stays in JWKS after rotation
  migration_window: "24h"       # HS256 fallback active for this duration after upgrade

  # ExternalPKIProvider only:
  signing_key_file: ""          # path to PEM private key file

# Kept during migration window only — ignored after:
jwt_secret: "..."
```

---

## 10. Dependency Injection Wiring

**File:** `internal/container/service_container.go`

```go
// In Initialize():
provider, err := signing.NewProvider(viperCfg, c.cryptoService, c.keyRepo)
if err != nil {
    return fmt.Errorf("JWT signing provider: %w", err)
}
c.jwtService = authServices.NewJWTServiceWithProvider(jwtConfig, provider)
```

`signing.NewProvider()` reads `jwt.key_source` and constructs the appropriate provider.

---

## 11. Files to Create / Modify

| Path | Action | Responsibility |
|---|---|---|
| `internal/signing/provider.go` | Create | `SigningKeyProvider` interface + `PublicKeyInfo` type + `NewProvider()` factory |
| `internal/signing/os_store.go` | Create | OS cert store lookup + RSA auto-gen fallback |
| `internal/signing/self_pki.go` | Create | ECDSA key in encrypted DB, rotation support |
| `internal/signing/external_pki.go` | Create | PEM from env var or file |
| `internal/signing/jwks.go` | Create | JWK Set serialization (RSA + ECDSA) |
| `internal/services/auth/jwt_service.go` | Modify | Provider injection, RS256/ES256 signing, kid+jti claims, HS256 fallback |
| `api/jwks.go` | Create | `GET /jwks.json` + `POST /api/v1/jwks/rotate` handlers |
| `api/api.go` | Modify | Register JWKS routes on rootRouter |
| `internal/container/service_container.go` | Modify | Wire `signing.NewProvider()` into JWTService |
| `.rocketvault.yaml` | Modify | Add `jwt` section, keep `jwt_secret` during migration |

---

## 12. Testing Strategy

- `OSStoreProvider`: test auto-gen fallback (no cert in store → generates to temp dir)
- `SelfPKIProvider`: mock `KeyRepository` + `CryptographyService`; test first-run key gen and rotation overlap
- `ExternalPKIProvider`: table-driven tests for RSA PEM, ECDSA PEM, missing key (error)
- `JWTService`: test RS256 sign + verify; test HS256 fallback during window; test rejection after window
- `GET /jwks.json`: assert JWK Set shape, correct `kty`/`alg`/`kid` fields
- `POST /api/v1/jwks/rotate`: assert new `kid` appears, old `kid` present during overlap, gone after
