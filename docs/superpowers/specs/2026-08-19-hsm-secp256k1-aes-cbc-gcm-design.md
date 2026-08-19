# HSM (PKCS#11) support for P-256K, AES-CBC, and AES-GCM

**Date**: 2026-08-19
**Status**: Approved
**Scope**: `internal/crypto/pkcs11_provider.go`, `internal/services/keys/crypto_service.go`,
`internal/crypto/pkcs11_provider_test.go`, `internal/services/keys/crypto_service_test.go`,
`api/keys_crud_test.go`, `.claude/azure-keyvault-parity.md`, `CLAUDE.md`

---

## Problem

`.claude/azure-keyvault-parity.md` §8's "HSM-backed keys" row is 🟡 partial for four reasons:

1. No FIPS 140-3 L3 certification — a hardware/process certification, not achievable through
   code. **Permanently out of scope**, not addressed by this spec.
2. P-256K (secp256k1) has no PKCS#11 mechanism — `pkcs11_provider.go`'s `ecOID` map only has
   P-256/P-384/P-521; `GenerateECDSAKey` returns `ErrUnsupportedCurve` for P-256K, and the code
   comment claims this curve is "not in the standard PKCS#11 curve OID table."
3. AES-CBC and AES-GCM exist in the software crypto path but are unreachable on an HSM-enabled
   instance, since `PKCS11KeyProvider` only implements AES-KW for wrap/unwrap; encrypt/decrypt and
   CBC/GCM mechanisms aren't implemented there at all.
4. (Closed same day, separately: B24/B25 fixed two bugs in how a P-256K *request* fails — a
   REST validator rejection and an uncaught 500 — but neither changed what the HSM path can
   actually do. This spec closes the underlying capability gap those bugs' error paths exist to
   protect.)

Reason 2 and 3's premises were never actually verified against a real PKCS#11 token — they were
written as design-time assumptions. Empirical testing against this environment's SoftHSM2 token
(both via `pkcs11-tool` and a throwaway Go program using the exact `github.com/miekg/pkcs11`
library RocketVault depends on) found all three operations genuinely work:

- **secp256k1 key generation**: `pkcs11-tool --keypairgen --key-type EC:secp256k1` succeeds,
  producing `EC_PARAMS: 06052b8104000a (OID 1.3.132.0.10)` — the correct secp256k1 OID.
- **secp256k1 sign/verify**: a full ECDSA sign + verify round-trip against the generated key
  succeeded via the generic `CKM_ECDSA` mechanism (`pkcs11-tool --sign --mechanism ECDSA`, then
  `--verify`).
- **AES-CBC**: `pkcs11-tool --list-mechanisms` reports `AES-CBC` and `AES-CBC-PAD` as supported
  (`encrypt, decrypt, wrap`); a 16-byte-block-aligned encrypt/decrypt round-trip succeeded.
- **AES-GCM**: `pkcs11-tool --list-mechanisms` reports `AES-GCM` as supported (`encrypt,
  decrypt`); the CLI tool's own `--encrypt`/`--decrypt` flags don't expose GCM's IV/AAD/tag
  parameters correctly, but a direct Go program using `miekg/pkcs11`'s `NewGCMParams(iv, aad,
  128)` — the same API RocketVault's own code would use — completed a full encrypt/decrypt
  round-trip with matching plaintext.

`CKM_EC_KEY_PAIR_GEN` is curve-agnostic in the PKCS#11 spec: it validates against a key-size
range (SoftHSM2 reports 112–521 bits for `ECDSA-KEY-PAIR-GEN`), not a fixed curve allowlist.
SoftHSM2's permissiveness doesn't prove every HSM vendor accepts secp256k1 — many real/hardware
HSMs restrict curve/mechanism support for FIPS-compliance reasons, and secp256k1 isn't a
NIST-approved curve — but it does prove the gap is a **software implementation gap in this
codebase**, not a hard PKCS#11-standard wall. This spec closes that implementation gap and adds
runtime handling for HSMs that do reject one of these operations, so a rejection degrades to a
clean error instead of an uncaught 500 (the exact failure mode B25 just fixed for the one gap
that was previously known).

## Goals

- `POST /keys {"type":"ECDSA","curve":"P-256K"}` succeeds end-to-end on an HSM-enabled instance
  wherever the underlying token supports it (verified: SoftHSM2), including working
  `sign`/`verify` afterward.
- `POST /keys/{id}/wrap`/`unwrap` with `A128CBC`/`A192CBC`/`A256CBC` succeed against an
  HSM-backed AES key.
- `POST /keys/{id}/encrypt`/`decrypt` with `AES256-GCM` succeed against an HSM-backed AES key.
- On any HSM that rejects one of these at the PKCS#11 level (a real possibility for secp256k1 on
  vendor hardware), the failure surfaces as the existing `ErrUnsupportedCurve`/
  `ErrUnsupportedAlgorithm` sentinel → a clean 400 via the B24/B25 error-mapping pipeline already
  in `api/keys.go`/`errors_key.go` — not a leaked 500. No changes to those two files are needed;
  this is a property of translating the right errors at the source.
- `.claude/azure-keyvault-parity.md` §3 and §8 reflect the new capability honestly, including the
  caveat that only SoftHSM2 was verified — real HSM vendor support is expected to vary.

## Non-goals

- **FIPS 140-3 L3 certification** — not a code change, permanently out of scope.
- **Proactive capability probing** (`C_GetMechanismList`/`C_GetMechanismInfo` at provider
  startup, or a health-endpoint capability surface) — considered and rejected. PKCS#11's
  mechanism-info API reports key-size ranges, not which named curves a mechanism accepts, so it
  cannot actually answer "does this HSM support secp256k1?" ahead of time — you still have to
  attempt the operation and interpret the real result, which is exactly what this spec's reactive
  error-translation does. A proactive layer would be additive engineering for a benefit the
  reactive approach already provides at the point a request actually fails; it can be added later
  as a pure observability improvement without any rework of this spec's design.
- **New AES-GCM key-size variants.** RocketVault's software path only ever implemented a single
  256-bit GCM identifier (`AlgorithmAES256` = `"AES256-GCM"`). This spec matches that — no
  `A128GCM`/`A192GCM` are introduced, since nothing in the codebase asks for them.
- **Wrapping with AES-GCM.** GCM has never been in the wrap/unwrap algorithm allowlist
  (`wrapAlgorithmToEncryption`/`isHSMWrapAlgorithm` in `crypto_service.go`) on either provider —
  it's Encrypt/Decrypt-only, matching Azure's own convention. This spec doesn't change that.
- **CLI support for creating P-256K keys via `rocketvault keys create`.** The CLI already
  supports `--curve P-256K` (it calls `KeyService` directly, bypassing the REST validator B24
  fixed) — no CLI change needed. This spec is entirely about the HSM/PKCS#11 provider layer.
- **Testing against real vendor hardware.** Only SoftHSM2 is available in this environment. The
  design's runtime error-translation logic gets direct unit tests (constructing/matching the
  known PKCS#11 error strings), but the actual "a real HSM rejects this" path cannot be
  integration-tested here.

## Design

### 1. P-256K (secp256k1) EC curve support

`internal/crypto/pkcs11_provider.go`:

- Add `"P-256K": {1, 3, 132, 0, 10}` to the `ecOID` map (the verified secp256k1 OID). Remove/
  correct the "secp256k1 is intentionally excluded" doc comment on `ecOID` and the "P-256K is not
  supported on PKCS#11" comment on `GenerateECDSAKey` — replace with an accurate description
  referencing this spec and noting production HSM support may vary.
- Add an entry to `signMechanisms`:
  ```go
  AlgorithmES256K: {p11.CKM_ECDSA, true, AlgorithmES256K, nil},
  ```
  This reuses the exact same `CKM_ECDSA` mechanism as ES256/384/512 — `CKM_ECDSA` operates on
  whatever EC key is loaded regardless of curve, and takes a pre-hashed digest. `preHash: true`
  with `hashAlgo: AlgorithmES256K` resolves to SHA-256 via the existing `getHasher` function
  (`crypto_operations.go`, already used by the software provider's ES256K path) — no new hashing
  logic needed. Once this map entry exists, `Sign`/`Verify` work for P-256K keys with zero other
  code changes, since neither function branches on curve — only on `SignatureAlgorithm`.
- No changes needed in `KeyService`, `api/keys.go`, or `errors_key.go`. `CreateECDSAKey` and
  `RotateKey` already pass `"P-256K"` through to the provider unconditionally; the provider was
  the only gate. B24/B25's error-mapping code stays exactly as-is — it becomes unreachable on
  SoftHSM2 specifically (a good outcome, not dead code: it's still the correct behavior for any
  HSM that genuinely rejects the curve, per the error-translation design below).

### 2. AES-CBC on HSM-backed keys

`internal/crypto/pkcs11_provider.go`'s `Encrypt`/`Decrypt` currently dispatch on
`isAESKWAlgorithm(algorithm)` (secret-key wrap path) vs. everything else (RSA-OAEP path via
`oaepMechParams`, which returns `ErrUnsupportedAlgorithm` for anything it doesn't recognize,
including CBC). Add a third case, checked before the RSA-OAEP fallback:

```go
func isAESCBCAlgorithm(algorithm EncryptionAlgorithm) bool {
    switch algorithm {
    case AlgorithmA128CBC, AlgorithmA192CBC, AlgorithmA256CBC:
        return true
    default:
        return false
    }
}
```

New `encryptAESCBC`/`decryptAESCBC` methods on `PKCS11KeyProvider`, structurally parallel to the
existing `wrapRawData`/`unwrapRawData`:

- Look up the secret key handle via the existing `findSecretKey` (same lookup AES-KW already
  uses — no change to `GenerateAESKey`, which already sets `CKA_ENCRYPT`/`CKA_DECRYPT` true on
  every AES key, just never had a code path that used them).
- Generate a random 16-byte IV in Go (`crypto/rand`, matching the software provider's
  `encryptAESCBC` convention exactly).
- `mech := p11.NewMechanism(p11.CKM_AES_CBC_PAD, iv)` — the **padded** variant. PKCS#11's
  `CKM_AES_CBC_PAD` applies PKCS7 padding on-token, so the plaintext doesn't need to be
  block-aligned in Go — this matches the software provider's PKCS7-padding behavior exactly,
  without needing to reimplement padding logic here.
- `EncryptInit`/`Encrypt` (or `DecryptInit`/`Decrypt`) against the secret key handle.
- Return `(ciphertext, iv, nil)` from `Encrypt` — same `(ciphertext, nonce, err)` shape every
  other algorithm already returns; `Decrypt` takes the IV back via its existing `nonce []byte`
  parameter. **No interface or type changes** — `EncryptResult`/`DecryptResult` and the
  `KeyProvider` interface are untouched.

`internal/services/keys/crypto_service.go`:

- `isHSMWrapAlgorithm` gains `"A128CBC", "A192CBC", "A256CBC"` alongside the existing RSA-OAEP/
  AES-KW cases. This is the actual gate that currently blocks CBC wrap for HSM-backed keys before
  the request ever reaches the provider (`WrapKey`/`UnwrapKey` check this before calling
  `s.keyProvider.Encrypt`/`Decrypt`) — the provider-level fix above is necessary but not
  sufficient without this.
- Update the stale doc comments on `WrapKey`, `UnwrapKey`, and `isHSMWrapAlgorithm` ("AES-CBC wrap
  has no PKCS#11 mechanism and stays software-key-only") to describe the new behavior.
- The `aesKWKeyBits` bit-size check in `WrapKey`/`UnwrapKey` already only applies to KW variants
  (`case "A128KW"/"A192KW"/"A256KW"`, returns 0 — meaning "skip the check" — for anything else,
  including CBC) — no change needed there; CBC's key-size correctness is enforced by
  `GenerateAESKey`'s existing 128/192/256 validation at key-creation time, same as it already is
  for the software path.

### 3. AES-GCM on HSM-backed keys

Same shape as CBC, one algorithm, Encrypt/Decrypt only (never wrap/unwrap — see Non-goals):

```go
func isAESGCMAlgorithm(algorithm EncryptionAlgorithm) bool {
    return algorithm == AlgorithmAES256
}
```

New `encryptAESGCM`/`decryptAESGCM` methods:

- Same `findSecretKey` lookup.
- Generate a random 12-byte nonce in Go (matching the software provider's `encryptAES` — GCM's
  standard 96-bit IV size, not CBC's 16-byte block size).
- `gcmParams := p11.NewGCMParams(iv, nil, 128)` — no AAD (`nil`), 128-bit tag, matching the
  software path's `cipher.NewGCM(block)` default (Go's stdlib GCM defaults to a 16-byte/128-bit
  tag with no AAD when called via `Seal(nil, nonce, data, nil)`).
- `defer gcmParams.Free()` — required by the `miekg/pkcs11` library to release the C-side
  parameter struct (confirmed via the library's own doc comment on `GCMParams`).
- `EncryptInit`/`Encrypt` (or `DecryptInit`/`Decrypt`) against the secret key handle.
- Return `(ciphertext, nonce, nil)` — same shape as every other algorithm.

`crypto_service.go`: no changes needed for GCM — the plain `Encrypt`/`Decrypt` service methods
have no algorithm allowlist (unlike `WrapKey`/`UnwrapKey`); they pass straight through to
`s.keyProvider.Encrypt`/`Decrypt` and rely on the provider to accept or reject the algorithm,
which the new branch now does correctly.

### 4. Reactive HSM-capability error translation (the graduated-degradation design decision)

The existing `isSignatureInvalid` helper string-matches `err.Error()` against
`"pkcs11: 0x<hex>: <SYMBOL>"`, relying on the library's internal `strerror` map (`error.go`) to
supply the symbol name. **That map is incomplete**: `CKR_CURVE_NOT_SUPPORTED` (0x140) has no
entry in it, so `Error(0x140).Error()` actually formats as `"pkcs11: 0x140: "` — an empty symbol,
not `"...CKR_CURVE_NOT_SUPPORTED"`. A string-match helper written the same way
`isSignatureInvalid` is would silently never match that one code (confirmed by reading
`error.go`'s `strerror` map and `Error.Error()`'s `fmt.Sprintf("pkcs11: 0x%X: %s", ...)`
directly — not assumed).

Rather than depend on that incomplete table (which could also silently change behavior if a
future library version adds the missing entry), the new helper compares the library's own typed
`p11.Error` value directly, extracted via `errors.As` — robust regardless of what string
representation the library does or doesn't produce for a given code:

```go
// Known CKR_* result codes a PKCS#11 token returns when it understands a
// request but doesn't support the specific curve or mechanism -- as opposed
// to a transport/system failure. Values from the PKCS#11 v2.40 spec.
const (
    ckrCurveNotSupported     = p11.Error(0x140) // CKR_CURVE_NOT_SUPPORTED
    ckrDomainParamsInvalid   = p11.Error(0x130) // CKR_DOMAIN_PARAMS_INVALID
    ckrMechanismInvalid      = p11.Error(0x70)  // CKR_MECHANISM_INVALID
    ckrMechanismParamInvalid = p11.Error(0x71)  // CKR_MECHANISM_PARAM_INVALID
)

// isHSMCapabilityError reports whether err indicates the token rejected an
// operation because it doesn't support the requested curve or mechanism,
// rather than a transport/system failure. SoftHSM2 accepts secp256k1 and
// AES-CBC/GCM (verified during this feature's design), but real HSM vendors
// vary -- this lets any such rejection degrade to a clean, typed error
// instead of an opaque one. Compares the library's typed error value
// directly (via errors.As) rather than its string form, since
// CKR_CURVE_NOT_SUPPORTED has no entry in the library's own strerror table
// and so has no reliable string representation to match against.
func isHSMCapabilityError(err error) bool {
    var pErr p11.Error
    if !errors.As(err, &pErr) {
        return false
    }
    switch pErr {
    case ckrCurveNotSupported, ckrDomainParamsInvalid, ckrMechanismInvalid, ckrMechanismParamInvalid:
        return true
    default:
        return false
    }
}
```

This works because `toError` (`error.go`) always returns a bare `p11.Error` value (never
string-wrapped at the library boundary), and every RocketVault call site wraps it with `%w`
(e.g. `fmt.Errorf("pkcs11 ec key gen (%s): %w", curveName, err)`), so `errors.As` correctly
unwraps through to the typed value. `pkcs11_provider.go` already imports `errors` (for
`errors.New` on the package's sentinel definitions) — only the `p11.Error` type reference is new,
and `p11` is already imported. `isSignatureInvalid` is existing code and out of scope for this
spec to change, even though it could arguably benefit from the same robustness fix — that's a
tangential improvement, not required for this feature, and changing working pre-existing code
without a driving need would be scope creep.

Applied at three call sites, each wrapping a capability-rejection as the package's existing
sentinel (never introducing a new error type):

- `GenerateECDSAKey`: if `GenerateKeyPair` fails and `isHSMCapabilityError(err)`, return
  `fmt.Errorf("%w: %s (rejected by HSM)", ErrUnsupportedCurve, curveName)` instead of the generic
  `"pkcs11 ec key gen (%s): %w"` wrap — this is defense in depth beyond the static `ecOID` map:
  even for curves the map says should work (P-256/P-384/P-521, or the new P-256K), a *specific*
  token might still reject one at the hardware level, and that should look identical to the
  already-known-unsupported case, not a 500.
- `encryptAESCBC`/`decryptAESCBC` and `encryptAESGCM`/`decryptAESGCM`: if `EncryptInit`/
  `DecryptInit` fails and `isHSMCapabilityError(err)`, return
  `fmt.Errorf("%w: %s (rejected by HSM)", ErrUnsupportedAlgorithm, algorithm)`.

Because `api/keys.go`'s `createKey` switch and `errors_key.go`'s `writeKeyError` already map
`crypto.ErrUnsupportedCurve`/`ErrUnsupportedAlgorithm` to a clean 400 (B24/B25), **no changes are
needed in either file** for this to work end-to-end on any HSM vendor, including ones this
environment can't test against.

## Testing

`internal/crypto/pkcs11_provider_test.go` (existing `SOFTHSM2_LIB`-env-gated live-token pattern,
skips cleanly when SoftHSM2 isn't available — no new test infrastructure):

- Flip `TestPKCS11Provider_GenerateECDSAKey_P256K` (currently asserts
  `assert.ErrorIs(t, err, crypto.ErrUnsupportedCurve)`) to assert success and a valid handle.
- New: sign + verify round-trip for an HSM-backed P-256K key via `AlgorithmES256K`.
- New: AES-CBC encrypt/decrypt round-trip for A128CBC/A192CBC/A256CBC (one test per size, or a
  table test) — including a tamper-detection case (flipped ciphertext byte fails to decrypt to
  the original plaintext, or fails outright — CBC has no built-in integrity check, so this test
  documents that property rather than asserting a specific failure mode).
- New: AES-GCM encrypt/decrypt round-trip — including a genuine tamper-detection case (GCM is
  authenticated, so a flipped ciphertext byte or wrong nonce must fail decryption with an error,
  not silently return wrong plaintext).
- New: unit tests for `isHSMCapabilityError` against literal known PKCS#11 error strings (no live
  HSM needed for this one, since it's pure string matching) — both positive matches and a
  negative case (a generic error that should NOT be classified as a capability rejection, to
  guard against over-broad matching swallowing real infrastructure failures as clean 400s).

`internal/services/keys/crypto_service_test.go` (or wherever `WrapKey`/`UnwrapKey` are tested):

- Find and flip whatever test currently asserts CBC wrap is rejected for HSM-backed keys (per
  `isHSMWrapAlgorithm`'s current `false` case) to assert success instead, using a mock/fake
  provider consistent with that file's existing test doubles.

`api/keys_crud_test.go`:

- One regression test closing the loop end-to-end: `POST /keys/{id}/wrap` with `A256CBC` against
  an HSM-backed key mock returns 200/201 rather than the old rejection — mirrors the shape of the
  existing `TestCreateKey_ECDSA_P256K_NoHSMMechanism_Returns400`-style tests added for B25, but
  asserting success this time.

All new/flipped tests must be run against the real SoftHSM2 token in this environment (not just
mocked) at least once during implementation, the same way this spec's own research was verified,
before considering the feature done — mocks alone would not have caught the original wrong
assumption that started this spec.

## Documentation

- `.claude/azure-keyvault-parity.md`:
  - §3 "EC curves" and "Sign/Verify — EC" rows: P-256K moves from "CLI-only, unreachable over
    REST" to full REST support (creation + sign + verify), with an honest caveat that only
    SoftHSM2 was verified — cite this spec and note real HSM vendor support for secp256k1 (a
    non-NIST curve) may vary, with the reactive-error-translation behavior documented as the
    fallback for vendors that reject it.
  - §3 "Wrap/Encrypt — AES (KW/CBC/GCM)" row: AES-CBC and AES-GCM move from "unreachable — no
    software-backed symmetric key can be created" to HSM-backed support, alongside the existing
    AES-KW row content.
  - §8 "HSM-backed keys" row and its Status glyph: re-evaluate once implemented — likely moves
    from 🟡 to either ✅ (if the remaining FIPS-certification caveat is treated as a separate,
    already-well-understood dimension rather than blocking this row) or stays 🟡 with a
    much narrower, single-sentence caveat. Final call deferred to implementation time, once the
    actual test results are in hand rather than speculated here.
  - Summary section reconciled to match, following this doc's established dated-note convention.
- `pkcs11_provider.go`/`crypto_service.go` code comments asserting these are permanent
  limitations get corrected in place (not left stale like the ones this spec's research found).
- Likely a short `CLAUDE.md` note under "Key Management" following the precedent set by the
  2026-08-11–13 HSM AES-KW addition (a similar capability-expansion entry) — exact wording
  deferred to implementation time.
- No `.claude/known-bugs.md` entry — nothing here was broken in the sense that file tracks;
  this is new capability, not a fix. (B24/B25 already cover the *error-handling* bugs that
  existed around the old gap; this spec closes the gap itself.)
