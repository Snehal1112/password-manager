# OS Keychain JWT Key Storage Design

**Date**: 2026-05-22
**Status**: Approved
**Scope**: Replace plaintext PEM file storage in `OSStoreProvider` with OS keychain
(`go-keyring`), falling back to the existing PEM file path when the keychain is
unavailable (headless Linux, Docker, CI).

---

## 1. Problem

`OSStoreProvider` auto-generates an RSA-2048 private key and writes it as a plaintext
PEM file to `~/.local/share/rocketvault/jwt-signing.pem` (or `/etc/ssl/certs/` if
root). Any local user who can read that file can steal the JWT signing key and mint
arbitrary tokens — defeating the entire purpose of asymmetric signing.

---

## 2. Goals

- Store the auto-generated RSA private key in the OS keychain (GNOME Keyring on Linux,
  Keychain on macOS, Credential Manager on Windows) so it is ACL-protected and
  optionally hardware-backed.
- Survive headless / container environments where no keychain daemon is running by
  falling back silently to the existing PEM file path.
- Cross-platform: Linux + macOS + Windows.
- Minimal scope: only `OSStoreProvider` changes; other providers are unaffected.

## 3. Non-Goals

- Replacing `self_pki` or `external_pki` storage — they use the encrypted DB and
  env/file respectively, which are already acceptable.
- Requiring libsecret at build time — it must be a runtime-only dependency on Linux.
- HSM / TPM integration — hardware backing is used automatically by the OS if available;
  we do not explicitly require it.

---

## 4. Architecture

```
NewOSStoreProvider(cn)
  │
  ├─ 1. loadFromKeychain(cn)   ──→ found: use key, return
  │       (go-keyring Get)
  │
  ├─ 2. Not found: generateSelfSignedRSA(cn)
  │
  ├─ 3. saveToKeychain(cn, keyPEM)  ──→ ok: return
  │       (go-keyring Set)
  │
  └─ 4. Keychain error: warn + fall back to persistKeyToFile(cn)
              (existing PEM file logic, unchanged)
```

### Keychain Entry Shape

| Field   | Value                                    |
|---------|------------------------------------------|
| Service | `"rocketvault"`                          |
| User    | `"jwt-signing-key-<cn>"` (e.g. `jwt-signing-key-rocketvault`) |
| Secret  | PEM-encoded RSA private key (key only, no certificate) |

The `cn` is embedded in the label so multiple RocketVault instances with different
`jwt.key_cn` values do not collide in the same keychain.

---

## 5. Library

**`github.com/zalando/go-keyring`**

- Pure Go on macOS (Security framework) and Windows (Credential Manager).
- Uses D-Bus / libsecret on Linux — runtime dependency only, not a build dependency.
- Returns `keyring.ErrNotFound` for missing entries and a distinct error for daemon
  unavailable — both are handled explicitly.

---

## 6. Fallback Behaviour

| Situation | Behaviour |
|-----------|-----------|
| Keychain available, key present | Load from keychain, skip generation |
| Keychain available, key absent | Generate, store in keychain |
| Keychain unavailable (no daemon) | Generate, warn, write PEM file |
| PEM file fallback fails too | Log warning, continue in-memory only |

In-memory-only means the key is valid for the lifetime of the process but lost on
restart. This is the same behaviour as today when both paths fail.

---

## 7. Files Changed

| File | Change |
|------|--------|
| `internal/signing/os_store.go` | Add `loadFromKeychain`, `saveToKeychain`; update `NewOSStoreProvider` startup sequence; keep `persistKey` as file fallback |
| `go.mod` / `go.sum` | Add `github.com/zalando/go-keyring` |

No other files are changed.

---

## 8. Testing Strategy

- **Unit — keychain happy path**: inject a fake keychain (interface + mock); verify key
  is loaded on second call without regeneration.
- **Unit — keychain unavailable**: fake keychain returns error; verify fallback to PEM
  file is attempted and warning is logged.
- **Unit — keychain missing key**: fake keychain returns `ErrNotFound`; verify key is
  generated and `Set` is called.
- **Manual**: after server start, `secret-tool lookup service rocketvault username
  jwt-signing-key-rocketvault` on Linux shows the PEM; restarting the server reuses
  the same key (same `kid` in `/jwks.json`).
