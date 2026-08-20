# Testing HSM / PKCS#11 with SoftHSM2

SoftHSM2 is a software token that implements the PKCS#11 interface. It lets
you test the HSM code path without physical hardware. Steps below are
Ubuntu-first; where macOS (Homebrew) differs, a macOS variant is called out.

## 1. Install SoftHSM2

```bash
# Ubuntu / Debian
sudo apt install softhsm2 opensc
```

```bash
# macOS (Homebrew)
brew install softhsm opensc
```

`opensc` provides `pkcs11-tool`, used in the verification step below. The
`~/.zshrc` persistence used later in this guide works unmodified on macOS,
since zsh is the default shell there too.

## 2. Create the SoftHSM2 configuration file

After install, SoftHSM2 needs a config file pointing at a token directory.
The default location `softhsm2-util` looks for is `~/.config/softhsm2/softhsm2.conf`.

```bash
mkdir -p ~/.config/softhsm2/tokens

cat > ~/.config/softhsm2/softhsm2.conf <<EOF
directories.tokendir = $HOME/.config/softhsm2/tokens/
objectstore.backend = file
log.level = INFO
EOF
```

> Use double-quoted heredoc (`<<EOF`, not `<<'EOF'`) so `$HOME` expands.
> Single quotes prevent expansion and cause a "Failed to enumerate object store" error.

Persist the env var so every new shell finds the config:

```bash
echo 'export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf' >> ~/.zshrc
export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf
```

## 3. Initialize a token

```bash
softhsm2-util --init-token --slot 0 --label rocketvault --so-pin 0000 --pin 1234
```

Expected output:

```
The token has been initialized and is reassigned to slot <N>
```

Note the new slot number — SoftHSM2 reassigns the slot after init. Use it in
step 7 if it differs from 0.

## 4. Locate the library

On Ubuntu, both paths are typically present:

```
/usr/lib/softhsm/libsofthsm2.so
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

Either works. Use the first one in the config below.

On macOS (Homebrew), the path is under the Cellar and includes the installed
version number; Homebrew keeps the `.so` extension even on macOS (dlopen
doesn't care about the extension, only the file's actual Mach-O format), so
this is not a typo:

```bash
find "$(brew --prefix)/Cellar/softhsm" -name "libsofthsm2.so"
# e.g. /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so (Apple Silicon)
#   or /usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so (Intel)
```

## 5. Enable HSM in `.rocketvault.yaml`

Uncomment and fill in the `hsm` block at the bottom of the file. Use whichever
path step 4 found on your platform (`lib_path` below is the Ubuntu path;
substitute the Homebrew Cellar path on macOS):

```yaml
hsm:
  enabled: true
  lib_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: rocketvault
  pin: "1234"
  slot_id: 0
```

> Set `enabled: false` to switch back to the software provider without
> restarting or changing anything else.

## 6. Start the server

```bash
go run main.go serve
```

Look for this line in the log output:

```
PKCS#11 HSM key provider initialised
```

If you see `Software key provider initialised` instead, `hsm.enabled` is
still false.

## 7. Exercise the HSM via the API

### Authenticate

```bash
TOKEN=$(curl -s -X POST http://localhost:8774/api/v1/users/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123","totp_code":"<code>"}' \
  | jq -r .token)
```

### Create an RSA key on the token

```bash
curl -s -X POST http://localhost:8774/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"hsm-test","type":"RSA","bits":2048}' | jq
```

The key is stored in the database as `pkcs11:<uuid>` instead of an encrypted
PEM blob. The UUID is the label of the key pair on the token.

### Sign data (base64-encoded input)

```bash
KEY_ID=<id from create response>

curl -s -X POST http://localhost:8774/api/v1/keys/${KEY_ID}/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"value":"aGVsbG8=","algorithm":"RS256"}' | jq
```

### Verify the signature

```bash
SIG=<signature from sign response>

curl -s -X POST "http://localhost:8774/api/v1/keys/${KEY_ID}/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"value\":\"aGVsbG8=\",\"signature\":\"${SIG}\",\"algorithm\":\"RS256\"}" | jq
```

### Encrypt and decrypt

```bash
curl -s -X POST "http://localhost:8774/api/v1/keys/${KEY_ID}/encrypt" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"value":"aGVsbG8=","algorithm":"RSA-OAEP"}' | jq

# Use the value from the encrypt response
curl -s -X POST "http://localhost:8774/api/v1/keys/${KEY_ID}/decrypt" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"value":"<ciphertext>","algorithm":"RSA-OAEP"}' | jq
```

## 8. Verify keys are stored on the token

```bash
pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --list-objects
```

On macOS, pass the Homebrew Cellar path found in step 4 to `--module` instead.

> Make sure `SOFTHSM2_CONF` is exported before running `pkcs11-tool`, otherwise
> it will not find the token.

Each key created through RocketVault appears as a public + private key pair
labeled with the UUID stored in the database.

## 9. Run the integration tests

The PKCS#11 tests skip automatically when SoftHSM2 is not available. To run
them, both env vars must be set:

```bash
export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf
export SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so  # macOS: the Homebrew Cellar path from step 4
go test ./internal/crypto/... -v -run TestPKCS11
```

Persist `SOFTHSM2_LIB` alongside `SOFTHSM2_CONF` in `~/.zshrc` so you don't
need to export it each session:

```bash
echo 'export SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so' >> ~/.zshrc
```

Expected: all `TestPKCS11*` tests pass, including the secp256k1 ones —
`TestPKCS11Provider_GenerateECDSAKey_P256K` and
`TestPKCS11Provider_SignVerify_ECDSA_ES256K` both require success against
SoftHSM2, which accepts any curve inside its 112–521 bit key-size range.

A different HSM may legitimately refuse secp256k1, since it is not a
NIST-approved curve. That is not a bug and not a test failure: the provider
maps a token's `CKR_CURVE_NOT_SUPPORTED` / `CKR_DOMAIN_PARAMS_INVALID`
rejection onto a clean `ErrUnsupportedCurve` rather than leaking the raw
PKCS#11 error (see `isHSMCapabilityError` in
`internal/crypto/pkcs11_provider.go`).

## 10. Reset the token

If you need a clean slate:

```bash
softhsm2-util --delete-token --token rocketvault
softhsm2-util --init-token --slot 0 --label rocketvault --so-pin 0000 --pin 1234
```

## Supported algorithms

| Operation | Algorithms |
|-----------|-----------|
| Sign / Verify | RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, ES256K |
| Encrypt / Decrypt | RSA-OAEP (SHA-1), RSA-OAEP-256 (SHA-256); AES256-GCM and A128CBC / A192CBC / A256CBC on OCT keys |
| Wrap / Unwrap | RSA-OAEP, RSA-OAEP-256, A128KW / A192KW / A256KW |
| Key generation | RSA 2048/4096, ECDSA P-256 / P-384 / P-521 / P-256K, AES 128/192/256 |

Two things the table doesn't show:

**AES-CBC is deliberately absent from wrap/unwrap** while being present for
encrypt/decrypt. CBC needs an IV, and the wrap/unwrap request and response
shapes have no field to carry one — `EncryptResult.Nonce` and
`DecryptRequest.Nonce` do round-trip it, so use `/encrypt` and `/decrypt` for
CBC instead. See `isHSMWrapAlgorithm` in
`internal/services/keys/crypto_service.go`.

**OCT (symmetric AES) keys are HSM-only by design**, matching Azure: Managed
HSM never allows symmetric key creation on Standard/Premium vaults, and the
software provider mirrors that restriction. `CreateOctKey` fails with
`crypto.ErrOctKeysRequireHSM` unless `hsm.enabled: true`.

secp256k1 (P-256K / ES256K) works on this path — `CKM_EC_KEY_PAIR_GEN` and
`CKM_ECDSA` are both curve-agnostic in the PKCS#11 spec, so the curve's OID is
all that's needed. It is not a NIST curve, though, so an individual token may
still refuse it; see the note in step 9 above for how that surfaces.
