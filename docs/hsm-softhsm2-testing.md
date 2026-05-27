# Testing HSM / PKCS#11 with SoftHSM2 on Ubuntu

SoftHSM2 is a software token that implements the PKCS#11 interface. It lets
you test the HSM code path without physical hardware.

## 1. Install SoftHSM2

```bash
sudo apt install softhsm2 opensc
```

`opensc` provides `pkcs11-tool`, used in the verification step below.

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

On this machine both paths are present:

```
/usr/lib/softhsm/libsofthsm2.so
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

Either works. Use the first one in the config below.

## 5. Enable HSM in `.rocketvault.yaml`

Uncomment and fill in the `hsm` block at the bottom of the file:

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

> Make sure `SOFTHSM2_CONF` is exported before running `pkcs11-tool`, otherwise
> it will not find the token.

Each key created through RocketVault appears as a public + private key pair
labeled with the UUID stored in the database.

## 9. Run the integration tests

The PKCS#11 tests skip automatically when SoftHSM2 is not available. To run
them, both env vars must be set:

```bash
export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf
export SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so
go test ./internal/crypto/... -v -run TestPKCS11
```

Persist `SOFTHSM2_LIB` alongside `SOFTHSM2_CONF` in `~/.zshrc` so you don't
need to export it each session:

```bash
echo 'export SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so' >> ~/.zshrc
```

Expected: all `TestPKCS11*` tests pass; the `P256K` test returns
`ErrUnsupportedCurve` (secp256k1 is not in the standard PKCS#11 EC OID table).

## 10. Reset the token

If you need a clean slate:

```bash
softhsm2-util --delete-token --token rocketvault
softhsm2-util --init-token --slot 0 --label rocketvault --so-pin 0000 --pin 1234
```

## Supported algorithms

| Operation | Algorithms |
|-----------|-----------|
| Sign / Verify | RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512 |
| Encrypt / Decrypt | RSA-OAEP (SHA-1), RSA-OAEP-256 (SHA-256) |
| Key generation | RSA 2048/4096, ECDSA P-256 / P-384 / P-521 |

P-256K (secp256k1) is handled by the software provider regardless of HSM
config, because it is not in the standard PKCS#11 EC OID table.
