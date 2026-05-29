# RocketVault — Manual Testing Guide

This guide covers every feature of RocketVault that can be tested manually via `curl`,
the CLI, or a browser. Work through the sections in order on a fresh development setup —
each section builds on the previous one.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Starting the Server](#2-starting-the-server)
3. [Health Checks](#3-health-checks)
4. [Bootstrap — First Admin User](#4-bootstrap--first-admin-user)
5. [Authentication](#5-authentication)
6. [JWT / JWKS Verification](#6-jwt--jwks-verification)
7. [User Management](#7-user-management)
8. [Secrets](#8-secrets)
9. [Secret Versions](#9-secret-versions)
10. [Keys](#10-keys)
11. [Certificates](#11-certificates)
12. [Soft Delete and Purge](#12-soft-delete-and-purge)
13. [Access Policies](#13-access-policies)
14. [OAuth2 / Service Accounts](#14-oauth2--service-accounts)
15. [Key Source Providers (JWT Signing)](#15-key-source-providers-jwt-signing)
16. [OS Keychain Key Storage](#16-os-keychain-key-storage)
17. [Rate Limiting](#17-rate-limiting)
18. [CLI Commands](#18-cli-commands)
19. [Backup and Restore](#19-backup-and-restore)

---

## 1. Prerequisites

### Tools

```bash
# Required
go version          # 1.25+
curl --version
jq --version        # brew install jq / apt install jq

# For keychain tests (Linux)
apt install libsecret-tools    # provides secret-tool

# For JWT signature verification (optional)
pip install PyJWT              # or: cargo install jwt-cli
```

### Environment

```bash
# Clone and enter the project
cd /path/to/rocketvault

# Confirm config exists
cat .rocketvault.yaml | grep -E "server|bootstrap_token|jwt"
```

Expected values from the dev config:

| Setting | Value |
|---------|-------|
| Server address | `:8774` |
| Bootstrap token | `***SECRET-REMOVED-2026-08-17***` |
| JWT key source | `os_store` |
| JWT expiry | `1h` |

### Convenience alias

All examples below use `$BASE`. Set it once:

```bash
export BASE=http://localhost:8774
```

---

## 2. Starting the Server

```bash
go run main.go serve
```

Expected log output on first run:

```
OSStoreProvider: no key in keychain, auto-generating RSA-2048 key
OSStoreProvider: loaded JWT signing key from OS keychain      ← keychain available
# OR
OSStoreProvider: keychain unavailable, falling back to PEM file  ← headless
Retry service initialized successfully
Api configured with basePath=/api/v1
Initialized api Vault,Secrets,Users,Keys,Certificates,Health,Config,Deleted,...
```

The server listens on `http://localhost:8774`.

---

## 3. Health Checks

These endpoints require no authentication.

### Liveness

```bash
curl -s $BASE/api/v1/health/live | jq .
```

Expected:
```json
{"status":"OK"}
```

### Readiness

```bash
curl -s $BASE/api/v1/health/ready | jq .
```

Expected:
```json
{"status":"OK"}
```

### Full health

```bash
curl -s $BASE/api/v1/health | jq .
```

Expected: JSON with database connection status and metrics.

### Frontend config (public)

```bash
curl -s $BASE/api/v1/config | jq .
```

Expected:
```json
{
  "feature_flags": {},
  "public_api_url": "http://localhost:8774",
  "sentry_dsn": ""
}
```

---

## 4. Bootstrap — First Admin User

The bootstrap token lets you create the first admin user without being authenticated.
It can only be used once.

```bash
curl -s -X POST $BASE/api/v1/users/admin \
  -H "Content-Type: application/json" \
  -d '{
    "admin_username": "admin",
    "admin_password": "admin123",
    "bootstrap_token": "***SECRET-REMOVED-2026-08-17***"
  }' | jq .
```

Expected:
```json
{
  "id": "...",
  "username": "admin",
  "role": "admin",
  "totp_secret": "BASE32ENCODEDSTRING...",
  "totp_qr_url": "otpauth://totp/..."
}
```

**Important:** Scan the `totp_qr_url` with an authenticator app (Google Authenticator,
Authy, etc.) before proceeding. All login requests require a valid TOTP code.

If you don't have an authenticator app handy, you can derive the current TOTP code:

```bash
# Install oathtool: apt install oathtool
oathtool --totp --base32 "YOUR_TOTP_SECRET_HERE"
```

---

## 5. Authentication

### Login

```bash
TOKEN=$(curl -s -X POST $BASE/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123",
    "totp_code": "123456"
  }' | jq -r .token)

echo "Token: $TOKEN"
```

Expected: a JWT string (three base64 segments separated by dots).

Save the token — all subsequent requests use it:

```bash
export AUTH="-H \"Authorization: Bearer $TOKEN\""
# Or inline in each curl call as shown below
```

### Refresh token

Login also returns a `refresh_token`. Use it to get a new access token without re-entering
your password and TOTP code:

```bash
REFRESH=$(curl -s -X POST $BASE/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"123456"}' \
  | jq -r .refresh_token)

curl -s -X POST $BASE/api/v1/users/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH\"}" | jq .
```

Expected: new `token` and `refresh_token`.

### List sessions

```bash
curl -s $BASE/api/v1/users/sessions \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Expected: array of active sessions with IDs and creation times.

### Revoke a session

```bash
SESSION_ID="<session_id_from_above>"

curl -s -X DELETE $BASE/api/v1/users/sessions/$SESSION_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Revoke all sessions

```bash
curl -s -X DELETE $BASE/api/v1/users/sessions \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 6. JWT / JWKS Verification

These tests verify the asymmetric JWT signing introduced in the RS256 migration.

### Inspect the JWKS endpoint

```bash
curl -s $BASE/jwks.json | jq .
```

Expected (RS256 with os_store):
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

Check `Cache-Control` header:

```bash
curl -si $BASE/jwks.json | grep -i cache-control
# Expected: Cache-Control: public, max-age=3600
```

### Verify token header contains kid and RS256

```bash
# Decode header (base64url — pad if needed)
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | jq .
```

Expected:
```json
{
  "alg": "RS256",
  "kid": "a1b2c3d4e5f6a7b8",
  "typ": "JWT"
}
```

### Verify kid in token matches kid in JWKS

```bash
TOKEN_KID=$(echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | jq -r .kid)
JWKS_KID=$(curl -s $BASE/jwks.json | jq -r '.keys[0].kid')

echo "Token kid : $TOKEN_KID"
echo "JWKS  kid : $JWKS_KID"
[ "$TOKEN_KID" = "$JWKS_KID" ] && echo "✓ MATCH" || echo "✗ MISMATCH"
```

### Verify jti claim is present

```bash
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .jti
# Expected: a non-empty UUID string
```

### Verify signature using JWKS public key (Python)

```bash
python3 - <<EOF
import json, urllib.request
import jwt
from jwt.algorithms import RSAAlgorithm

raw  = urllib.request.urlopen("$BASE/jwks.json").read()
keys = json.loads(raw)["keys"]
pub  = RSAAlgorithm.from_jwk(json.dumps(keys[0]))

claims = jwt.decode(
    "$TOKEN", pub,
    algorithms=["RS256"],
    audience="PASSWORD_MANAGER",
    options={"verify_iss": False}
)
print("✓ Signature valid. sub =", claims["sub"])
print("  username =", claims["username"])
print("  role     =", claims["role"])
EOF
```

### Test JWKS rotate (os_store — should return 400)

```bash
curl -s -X POST $BASE/api/v1/jwks/rotate \
  -H "Authorization: Bearer $TOKEN" | jq .
# Expected: 400, message contains "self_pki"
```

---

## 7. User Management

### Create a regular user (admin only)

```bash
curl -s -X POST $BASE/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "alicepassword123",
    "role": "user"
  }' | jq .
```

Expected: user object with `id`, `username`, `role`, `totp_secret`.

Save Alice's user ID:

```bash
export ALICE_ID="<id_from_above>"
```

### List all users

```bash
curl -s $BASE/api/v1/users \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Get a specific user

```bash
curl -s $BASE/api/v1/users/$ALICE_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Update a user

```bash
curl -s -X PUT $BASE/api/v1/users/$ALICE_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}' | jq .
```

### Delete a user

```bash
curl -s -X DELETE $BASE/api/v1/users/$ALICE_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 8. Secrets

Secrets are encrypted at rest. Only the owning user (or admin) can read them.

### Create a secret

```bash
SECRET_ID=$(curl -s -X POST $BASE/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "db-password",
    "value": "supersecret123",
    "tags": ["database", "production"]
  }' | jq -r .id)

echo "Secret ID: $SECRET_ID"
```

### List secrets

```bash
curl -s $BASE/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Get a secret (decrypted)

```bash
curl -s $BASE/api/v1/secrets/$SECRET_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Expected: `value` field contains the plaintext `"supersecret123"`.

### Update a secret

```bash
curl -s -X PUT $BASE/api/v1/secrets/$SECRET_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "newpassword456", "tags": ["database"]}' | jq .
```

### Generate a random secret value

```bash
curl -s -X POST $BASE/api/v1/secrets/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "api-key", "length": 32, "type": "alphanumeric"}' | jq .
```

### Export secrets

```bash
curl -s -X POST $BASE/api/v1/secrets/export \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "json"}' | jq .
```

### Import secrets

```bash
curl -s -X POST $BASE/api/v1/secrets/import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "secrets": [
      {"name": "imported-key", "value": "importedvalue", "tags": ["imported"]}
    ]
  }' | jq .
```

### Delete a secret (soft delete)

```bash
curl -s -X DELETE $BASE/api/v1/secrets/$SECRET_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

This soft-deletes the secret. See [Section 12](#12-soft-delete-and-purge) to restore or purge it.

---

## 9. Secret Versions

Every time you update a secret's value a new version is created. Old versions are
retained and readable.

### Create a secret and update it twice

```bash
VER_SECRET=$(curl -s -X POST $BASE/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"versioned-secret","value":"v1"}' | jq -r .id)

curl -s -X PUT $BASE/api/v1/secrets/$VER_SECRET \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"v2"}' | jq .

curl -s -X PUT $BASE/api/v1/secrets/$VER_SECRET \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"v3"}' | jq .
```

### List all versions

```bash
curl -s $BASE/api/v1/secrets/$VER_SECRET/versions \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Expected: three versions with version numbers 1, 2, 3.

### Get a specific version

```bash
curl -s $BASE/api/v1/secrets/$VER_SECRET/versions/1 \
  -H "Authorization: Bearer $TOKEN" | jq .
# Expected: value = "v1"
```

### Get the latest version

```bash
curl -s $BASE/api/v1/secrets/$VER_SECRET/versions/latest \
  -H "Authorization: Bearer $TOKEN" | jq .
# Expected: value = "v3"
```

---

## 10. Keys

RocketVault stores RSA and ECDSA private keys, encrypted at rest.

### Create an RSA key

```bash
KEY_ID=$(curl -s -X POST $BASE/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-rsa-key",
    "type": "RSA",
    "tags": ["signing"]
  }' | jq -r .id)

echo "Key ID: $KEY_ID"
```

### Create an ECDSA key

```bash
ECDSA_KEY_ID=$(curl -s -X POST $BASE/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-ecdsa-key",
    "type": "ECDSA",
    "tags": ["signing", "jwt"]
  }' | jq -r .id)
```

### List keys

```bash
curl -s $BASE/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Get a key

```bash
curl -s $BASE/api/v1/keys/$KEY_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Rotate a key

```bash
curl -s -X POST $BASE/api/v1/keys/$KEY_ID/rotate \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Expected: new key material with same name, revoked flag set on old version.

### Wrap (encrypt) data with a key

```bash
curl -s -X POST $BASE/api/v1/keys/$KEY_ID/wrap \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "sensitive data to encrypt"}' | jq .
```

### Unwrap (decrypt) data with a key

```bash
CIPHERTEXT="<ciphertext_from_wrap_above>"

curl -s -X POST $BASE/api/v1/keys/$KEY_ID/unwrap \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext\": \"$CIPHERTEXT\"}" | jq .
```

Expected: `plaintext` = `"sensitive data to encrypt"`.

### Update a key

```bash
curl -s -X PUT $BASE/api/v1/keys/$KEY_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-rsa-key-renamed", "tags": ["signing", "renamed"]}' | jq .
```

### Delete a key (soft delete)

```bash
curl -s -X DELETE $BASE/api/v1/keys/$KEY_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 11. Certificates

### Create a self-signed certificate

```bash
CERT_ID=$(curl -s -X POST $BASE/api/v1/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-tls-cert",
    "common_name": "example.com",
    "organization": "Acme Corp",
    "validity_days": 365,
    "key_type": "RSA",
    "key_size": 2048
  }' | jq -r .id)

echo "Certificate ID: $CERT_ID"
```

### List certificates

```bash
curl -s $BASE/api/v1/certificates \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Get a certificate

```bash
curl -s $BASE/api/v1/certificates/$CERT_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Update a certificate

```bash
curl -s -X PUT $BASE/api/v1/certificates/$CERT_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-tls-cert-updated"}' | jq .
```

### Delete a certificate (soft delete)

```bash
curl -s -X DELETE $BASE/api/v1/certificates/$CERT_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 12. Soft Delete and Purge

Secrets, keys, and certificates are soft-deleted by default (retained for 30 days).
They can be restored or permanently purged.

### List soft-deleted secrets

```bash
curl -s $BASE/api/v1/deleted/secrets \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Restore a secret

```bash
DELETED_SECRET_ID="<id_of_soft_deleted_secret>"

curl -s -X POST $BASE/api/v1/deleted/secrets/$DELETED_SECRET_ID/restore \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Permanently purge a secret

```bash
curl -s -X DELETE $BASE/api/v1/deleted/secrets/$DELETED_SECRET_ID/purge \
  -H "Authorization: Bearer $TOKEN" | jq .
```

After purging, the secret is gone permanently. Attempting to get or restore it returns 404.

### Same pattern for keys and certificates

```bash
# Deleted keys
curl -s $BASE/api/v1/deleted/keys \
  -H "Authorization: Bearer $TOKEN" | jq .

curl -s -X POST $BASE/api/v1/deleted/keys/$KEY_ID/restore \
  -H "Authorization: Bearer $TOKEN" | jq .

curl -s -X DELETE $BASE/api/v1/deleted/keys/$KEY_ID/purge \
  -H "Authorization: Bearer $TOKEN" | jq .

# Deleted certificates
curl -s $BASE/api/v1/deleted/certificates \
  -H "Authorization: Bearer $TOKEN" | jq .

curl -s -X POST $BASE/api/v1/deleted/certificates/$CERT_ID/restore \
  -H "Authorization: Bearer $TOKEN" | jq .

curl -s -X DELETE $BASE/api/v1/deleted/certificates/$CERT_ID/purge \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 13. Access Policies

Access policies control which users or service accounts can access which resources.

### Create an access policy

```bash
POLICY_ID=$(curl -s -X POST $BASE/api/v1/access-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "read-db-secrets",
    "principal_id": "'$ALICE_ID'",
    "resource_type": "secret",
    "resource_id": "'$SECRET_ID'",
    "actions": ["read"]
  }' | jq -r .id)

echo "Policy ID: $POLICY_ID"
```

### List all access policies

```bash
curl -s $BASE/api/v1/access-policies \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Get a policy

```bash
curl -s $BASE/api/v1/access-policies/$POLICY_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### List policies by principal

```bash
curl -s $BASE/api/v1/access-policies/principal/$ALICE_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Update a policy

```bash
curl -s -X PUT $BASE/api/v1/access-policies/$POLICY_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"actions": ["read", "update"]}' | jq .
```

### Delete a policy

```bash
curl -s -X DELETE $BASE/api/v1/access-policies/$POLICY_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 14. OAuth2 / Service Accounts

Service accounts allow non-human callers (CI pipelines, other services) to authenticate
via OAuth2 client credentials without a TOTP code.

### Create a service account

```bash
SA=$(curl -s -X POST $BASE/api/v1/service-accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-pipeline",
    "description": "CI/CD pipeline service account"
  }' | jq .)

echo "$SA" | jq .
SA_ID=$(echo "$SA" | jq -r .id)
SA_SECRET=$(echo "$SA" | jq -r .client_secret)

echo "SA ID     : $SA_ID"
echo "SA Secret : $SA_SECRET"
```

**Save `client_secret` now** — it is only shown once.

### Get an OAuth2 token (client credentials flow)

```bash
# The client_id is the service account NAME, basic-auth encoded with client_secret
CLIENT_ID="ci-pipeline"
CLIENT_SECRET="$SA_SECRET"

OAUTH_TOKEN=$(curl -s -X POST $BASE/api/v1/oauth2/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" | jq -r .access_token)

echo "OAuth token: $OAUTH_TOKEN"
```

### Use the OAuth2 token to read secrets, keys, and certificates

```bash
# Secrets
curl -s $BASE/api/v1/secrets \
  -H "Authorization: Bearer $OAUTH_TOKEN" | jq .

# A specific secret
curl -s $BASE/api/v1/secrets/$SECRET_ID \
  -H "Authorization: Bearer $OAUTH_TOKEN" | jq .

# Keys
curl -s $BASE/api/v1/keys \
  -H "Authorization: Bearer $OAUTH_TOKEN" | jq .

# A specific key
curl -s $BASE/api/v1/keys/$KEY_ID \
  -H "Authorization: Bearer $OAUTH_TOKEN" | jq .

# Certificates
curl -s $BASE/api/v1/certificates \
  -H "Authorization: Bearer $OAUTH_TOKEN" | jq .

# A specific certificate
curl -s $BASE/api/v1/certificates/$CERT_ID \
  -H "Authorization: Bearer $OAUTH_TOKEN" | jq .
```

> **Note:** Service accounts only see resources they own or have an explicit access
> policy for. If any of the above return empty results, grant access first:
>
> ```bash
> # Grant read access to a specific secret
> curl -s -X POST $BASE/api/v1/access-policies \
>   -H "Authorization: Bearer $TOKEN" \
>   -H "Content-Type: application/json" \
>   -d '{
>     "name": "ci-read-secret",
>     "principal_id": "'$SA_ID'",
>     "resource_type": "secret",
>     "resource_id": "'$SECRET_ID'",
>     "actions": ["read"]
>   }' | jq .
>
> # Grant read access to a specific key
> curl -s -X POST $BASE/api/v1/access-policies \
>   -H "Authorization: Bearer $TOKEN" \
>   -H "Content-Type: application/json" \
>   -d '{
>     "name": "ci-read-key",
>     "principal_id": "'$SA_ID'",
>     "resource_type": "key",
>     "resource_id": "'$KEY_ID'",
>     "actions": ["read"]
>   }' | jq .
>
> # Grant read access to a specific certificate
> curl -s -X POST $BASE/api/v1/access-policies \
>   -H "Authorization: Bearer $TOKEN" \
>   -H "Content-Type: application/json" \
>   -d '{
>     "name": "ci-read-cert",
>     "principal_id": "'$SA_ID'",
>     "resource_type": "certificate",
>     "resource_id": "'$CERT_ID'",
>     "actions": ["read"]
>   }' | jq .
> ```
>
> Then retry the reads with `$OAUTH_TOKEN`.

### List service accounts

```bash
curl -s $BASE/api/v1/service-accounts \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Rotate a service account secret

```bash
curl -s -X POST $BASE/api/v1/service-accounts/$SA_ID/rotate \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Expected: new `client_secret`. The old one is immediately invalidated.

### Delete a service account

```bash
curl -s -X DELETE $BASE/api/v1/service-accounts/$SA_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 15. Key Source Providers (JWT Signing)

Three providers control how the JWT signing key is stored. Switch between them in
`.rocketvault.yaml` under `jwt.key_source` and restart the server.

### os_store (default)

Uses the OS keychain (GNOME Keyring, macOS Keychain, Windows Credential Manager).
Falls back to `~/.local/share/rocketvault/jwt-signing.pem` if no keychain is available.

```yaml
jwt:
  key_source: "os_store"
  key_cn: "rocketvault"
```

Expected logs on start:
```
OSStoreProvider: loaded JWT signing key from OS keychain
# OR (headless)
OSStoreProvider: keychain unavailable, falling back to PEM file
```

Algorithm: RS256. Test with:
```bash
curl -s $BASE/jwks.json | jq '.keys[0].alg'
# Expected: "RS256"
```

### self_pki

Stores an ECDSA P-256 key in RocketVault's own encrypted database. Supports runtime
rotation.

```yaml
jwt:
  key_source: "self_pki"
  rotation_overlap: "1h"
```

Restart the server, then:

```bash
# Algorithm should now be ES256
curl -s $BASE/jwks.json | jq '.keys[0].alg'
# Expected: "ES256"

# Rotate the signing key
curl -s -X POST $BASE/api/v1/jwks/rotate \
  -H "Authorization: Bearer $TOKEN" | jq .
# Expected: {"status":"ok","new_kid":"...","overlap_until":"<RFC3339>"}

# During overlap — two kids in JWKS
curl -s $BASE/jwks.json | jq '[.keys[].kid]'

# Tokens issued before rotation still validate during the overlap window
curl -s $BASE/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" | jq .[0].name
```

### external_pki

Reads a PEM private key from an environment variable or file.

**From a file:**
```bash
# Generate a test RSA key
openssl genrsa -out /tmp/jwt-signing.pem 2048

# Add to config
# jwt:
#   key_source: "external_pki"
#   signing_key_file: "/tmp/jwt-signing.pem"
```

**From an environment variable (base64-encoded PEM):**
```bash
ROCKETVAULT_JWT_SIGNING_KEY=$(base64 -w0 /tmp/jwt-signing.pem) \
  go run main.go serve
```

Verify: algorithm is RS256 (RSA key) or ES256 (ECDSA key) depending on key type.

---

## 16. OS Keychain Key Storage

This section tests the keychain persistence introduced to protect the JWT signing key.

### Verify key is stored in the keychain

After first server start with `key_source: os_store`:

```bash
# Linux (GNOME Keyring)
secret-tool lookup service rocketvault username jwt-signing-key-rocketvault
```

Expected: the RSA private key PEM block.

### Verify kid is stable across restarts

```bash
# Record kid before restart
BEFORE=$(curl -s $BASE/jwks.json | jq -r '.keys[0].kid')
echo "Before restart: $BEFORE"

# Stop the server (Ctrl+C) and restart
go run main.go serve &
sleep 3

# kid must be identical
AFTER=$(curl -s $BASE/jwks.json | jq -r '.keys[0].kid')
echo "After restart : $AFTER"

[ "$BEFORE" = "$AFTER" ] && echo "✓ kid is stable" || echo "✗ kid changed — keychain not working"
```

### Verify old tokens still work after restart

```bash
# Get token before restart
TOKEN_PRE=$(curl -s -X POST $BASE/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"YOURCODE"}' \
  | jq -r .token)

# Restart server
# kill <server_pid> && go run main.go serve &
# sleep 3

# Old token must still validate (same key loaded from keychain)
curl -s $BASE/api/v1/users/sessions \
  -H "Authorization: Bearer $TOKEN_PRE" | jq .status
```

### Test the PEM file fallback (no keychain)

```bash
# Unset D-Bus to prevent keychain access
DBUS_SESSION_BUS_ADDRESS="" go run main.go serve
```

Expected logs:
```
OSStoreProvider: keychain unavailable, falling back to PEM file
OSStoreProvider: persisted fallback key to user home path=~/.local/share/rocketvault/jwt-signing.pem
```

Verify the file:
```bash
ls -la ~/.local/share/rocketvault/jwt-signing.pem
# Expected: mode -rw------- (0600), owned by your user
```

### Verify private key is NOT in /etc/ssl/certs

```bash
ls /etc/ssl/certs/rocketvault* 2>/dev/null || echo "✓ No private key in system certs dir"
```

Expected: no file found. The system certs directory is world-readable — private keys must never be written there.

### Test different key_cn values don't collide

```bash
# Change key_cn to "rocketvault-staging" and restart
# secret-tool shows two separate entries:
secret-tool lookup service rocketvault username jwt-signing-key-rocketvault
secret-tool lookup service rocketvault username jwt-signing-key-rocketvault-staging
# Both should exist independently
```

---

## 17. Rate Limiting

The server applies rate limits per IP:

| Endpoint group | Limit (dev config) |
|----------------|-------------------|
| All API endpoints | 300 req/min |
| Auth endpoints (`/login`, `/refresh`, `/oauth2/token`) | 5 req/min |

### Test auth rate limit

```bash
# Send 6 rapid login requests — the 6th should be rate-limited
for i in $(seq 1 6); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST $BASE/api/v1/users/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong","totp_code":"000000"}')
  echo "Request $i: HTTP $STATUS"
done
```

Expected: first 5 return `401`, sixth returns `429 Too Many Requests`.

---

## 18. CLI Commands

RocketVault has a Cobra CLI for management tasks. All CLI commands require
`--username`, `--password`, and `--totp-code` flags (or use the server API).

### Start the server

```bash
go run main.go serve
go run main.go serve --config /path/to/custom.yaml
```

### Check version

```bash
go run main.go version
```

### Database migration

```bash
go run main.go migrate
```

### Health check (CLI)

```bash
go run main.go health
```

### Secret management (CLI)

```bash
# List secrets
go run main.go secrets list \
  --username admin --password admin123 --totp-code 123456

# Get a secret
go run main.go secrets get <secret-id> \
  --username admin --password admin123 --totp-code 123456

# Create a secret
go run main.go secrets create \
  --name "my-secret" --value "my-value" \
  --username admin --password admin123 --totp-code 123456
```

### Key management (CLI)

```bash
go run main.go keys list \
  --username admin --password admin123 --totp-code 123456

go run main.go keys create \
  --name "my-key" --type RSA \
  --username admin --password admin123 --totp-code 123456
```

### User management (CLI)

```bash
# Create admin user (bootstrap)
go run main.go users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token ***SECRET-REMOVED-2026-08-17***

# List users
go run main.go users list \
  --username admin --password admin123 --totp-code 123456
```

### Certificate management (CLI)

```bash
go run main.go certificates list \
  --username admin --password admin123 --totp-code 123456
```

### Secret rotation policy (CLI)

```bash
# Create a rotation policy
go run main.go rotation create \
  --secret-id <secret-id> \
  --interval 30d \
  --username admin --password admin123 --totp-code 123456

# List rotation policies
go run main.go rotation list \
  --username admin --password admin123 --totp-code 123456

# Trigger manual rotation
go run main.go rotation rotate \
  --secret-id <secret-id> \
  --username admin --password admin123 --totp-code 123456
```

### Output formats

Most CLI commands support `--output` flag:

```bash
go run main.go secrets list --output json \
  --username admin --password admin123 --totp-code 123456

go run main.go secrets list --output table \
  --username admin --password admin123 --totp-code 123456
```

---

## 19. Backup and Restore

### Create a backup

```bash
go run main.go backup create \
  --username admin --password admin123 --totp-code 123456
```

Expected: backup file written to the configured backup directory.

### List backups

```bash
go run main.go backup list \
  --username admin --password admin123 --totp-code 123456
```

### Restore from a backup

```bash
go run main.go backup restore --file /path/to/backup.json \
  --username admin --password admin123 --totp-code 123456
```

---

## Quick Reference — All Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/health/live` | None | Liveness probe |
| GET | `/api/v1/health/ready` | None | Readiness probe |
| GET | `/api/v1/health` | None | Full health status |
| GET | `/api/v1/health/database` | JWT | Database health status |
| GET | `/api/v1/config` | None | Frontend config |
| GET | `/jwks.json` | None | JWKS public keys |
| POST | `/api/v1/users/login` | None | Login → JWT |
| POST | `/api/v1/users/refresh` | None | Refresh token |
| POST | `/api/v1/oauth2/token` | Basic (client creds) | OAuth2 token |
| GET | `/api/v1/users/sessions` | JWT | List sessions |
| DELETE | `/api/v1/users/sessions/{id}` | JWT | Revoke session |
| DELETE | `/api/v1/users/sessions` | JWT | Revoke all sessions |
| POST | `/api/v1/users` | JWT (admin) | Create user |
| GET | `/api/v1/users` | JWT (admin) | List users |
| GET | `/api/v1/users/{id}` | JWT | Get user |
| PUT | `/api/v1/users/{id}` | JWT (admin) | Update user |
| DELETE | `/api/v1/users/{id}` | JWT (admin) | Delete user |
| POST | `/api/v1/secrets` | JWT | Create secret |
| GET | `/api/v1/secrets` | JWT | List secrets |
| GET | `/api/v1/secrets/{id}` | JWT | Get secret |
| PUT | `/api/v1/secrets/{id}` | JWT | Update secret |
| DELETE | `/api/v1/secrets/{id}` | JWT | Soft-delete secret |
| POST | `/api/v1/secrets/generate` | JWT | Generate random secret |
| POST | `/api/v1/secrets/export` | JWT | Export secrets |
| POST | `/api/v1/secrets/import` | JWT | Import secrets |
| POST | `/api/v1/secrets/{id}/backup` | JWT | Backup secret item |
| POST | `/api/v1/secrets/restore` | JWT | Restore secret item |
| GET | `/api/v1/secrets/{id}/versions` | JWT | List versions |
| GET | `/api/v1/secrets/{id}/versions/{n}` | JWT | Get version n |
| GET | `/api/v1/secrets/{id}/versions/latest` | JWT | Get latest version |
| POST | `/api/v1/keys` | JWT | Create key |
| GET | `/api/v1/keys` | JWT | List keys |
| GET | `/api/v1/keys/{id}` | JWT | Get key |
| PUT | `/api/v1/keys/{id}` | JWT | Update key |
| DELETE | `/api/v1/keys/{id}` | JWT | Soft-delete key |
| POST | `/api/v1/keys/{id}/rotate` | JWT | Rotate key |
| GET | `/api/v1/keys/{id}/versions` | JWT | List key versions |
| POST | `/api/v1/keys/{id}/wrap` | JWT | Wrap (encrypt) data |
| POST | `/api/v1/keys/{id}/unwrap` | JWT | Unwrap (decrypt) data |
| POST | `/api/v1/keys/{id}/sign` | JWT | Sign payload |
| POST | `/api/v1/keys/{id}/verify` | JWT | Verify signature |
| POST | `/api/v1/keys/{id}/encrypt` | JWT | Encrypt payload |
| POST | `/api/v1/keys/{id}/decrypt` | JWT | Decrypt payload |
| POST | `/api/v1/keys/{id}/backup` | JWT | Backup key item |
| POST | `/api/v1/keys/restore` | JWT | Restore key item |
| POST | `/api/v1/certificates` | JWT | Create certificate |
| GET | `/api/v1/certificates` | JWT | List certificates |
| GET | `/api/v1/certificates/{id}` | JWT | Get certificate |
| PUT | `/api/v1/certificates/{id}` | JWT | Update certificate |
| DELETE | `/api/v1/certificates/{id}` | JWT | Soft-delete certificate |
| GET | `/api/v1/certificates/{id}/policy` | JWT | Get certificate policy |
| PUT | `/api/v1/certificates/{id}/policy` | JWT | Upsert certificate policy |
| DELETE | `/api/v1/certificates/{id}/policy` | JWT | Delete certificate policy |
| POST | `/api/v1/certificates/{id}/backup` | JWT | Backup certificate item |
| POST | `/api/v1/certificates/restore` | JWT | Restore certificate item |
| GET | `/api/v1/deleted/secrets` | JWT | List deleted secrets |
| POST | `/api/v1/deleted/secrets/{id}/restore` | JWT | Restore secret |
| DELETE | `/api/v1/deleted/secrets/{id}/purge` | JWT | Purge secret |
| GET | `/api/v1/deleted/keys/{id}` | JWT | Get deleted key |
| GET | `/api/v1/deleted/keys` | JWT | List deleted keys |
| POST | `/api/v1/deleted/keys/{id}/restore` | JWT | Restore key |
| DELETE | `/api/v1/deleted/keys/{id}/purge` | JWT | Purge key |
| GET | `/api/v1/deleted/certificates` | JWT | List deleted certs |
| POST | `/api/v1/deleted/certificates/{id}/restore` | JWT | Restore certificate |
| DELETE | `/api/v1/deleted/certificates/{id}/purge` | JWT | Purge certificate |
| GET | `/api/v1/access-policies` | JWT | List policies |
| POST | `/api/v1/access-policies` | JWT | Create policy |
| GET | `/api/v1/access-policies/{id}` | JWT | Get policy |
| PUT | `/api/v1/access-policies/{id}` | JWT | Update policy |
| DELETE | `/api/v1/access-policies/{id}` | JWT | Delete policy |
| GET | `/api/v1/access-policies/principal/{id}` | JWT | Policies by principal |
| GET | `/api/v1/audit/logs` | JWT (admin) | Query audit logs |
| GET | `/api/v1/audit/reports/soc2` | JWT (admin) | SOC 2 report |
| GET | `/api/v1/audit/reports/gdpr` | JWT (admin) | GDPR report |
| GET | `/api/v1/audit/config` | JWT (admin) | Get audit retention config |
| PATCH | `/api/v1/audit/config` | JWT (admin) | Update audit retention config |
| POST | `/api/v1/service-accounts` | JWT (admin) | Create service account |
| GET | `/api/v1/service-accounts` | JWT (admin) | List service accounts |
| GET | `/api/v1/service-accounts/{id}` | JWT (admin) | Get service account |
| DELETE | `/api/v1/service-accounts/{id}` | JWT (admin) | Delete service account |
| POST | `/api/v1/service-accounts/{id}/rotate` | JWT (admin) | Rotate SA secret |
| POST | `/api/v1/jwks/rotate` | JWT (admin) | Rotate JWT signing key |
