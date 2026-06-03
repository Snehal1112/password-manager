#!/usr/bin/env bash
# Capture real RocketVault API responses for the admin manual, with secrets redacted.
# Produces docs/.manual-capture.json. Rerunnable; uses a throwaway DB.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CFG=/tmp/rv-capture.yaml
DB=/tmp/rv-capture.db
BIN=/tmp/rocketvault-capture
TOK="***SECRET-REMOVED-2026-08-17***"
B=http://localhost:8774

cp "$ROOT/.rocketvault.yaml" "$CFG"
sed -i "s#./dev-rocketvault.db#$DB#" "$CFG"
rm -f "$DB"
( cd "$ROOT" && go build -o "$BIN" . )

# Bootstrap admin (CLI-only) and extract the TOTP base32 secret.
SECRET=$("$BIN" users admin --config "$CFG" --admin-username admin \
  --admin-password admin123 --bootstrap-token "$TOK" 2>/dev/null \
  | grep -oE 'secret=[A-Z2-7]+' | head -1 | cut -d= -f2)

# Start the server on the throwaway DB.
"$BIN" serve --config "$CFG" >/tmp/rv-capture-server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for i in $(seq 1 20); do curl -sf "$B/api/v1/health/live" >/dev/null && break; sleep 0.5; done

CODE=$(oathtool --totp --base32 "$SECRET")
LOGIN=$(curl -s -X POST "$B/api/v1/users/login" -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$CODE\"}")
TOKEN=$(echo "$LOGIN" | jq -r .token)
A="Authorization: Bearer $TOKEN"

post(){ curl -s -X POST "$B$1" -H "$A" -H "Content-Type: application/json" -d "$2"; }
get(){ curl -s "$B$1" -H "$A"; }

# Exercise endpoints; collect into one object keyed by a stable label.
SECRET_OBJ=$(post /api/v1/secrets '{"name":"db-password","value":"s3cret","tags":["database"]}')
SID=$(echo "$SECRET_OBJ" | jq -r .id)
KEY_OBJ=$(post /api/v1/keys '{"name":"my-rsa-key","type":"RSA","bits":2048}')
VAULT_OBJ=$(post /api/v1/vaults '{"name":"team-alpha"}')
SA_OBJ=$(post /api/v1/service-accounts '{"name":"ci-pipeline","description":"CI"}')
HEALTH_OBJ=$(get /api/v1/health)
JWKS_OBJ=$(curl -s "$B/jwks.json")

# Assemble, then redact sensitive fields to placeholders.
jq -n \
  --argjson login "$LOGIN" \
  --argjson secret "$SECRET_OBJ" \
  --argjson secret_get "$(get /api/v1/secrets/$SID)" \
  --argjson key "$KEY_OBJ" \
  --argjson vault "$VAULT_OBJ" \
  --argjson sa "$SA_OBJ" \
  --argjson health "$HEALTH_OBJ" \
  --argjson jwks "$JWKS_OBJ" \
  '{login:$login, secret_create:$secret, secret_get:$secret_get, key_create:$key,
    vault_create:$vault, service_account:$sa, health:$health, jwks:$jwks}' \
| jq '
   (.login.token, .login.refresh_token) |= "<redacted-jwt>"
 | (.service_account.client_secret) |= "<shown-once-redacted>"
 | (.secret_get.value) |= "<decrypted-value>"
 | (if .key_create.n then .key_create.n = "<base64url-modulus>" else . end)
 | (.jwks.keys[]?.n) |= "<base64url-modulus>"
' > "$ROOT/docs/.manual-capture.json"

echo "Wrote docs/.manual-capture.json"
