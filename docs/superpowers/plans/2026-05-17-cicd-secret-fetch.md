# CI/CD Secret Fetch Script Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver `scripts/rocketvault-fetch-secrets.sh` — a self-contained shell script that authenticates to RocketVault via OAuth2 client credentials and exports fetched secrets as environment variables (and optionally writes them to a `.env` file).

**Architecture:** Single shell script with four phases: input validation, token exchange, secret fetch loop, cleanup. No server-side changes. Dependencies are `curl` and `jq` only.

**Tech Stack:** bash, curl, jq

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `scripts/rocketvault-fetch-secrets.sh` | The entire implementation |

---

## Task 1: Create the script skeleton with input validation

**Files:**
- Create: `scripts/rocketvault-fetch-secrets.sh`

- [ ] **Step 1: Create the script file with the validation block**

```bash
#!/usr/bin/env bash
# Fetch secrets from RocketVault and export them as environment variables.
# Usage: source scripts/rocketvault-fetch-secrets.sh
# Required env vars: VAULT_URL, VAULT_CLIENT_ID, VAULT_CLIENT_SECRET, VAULT_SECRETS
# Optional env vars: VAULT_ENV_FILE, VAULT_INSECURE

set +x  # Never trace — prevents secret values leaking into CI logs.

_rv_error() {
  echo "[rocketvault] ERROR: $*" >&2
}

# Validate required inputs.
if [ -z "${VAULT_URL:-}" ]; then
  _rv_error "VAULT_URL is not set"
  return 1 2>/dev/null || exit 1
fi
if [ -z "${VAULT_CLIENT_ID:-}" ]; then
  _rv_error "VAULT_CLIENT_ID is not set"
  return 1 2>/dev/null || exit 1
fi
if [ -z "${VAULT_CLIENT_SECRET:-}" ]; then
  _rv_error "VAULT_CLIENT_SECRET is not set"
  return 1 2>/dev/null || exit 1
fi
if [ -z "${VAULT_SECRETS:-}" ]; then
  _rv_error "VAULT_SECRETS is not set"
  return 1 2>/dev/null || exit 1
fi
```

> `return 1 2>/dev/null || exit 1` handles both sourced and executed invocations.

- [ ] **Step 2: Make the script executable**

```bash
chmod +x scripts/rocketvault-fetch-secrets.sh
```

- [ ] **Step 3: Verify the script fails correctly when required vars are missing**

```bash
env -i bash -c 'source scripts/rocketvault-fetch-secrets.sh; echo "should not reach here"'
```

Expected output:
```
[rocketvault] ERROR: VAULT_URL is not set
```
Exit code should be non-zero:
```bash
echo $?  # → 1
```

- [ ] **Step 4: Commit**

```bash
git add scripts/rocketvault-fetch-secrets.sh
git commit -m "feat(scripts): add rocketvault secret fetch script skeleton"
```

---

## Task 2: Add the OAuth2 token exchange

**Files:**
- Modify: `scripts/rocketvault-fetch-secrets.sh`

- [ ] **Step 1: Append the curl flags helper and token exchange block to the script**

Add after the validation block:

```bash
# Build curl flags — add -k only when VAULT_INSECURE=1.
_rv_curl_flags=""
if [ "${VAULT_INSECURE:-0}" = "1" ]; then
  _rv_curl_flags="-k"
fi

# Exchange client credentials for a short-lived Bearer token.
_rv_token_response=$(
  curl -sf ${_rv_curl_flags} \
    -X POST "${VAULT_URL}/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=${VAULT_CLIENT_ID}" \
    --data-urlencode "client_secret=${VAULT_CLIENT_SECRET}"
)

if [ $? -ne 0 ] || [ -z "${_rv_token_response}" ]; then
  _rv_error "Failed to reach ${VAULT_URL}/oauth2/token — check VAULT_URL and network access"
  unset _rv_token_response _rv_curl_flags
  return 1 2>/dev/null || exit 1
fi

_rv_token=$(printf '%s' "${_rv_token_response}" | jq -r '.access_token // empty')
if [ -z "${_rv_token}" ]; then
  _rv_error "Authentication failed — server responded but returned no access_token"
  _rv_error "Server response: ${_rv_token_response}"
  unset _rv_token_response _rv_curl_flags _rv_token
  return 1 2>/dev/null || exit 1
fi

unset _rv_token_response
```

- [ ] **Step 2: Verify the token exchange block works against a live RocketVault instance**

Start RocketVault locally if not already running:
```bash
go run main.go serve
```

Create a test service account (requires admin login first):
```bash
# Get admin token
ADMIN_TOKEN=$(curl -sf -X POST http://localhost:8774/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"<totp>"}' | jq -r '.token')

# Create service account
SA=$(curl -sf -X POST http://localhost:8774/api/v1/service-accounts \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-test"}')

echo "client_id:     $(echo $SA | jq -r '.client_id')"
echo "client_secret: $(echo $SA | jq -r '.client_secret')"
```

Then test the token exchange:
```bash
VAULT_URL=http://localhost:8774 \
VAULT_CLIENT_ID=<client_id_from_above> \
VAULT_CLIENT_SECRET=<client_secret_from_above> \
VAULT_SECRETS="DUMMY=00000000-0000-0000-0000-000000000000" \
bash -c 'set +x; source scripts/rocketvault-fetch-secrets.sh; echo "token acquired: ${#_rv_token} chars"'
```

Expected: prints `token acquired: <N> chars` with no error.

- [ ] **Step 3: Commit**

```bash
git add scripts/rocketvault-fetch-secrets.sh
git commit -m "feat(scripts): add OAuth2 token exchange to secret fetch script"
```

---

## Task 3: Add the secret fetch loop

**Files:**
- Modify: `scripts/rocketvault-fetch-secrets.sh`

- [ ] **Step 1: Append the env file setup and secret fetch loop**

Add after the token exchange block:

```bash
# Prepare the .env file if requested.
if [ -n "${VAULT_ENV_FILE:-}" ]; then
  # Wipe and restrict permissions before writing any secrets.
  : > "${VAULT_ENV_FILE}"
  chmod 600 "${VAULT_ENV_FILE}"
fi

# Fetch each secret and export it.
for _rv_pair in ${VAULT_SECRETS}; do
  _rv_var="${_rv_pair%%=*}"
  _rv_uuid="${_rv_pair#*=}"

  _rv_http_status=$(
    curl -s ${_rv_curl_flags} \
      -o /tmp/_rv_secret_body \
      -w "%{http_code}" \
      -H "Authorization: Bearer ${_rv_token}" \
      "${VAULT_URL}/api/v1/secrets/${_rv_uuid}"
  )

  if [ "${_rv_http_status}" != "200" ]; then
    _rv_error "Failed to fetch secret for ${_rv_var} (uuid=${_rv_uuid}) — HTTP ${_rv_http_status}"
    rm -f /tmp/_rv_secret_body
    unset _rv_token _rv_curl_flags _rv_pair _rv_var _rv_uuid _rv_http_status
    return 1 2>/dev/null || exit 1
  fi

  _rv_value=$(jq -r '.value // empty' /tmp/_rv_secret_body)
  rm -f /tmp/_rv_secret_body

  if [ -z "${_rv_value}" ]; then
    _rv_error "Secret ${_rv_var} (uuid=${_rv_uuid}) was fetched but has an empty value"
    unset _rv_token _rv_curl_flags _rv_pair _rv_var _rv_uuid _rv_http_status _rv_value
    return 1 2>/dev/null || exit 1
  fi

  export "${_rv_var}=${_rv_value}"

  if [ -n "${VAULT_ENV_FILE:-}" ]; then
    printf '%s=%s\n' "${_rv_var}" "${_rv_value}" >> "${VAULT_ENV_FILE}"
  fi
done

rm -f /tmp/_rv_secret_body
```

> The body is written to `/tmp/_rv_secret_body` so the HTTP status code can be captured separately via `-w "%{http_code}"`. The file is deleted immediately after reading.

- [ ] **Step 2: Verify a real secret is fetched and exported**

Create a test secret in RocketVault:
```bash
SECRET_RESPONSE=$(curl -sf -X POST http://localhost:8774/api/v1/secrets \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-db-password","value":"supersecret123"}')
SECRET_ID=$(echo $SECRET_RESPONSE | jq -r '.id')
echo "secret_id: ${SECRET_ID}"
```

Run the full script sourced:
```bash
export VAULT_URL=http://localhost:8774
export VAULT_CLIENT_ID=<client_id>
export VAULT_CLIENT_SECRET=<client_secret>
export VAULT_SECRETS="DB_PASSWORD=${SECRET_ID}"
export VAULT_ENV_FILE=/tmp/test.env

source scripts/rocketvault-fetch-secrets.sh

# DB_PASSWORD should now be set:
[ "${DB_PASSWORD}" = "supersecret123" ] && echo "PASS" || echo "FAIL: got '${DB_PASSWORD}'"
# .env file should exist with 600 perms:
ls -la /tmp/test.env
cat /tmp/test.env
```

Expected:
```
PASS
-rw------- 1 ... /tmp/test.env
DB_PASSWORD=supersecret123
```

- [ ] **Step 3: Commit**

```bash
git add scripts/rocketvault-fetch-secrets.sh
git commit -m "feat(scripts): add secret fetch loop with env var export and .env file support"
```

---

## Task 4: Add cleanup and finalize the script

**Files:**
- Modify: `scripts/rocketvault-fetch-secrets.sh`

- [ ] **Step 1: Append the cleanup block**

Add after the fetch loop:

```bash
# Clean up all internal variables so they don't pollute the caller's environment.
unset _rv_token _rv_curl_flags _rv_pair _rv_var _rv_uuid _rv_http_status _rv_value
unset -f _rv_error
```

- [ ] **Step 2: Verify internal variables are not visible after sourcing**

```bash
export VAULT_URL=http://localhost:8774
export VAULT_CLIENT_ID=<client_id>
export VAULT_CLIENT_SECRET=<client_secret>
export VAULT_SECRETS="DB_PASSWORD=${SECRET_ID}"

source scripts/rocketvault-fetch-secrets.sh

# These should all be empty/unset:
[ -z "${_rv_token}" ] && echo "_rv_token: clean" || echo "_rv_token: LEAKED"
[ -z "${_rv_curl_flags}" ] && echo "_rv_curl_flags: clean" || echo "_rv_curl_flags: LEAKED"
type _rv_error 2>/dev/null && echo "_rv_error: LEAKED" || echo "_rv_error: clean"
```

Expected:
```
_rv_token: clean
_rv_curl_flags: clean
_rv_error: clean
```

- [ ] **Step 3: Do a final review of the complete script**

Read `scripts/rocketvault-fetch-secrets.sh` and confirm:
- `set +x` is the first real line after the shebang and comments
- No `echo` or `printf` of secret values anywhere
- All `_rv_*` internal vars are unset at the end
- `chmod 600` is called on `VAULT_ENV_FILE` before any writes
- `VAULT_INSECURE` is only wired to `-k` and nothing else

- [ ] **Step 4: Commit**

```bash
git add scripts/rocketvault-fetch-secrets.sh
git commit -m "feat(scripts): add cleanup block to rocketvault secret fetch script"
```

---

## Task 5: Add usage documentation to the scripts README

**Files:**
- Modify: `scripts/README.md`

- [ ] **Step 1: Add a section for the new script to `scripts/README.md`**

Open `scripts/README.md` and append:

```markdown
## rocketvault-fetch-secrets.sh

Fetches secrets from a running RocketVault instance using the OAuth2 client
credentials flow and exports them as environment variables.

### Prerequisites

- `curl` and `jq` must be available in the shell
- A service account must exist in RocketVault (`POST /api/v1/service-accounts`)
- The service account must have read access to the target secrets via access policies

### Required environment variables

| Variable | Purpose |
|---|---|
| `VAULT_URL` | RocketVault base URL, e.g. `https://vault.internal:8774` |
| `VAULT_CLIENT_ID` | Service account client ID |
| `VAULT_CLIENT_SECRET` | Service account client secret |
| `VAULT_SECRETS` | Space-separated `ENV_VAR_NAME=secret-uuid` pairs |

### Optional environment variables

| Variable | Purpose |
|---|---|
| `VAULT_ENV_FILE` | If set, secrets are also written to this file with `chmod 600` |
| `VAULT_INSECURE` | Set to `1` to skip TLS verification (dev/self-signed certs only) |

### Usage

```sh
export VAULT_URL=https://vault.internal:8774
export VAULT_CLIENT_ID=ci-runner
export VAULT_CLIENT_SECRET=$CI_VAULT_SECRET
export VAULT_SECRETS="DB_PASSWORD=<uuid> API_KEY=<uuid>"
export VAULT_ENV_FILE=.env   # optional

source scripts/rocketvault-fetch-secrets.sh
# $DB_PASSWORD and $API_KEY are now set
```

### Security notes

- Script uses `set +x` — secret values will not appear in CI trace logs
- `.env` file is created with `chmod 600`
- All internal variables are unset after completion
- Set `VAULT_INSECURE=1` only in non-production environments
```

- [ ] **Step 2: Verify the README renders correctly**

```bash
cat scripts/README.md
```

- [ ] **Step 3: Commit**

```bash
git add scripts/README.md
git commit -m "docs(scripts): document rocketvault-fetch-secrets.sh usage"
```
