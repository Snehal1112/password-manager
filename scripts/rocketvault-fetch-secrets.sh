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
