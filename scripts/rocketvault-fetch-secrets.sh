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
