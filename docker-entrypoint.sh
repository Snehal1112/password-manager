#!/bin/sh
# Renders /app/.rocketvault.yaml from the template at
# /app/.rocketvault.docker.yaml.tmpl, substituting runtime secrets from the
# container environment.
#
# This exists because RocketVault's config loader (cmd/root.go initConfig,
# using viper) does not expand "${VAR}" placeholders inside YAML values, so
# secrets cannot reference environment variables directly. Rendering the file
# at startup keeps all secrets out of the image and out of version control,
# while letting compose/.env / Fly secrets be the single source of truth.
#
# Required env vars (all must be set — the binary will fail to start without them):
#   POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB  — database credentials
#   RV_MASTER_KEY     — AES-256-GCM master key (base64, 32 bytes)
#   RV_JWT_SECRET     — JWT HMAC secret (base64, 32 bytes)
#   RV_BOOTSTRAP_TOKEN — one-time admin bootstrap token (base64, 32 bytes)
#
# Optional env vars:
#   RV_HSM_PIN        — PKCS#11 HSM slot PIN; only meaningful when
#                        hsm.enabled is true in the rendered config (false by
#                        default here). Left empty otherwise.
set -eu

TEMPLATE="/app/.rocketvault.docker.yaml.tmpl"
RENDERED="/app/.rocketvault.yaml"

# Abort early with a clear message if any required secret is missing.
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${RV_MASTER_KEY:?RV_MASTER_KEY is required — generate with: openssl rand -base64 32}"
: "${RV_JWT_SECRET:?RV_JWT_SECRET is required — generate with: openssl rand -base64 32}"
: "${RV_BOOTSTRAP_TOKEN:?RV_BOOTSTRAP_TOKEN is required — generate with: openssl rand -base64 32}"
: "${RV_HSM_PIN:=}"

if [ -f "$TEMPLATE" ]; then
    envsubst '${POSTGRES_USER} ${POSTGRES_PASSWORD} ${POSTGRES_DB} ${RV_MASTER_KEY} ${RV_JWT_SECRET} ${RV_BOOTSTRAP_TOKEN} ${RV_CORS_ORIGINS} ${RV_ISSUER} ${RV_HSM_PIN}' \
        < "$TEMPLATE" > "$RENDERED"
fi

exec "$@"
