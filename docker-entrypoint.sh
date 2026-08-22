#!/bin/sh
# Renders /app/.rocketvault.yaml from the single template at
# /app/.rocketvault.docker.yaml.tmpl, substituting runtime secrets and
# driver-specific values from the container environment.
#
# RV_DB_DRIVER selects the database driver (default: sqlite3):
#
#   RV_DB_DRIVER=sqlite3   (default) -- used by Railway and plain
#                           "docker run". Requires only RV_MASTER_KEY and
#                           RV_BOOTSTRAP_TOKEN. Sets RV_DATABASE_DRIVER,
#                           RV_DATABASE_CONNECTION, and RV_LOG_FILE so the
#                           SQLite file and logs land under /app/data,
#                           which must be a mounted persistent volume.
#   RV_DB_DRIVER=postgres  -- used by docker-compose.yml and fly.toml,
#                           which both set it explicitly. Additionally
#                           requires POSTGRES_USER, POSTGRES_PASSWORD, and
#                           POSTGRES_DB.
#
# This exists because RocketVault's config loader (cmd/root.go initConfig,
# using viper) does not expand "${VAR}" placeholders inside YAML values, so
# secrets cannot reference environment variables directly. Rendering the file
# at startup keeps all secrets out of the image and out of version control,
# while letting the platform's own secret store (Railway variables, compose
# .env, Fly secrets) be the single source of truth.
#
# Optional env vars for both drivers:
#   RV_ISSUER, RV_CORS_ORIGINS -- public URL / CORS origin, default to
#                                  http://localhost:8774 in the template if
#                                  left unset (envsubst substitutes "").
#   RV_HSM_PIN                 -- PKCS#11 HSM slot PIN; only meaningful when
#                                  hsm.enabled is true in the rendered
#                                  config (false by default). Left empty
#                                  otherwise.
set -eu

RV_DB_DRIVER="${RV_DB_DRIVER:-sqlite3}"
TEMPLATE="/app/.rocketvault.docker.yaml.tmpl"
RENDERED="/app/.rocketvault.yaml"

: "${RV_MASTER_KEY:?RV_MASTER_KEY is required — generate with: openssl rand -base64 32}"
: "${RV_BOOTSTRAP_TOKEN:?RV_BOOTSTRAP_TOKEN is required — generate with: openssl rand -base64 32}"
: "${RV_HSM_PIN:=}"

case "$RV_DB_DRIVER" in
    sqlite3)
        mkdir -p /app/data/logs
        RV_DATABASE_DRIVER="sqlite3"
        RV_DATABASE_CONNECTION="/app/data/rocketvault.db"
        RV_LOG_FILE="/app/data/logs/rocketvault.log"
        ;;
    postgres)
        : "${POSTGRES_USER:?POSTGRES_USER is required}"
        : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
        : "${POSTGRES_DB:?POSTGRES_DB is required}"
        RV_DATABASE_DRIVER="postgres"
        RV_DATABASE_CONNECTION="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable"
        RV_LOG_FILE="./logs/rocketvault.log"
        ;;
    *)
        echo "docker-entrypoint.sh: unknown RV_DB_DRIVER '$RV_DB_DRIVER' (expected sqlite3 or postgres)" >&2
        exit 1
        ;;
esac
export RV_DATABASE_DRIVER RV_DATABASE_CONNECTION RV_LOG_FILE

envsubst '${RV_MASTER_KEY} ${RV_BOOTSTRAP_TOKEN} ${RV_CORS_ORIGINS} ${RV_ISSUER} ${RV_HSM_PIN} ${RV_DATABASE_DRIVER} ${RV_DATABASE_CONNECTION} ${RV_LOG_FILE}' \
    < "$TEMPLATE" > "$RENDERED"

exec "$@"
