# Config Rationalisation Design

**Date:** 2026-03-07
**Status:** Approved
**Scope:** Configuration files only — no code changes

## Problem

Four `.rocketvault*.yaml` files existed in the project:

| File | Purpose | Status |
|------|---------|--------|
| `.rocketvault.yaml` | Development | Canonical file, actively loaded |
| `.rocketvault-test.yaml` | Test | Redundant — never auto-selected |
| `.rocketvault-staging.yaml` | Staging | Redundant — never auto-selected |
| `.rocketvault-production.yaml` | Production | Redundant — never auto-selected |

`initConfig()` in `cmd/root.go` always loads `.rocketvault.yaml` by default.
The only way to load another file is via `--config <path>`. There is no automatic
environment-based file switching. The three env-specific files were therefore unused.

Additionally, `jwt.expiry` was read by `internal/container/service_container.go:222`
but absent from all four files, causing viper to return a zero duration.

## Decision

**Option A — Minimal diff.** One missing key added, three redundant files deleted.

Rejected alternatives:
- Option B (annotated file): useful but not urgent, can be done incrementally.
- Option C (restructure viper keys): correct long-term goal but requires code changes
  across `common/encrypt.go`, `service_container.go`, and `cmd/users/admin.go`.

## Changes

### 1. Add missing `jwt.expiry` key to `.rocketvault.yaml`

```yaml
jwt:
  expiry: "15m"
```

15 minutes is the recommended JWT access token lifetime for a secrets manager.

### 2. Delete three redundant files

- `.rocketvault-test.yaml`
- `.rocketvault-staging.yaml`
- `.rocketvault-production.yaml`

All three were already covered by `.gitignore` (`*.rocketvault*.yaml`) so they
were never committed. Each environment's operator maintains their own local
`.rocketvault.yaml` with values appropriate for that machine.

## Keys the code actually reads (viper)

| Key | Read in |
|-----|---------|
| `master_key` | `common/encrypt.go` |
| `jwt_secret` | `internal/container/service_container.go` |
| `jwt.expiry` | `internal/container/service_container.go` |
| `bootstrap_token` | `cmd/users/admin.go` |
| `environment` | `internal/db/db.go` (selects DB pool preset) |
| `database.connection` | `internal/db/db.go` |
| `database.driver` | `internal/db/db.go` |
| `server.listen_addr` | `cmd/serve.go` |
| `server.read_timeout` | `server/server.go` |
| `server.write_timeout` | `server/server.go` |
| `server.idle_timeout` | `server/server.go` |
| `log.level` | `internal/logging/logging.go` |
| `log.format` | `internal/logging/logging.go` |
| `log.pretty_print` | `internal/logging/logging.go` |
| `log.file` | `internal/logging/logging.go` |
| `log.max_size_mb` | `internal/logging/logging.go` |
| `log.max_backups` | `internal/logging/logging.go` |
| `log.max_age_days` | `internal/logging/logging.go` |
| `log.rotation_method` | `internal/logging/logging.go` |
| `retry.database.*` | `internal/retry/config_loader.go` |
| `retry.external_services.*` | `internal/retry/config_loader.go` |
| `retry.circuit_breaker.*` | `internal/retry/config_loader.go` |

## Keys kept as forward-looking stubs (not yet read by code)

| Section | Planned use |
|---------|-------------|
| `monitoring.*` | Future metrics/observability integration |
| `health.*` | Future health-check endpoint configuration |
| `development.*` | Future dev-mode feature flags |
