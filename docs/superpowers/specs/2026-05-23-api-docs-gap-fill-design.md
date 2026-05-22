# API Docs Gap-Fill Design

**Date:** 2026-05-23
**Scope:** `docs/api/` Bruno collection — targeted update to match current `api/` implementation

## Problem

The Bruno collection in `docs/api/` is missing coverage for several endpoints that exist in the implementation, and the service-account requests are filed under `oauth2/` despite living at `/api/v1/service-accounts`.

## Gaps Found

| Gap | Location |
|-----|----------|
| No `.bru` files for health endpoints | `api/health.go` — 3 routes |
| No `.bru` files for JWKS endpoints | `api/jwks.go` — 2 routes |
| No `.bru` file for config endpoint | `api/config.go` — 1 route |
| Service-account files in wrong folder | `docs/api/oauth2/` vs URL `/api/v1/service-accounts` |
| CA-signed certificate path undocumented | `CreateCertificateAPIRequest.ca_cert_id` field |
| README structure table outdated | Missing new sections, stale oauth2 description |
| `ca_cert_id` absent from env vars | `docs/api/environments/local.bru` |

## Changes

### New folder: `docs/api/service-accounts/`

Move these 5 files from `docs/api/oauth2/` (URLs are already correct — no content changes needed):
- `create-service-account.bru`
- `list-service-accounts.bru`
- `get-service-account.bru`
- `delete-service-account.bru`
- `rotate-service-account-secret.bru`

`oauth2/token.bru` stays in `oauth2/` — its URL is `/api/v1/oauth2/token`.

### New folder: `docs/api/health/`

Three files, no auth, no body:
- `health.bru` — GET `/api/v1/health`
- `ready.bru` — GET `/api/v1/health/ready`
- `live.bru` — GET `/api/v1/health/live`

### New folder: `docs/api/jwks/`

Two files:
- `get-jwks.bru` — GET `/jwks.json`, no auth (public, on root router)
- `rotate-jwks.bru` — POST `/api/v1/jwks/rotate`, bearer auth (admin only)

### New folder: `docs/api/config/`

One file:
- `get-config.bru` — GET `/api/v1/config`, no auth (public)

### New file: `docs/api/certificates/create-certificate-ca-signed.bru`

Second create-certificate example covering the CA-signed path. Includes `ca_cert_id` field alongside `key_id`. Existing `create-certificate.bru` (self-signed) is untouched.

### Updated: `docs/api/README.md`

- Collection Structure table: add `service-accounts/`, `health/`, `jwks/`, `config/`; update `oauth2/` description to "OAuth2 token endpoint only"
- Env vars table: add `ca_cert_id` row

### Updated: `docs/api/environments/local.bru`

Add `ca_cert_id` variable with empty default.

## What is NOT changed

All existing `.bru` files in `secrets/`, `keys/`, `users/`, `access-policies/`, `soft-delete/`, `auth/`, and `oauth2/token.bru` are verified correct and untouched.

## File count summary

| Action | Count |
|--------|-------|
| Moved (no content change) | 5 |
| New `.bru` files | 7 |
| Updated files | 3 |
| Deleted files | 0 |
