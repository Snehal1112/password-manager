# API Docs Vault Update — Design Spec

**Date:** 2026-06-03
**Status:** Approved

## Goal

Update the Bruno collection at `docs/api/` to reflect the multi-vault implementation. All resource routes become vault-scoped. A new `vaults/` folder covers vault lifecycle management.

## Scope

### New: `docs/api/vaults/` (8 files)

| File | Method | URL |
|---|---|---|
| `create-vault.bru` | POST | `/api/v1/vaults` |
| `list-vaults.bru` | GET | `/api/v1/vaults` |
| `get-vault.bru` | GET | `/api/v1/vaults/{{vault_name}}` |
| `update-vault.bru` | PATCH | `/api/v1/vaults/{{vault_name}}` |
| `delete-vault.bru` | DELETE | `/api/v1/vaults/{{vault_name}}` |
| `recover-vault.bru` | POST | `/api/v1/vaults/{{vault_name}}/recover` |
| `purge-vault.bru` | DELETE | `/api/v1/vaults/{{vault_name}}/purge` |
| `list-deleted-vaults.bru` | GET | `/api/v1/vaults?include_deleted=true` |

**Request bodies:**

`create-vault.bru`:
```json
{
  "name": "my-vault",
  "enabled": true,
  "purge_protection": false,
  "retention_days": 90,
  "tags": ["env:dev"]
}
```

`update-vault.bru` (all fields optional):
```json
{
  "enabled": true,
  "purge_protection": true,
  "retention_days": 30,
  "tags": ["env:prod"]
}
```

All other vault operations use `body: none`. Files are sequenced 1–8. `list-deleted-vaults.bru` uses a `params` block for `include_deleted=true`.

### Updated: existing resource `.bru` files (~40 files)

URL rewrite applied uniformly across these folders:

| Folder | Old prefix | New prefix |
|---|---|---|
| `secrets/` | `/api/v1/secrets` | `/api/v1/vaults/{{vault_name}}/secrets` |
| `keys/` | `/api/v1/keys` | `/api/v1/vaults/{{vault_name}}/keys` |
| `certificates/` | `/api/v1/certificates` | `/api/v1/vaults/{{vault_name}}/certificates` |
| `access-policies/` | `/api/v1/access-policies` | `/api/v1/vaults/{{vault_name}}/access-policies` |
| `soft-delete/` | `/api/v1/deleted/` | `/api/v1/vaults/{{vault_name}}/deleted/` |

No other changes to existing files (meta, auth, body, seq unchanged).

### Updated: environment files (3 files)

Add `vault_name: default` to `environments/local.bru`, `staging.bru`, `production.bru`.

### Updated: `README.md`

1. Add `vault_name` row to the env var table.
2. Add `vaults/` entry to the collection structure block, note vault-scoping on affected resource folders.

## Out of scope

- `auth/`, `users/`, `health/`, `jwks/`, `config/`, `oauth2/`, `service-accounts/` — unaffected, no vault-scoping on these routes.
- No new environment files, no folder renames, no seq renumbering of existing files.

## Decisions

- **Replace, don't coexist.** Legacy flat routes still work for the default vault but are not the canonical path going forward. Keeping both would create confusion.
- **`list-deleted-vaults` uses query param**, not a separate path, matching the server's actual API (`GET /api/v1/vaults?include_deleted=true`).
- **`vault_name` default is `default`** in all environments, preserving backward-compatible behaviour for users who don't set it explicitly.
