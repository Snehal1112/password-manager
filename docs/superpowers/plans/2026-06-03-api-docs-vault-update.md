# API Docs Vault Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the Bruno collection at `docs/api/` so all resource routes are vault-scoped and a new `vaults/` folder covers vault lifecycle management.

**Architecture:** Add a `vaults/` folder with 8 new `.bru` files for vault CRUD/recover/purge. Rewrite the URL in every existing resource `.bru` file (secrets, keys, certificates, access-policies, soft-delete) from the legacy flat prefix to the vault-scoped prefix `/api/v1/vaults/{{vault_name}}/...`. Add `vault_name: default` to all three environment files and update the README.

**Tech Stack:** Bruno `.bru` file format (plain text DSL). No build tools required — all changes are file edits.

---

## File Map

### Created
- `docs/api/vaults/create-vault.bru`
- `docs/api/vaults/list-vaults.bru`
- `docs/api/vaults/get-vault.bru`
- `docs/api/vaults/update-vault.bru`
- `docs/api/vaults/delete-vault.bru`
- `docs/api/vaults/recover-vault.bru`
- `docs/api/vaults/purge-vault.bru`
- `docs/api/vaults/list-deleted-vaults.bru`

### Modified (URL rewrite only)
- `docs/api/secrets/*.bru` (11 files)
- `docs/api/keys/*.bru` (8 files)
- `docs/api/certificates/*.bru` (6 files)
- `docs/api/access-policies/*.bru` (6 files)
- `docs/api/soft-delete/*.bru` (9 files)
- `docs/api/environments/local.bru`
- `docs/api/environments/staging.bru`
- `docs/api/environments/production.bru`
- `docs/api/README.md`

---

## Task 1: Create the `vaults/` folder with vault CRUD files

**Files:**
- Create: `docs/api/vaults/create-vault.bru`
- Create: `docs/api/vaults/list-vaults.bru`
- Create: `docs/api/vaults/get-vault.bru`
- Create: `docs/api/vaults/update-vault.bru`
- Create: `docs/api/vaults/delete-vault.bru`

- [ ] **Step 1: Create `docs/api/vaults/create-vault.bru`**

```
meta {
  name: Create Vault
  type: http
  seq: 1
}

post {
  url: {{base_url}}/api/v1/vaults
  body: json
  auth: bearer
}

auth:bearer {
  token: {{token}}
}

body:json {
  {
    "name": "my-vault",
    "enabled": true,
    "purge_protection": false,
    "retention_days": 90,
    "tags": ["env:dev"]
  }
}
```

- [ ] **Step 2: Create `docs/api/vaults/list-vaults.bru`**

```
meta {
  name: List Vaults
  type: http
  seq: 2
}

get {
  url: {{base_url}}/api/v1/vaults
  body: none
  auth: bearer
}

auth:bearer {
  token: {{token}}
}
```

- [ ] **Step 3: Create `docs/api/vaults/get-vault.bru`**

```
meta {
  name: Get Vault
  type: http
  seq: 3
}

get {
  url: {{base_url}}/api/v1/vaults/{{vault_name}}
  body: none
  auth: bearer
}

auth:bearer {
  token: {{token}}
}
```

- [ ] **Step 4: Create `docs/api/vaults/update-vault.bru`**

```
meta {
  name: Update Vault
  type: http
  seq: 4
}

patch {
  url: {{base_url}}/api/v1/vaults/{{vault_name}}
  body: json
  auth: bearer
}

auth:bearer {
  token: {{token}}
}

body:json {
  {
    "enabled": true,
    "purge_protection": true,
    "retention_days": 30,
    "tags": ["env:prod"]
  }
}
```

- [ ] **Step 5: Create `docs/api/vaults/delete-vault.bru`**

```
meta {
  name: Delete Vault
  type: http
  seq: 5
}

delete {
  url: {{base_url}}/api/v1/vaults/{{vault_name}}
  body: none
  auth: bearer
}

auth:bearer {
  token: {{token}}
}
```

- [ ] **Step 6: Commit**

```bash
git add docs/api/vaults/
git commit -m "docs(api): add vaults CRUD Bruno requests"
```

---

## Task 2: Create vault soft-delete operation files

**Files:**
- Create: `docs/api/vaults/recover-vault.bru`
- Create: `docs/api/vaults/purge-vault.bru`
- Create: `docs/api/vaults/list-deleted-vaults.bru`

- [ ] **Step 1: Create `docs/api/vaults/recover-vault.bru`**

```
meta {
  name: Recover Vault
  type: http
  seq: 6
}

post {
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/recover
  body: none
  auth: bearer
}

auth:bearer {
  token: {{token}}
}
```

- [ ] **Step 2: Create `docs/api/vaults/purge-vault.bru`**

```
meta {
  name: Purge Vault (Permanent Delete)
  type: http
  seq: 7
}

delete {
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/purge
  body: none
  auth: bearer
}

auth:bearer {
  token: {{token}}
}
```

- [ ] **Step 3: Create `docs/api/vaults/list-deleted-vaults.bru`**

```
meta {
  name: List Deleted Vaults
  type: http
  seq: 8
}

get {
  url: {{base_url}}/api/v1/vaults
  body: none
  auth: bearer
}

auth:bearer {
  token: {{token}}
}

params:query {
  include_deleted: true
}
```

- [ ] **Step 4: Commit**

```bash
git add docs/api/vaults/
git commit -m "docs(api): add vault recover, purge, list-deleted requests"
```

---

## Task 3: Rewrite URLs in `secrets/` folder

**Files:**
- Modify: `docs/api/secrets/list-secrets.bru`
- Modify: `docs/api/secrets/get-secret.bru`
- Modify: `docs/api/secrets/create-secret.bru`
- Modify: `docs/api/secrets/update-secret.bru`
- Modify: `docs/api/secrets/delete-secret.bru`
- Modify: `docs/api/secrets/generate-secret.bru`
- Modify: `docs/api/secrets/export-secrets.bru`
- Modify: `docs/api/secrets/import-secrets.bru`
- Modify: `docs/api/secrets/list-versions.bru`
- Modify: `docs/api/secrets/get-version.bru`
- Modify: `docs/api/secrets/get-latest-version.bru`

The rule: replace `{{base_url}}/api/v1/secrets` with `{{base_url}}/api/v1/vaults/{{vault_name}}/secrets` in the URL line of every file. Nothing else changes.

- [ ] **Step 1: Update `list-secrets.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets?page=0&per_page=20
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets?page=0&per_page=20
```

- [ ] **Step 2: Update `get-secret.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/{{secret_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/{{secret_id}}
```

- [ ] **Step 3: Update `create-secret.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets
```

- [ ] **Step 4: Update `update-secret.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/{{secret_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/{{secret_id}}
```

- [ ] **Step 5: Update `delete-secret.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/{{secret_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/{{secret_id}}
```

- [ ] **Step 6: Update `generate-secret.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/generate
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/generate
```

- [ ] **Step 7: Update `export-secrets.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/export
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/export
```

- [ ] **Step 8: Update `import-secrets.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/import
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/import
```

- [ ] **Step 9: Update `list-versions.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/{{secret_id}}/versions
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/{{secret_id}}/versions
```

- [ ] **Step 10: Update `get-version.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/{{secret_id}}/versions/{{version}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/{{secret_id}}/versions/{{version}}
```

- [ ] **Step 11: Update `get-latest-version.bru`**

Change:
```
  url: {{base_url}}/api/v1/secrets/{{secret_id}}/versions/latest
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/secrets/{{secret_id}}/versions/latest
```

- [ ] **Step 12: Commit**

```bash
git add docs/api/secrets/
git commit -m "docs(api): vault-scope secrets routes"
```

---

## Task 4: Rewrite URLs in `keys/` folder

**Files:**
- Modify: `docs/api/keys/list-keys.bru`
- Modify: `docs/api/keys/get-key.bru`
- Modify: `docs/api/keys/create-key.bru`
- Modify: `docs/api/keys/update-key.bru`
- Modify: `docs/api/keys/delete-key.bru`
- Modify: `docs/api/keys/rotate-key.bru`
- Modify: `docs/api/keys/wrap-key.bru`
- Modify: `docs/api/keys/unwrap-key.bru`

The rule: replace `{{base_url}}/api/v1/keys` with `{{base_url}}/api/v1/vaults/{{vault_name}}/keys` in the URL line of every file.

- [ ] **Step 1: Update `list-keys.bru`**

Change:
```
  url: {{base_url}}/api/v1/keys?page=0&per_page=20
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/keys?page=0&per_page=20
```

- [ ] **Step 2: Update `get-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/keys/{{key_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/keys/{{key_id}}
```

- [ ] **Step 3: Update `create-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/keys
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/keys
```

- [ ] **Step 4: Update `update-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/keys/{{key_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/keys/{{key_id}}
```

- [ ] **Step 5: Update `delete-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/keys/{{key_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/keys/{{key_id}}
```

- [ ] **Step 6: Update `rotate-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/keys/{{key_id}}/rotate
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/keys/{{key_id}}/rotate
```

- [ ] **Step 7: Update `wrap-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/keys/{{key_id}}/wrap
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/keys/{{key_id}}/wrap
```

- [ ] **Step 8: Update `unwrap-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/keys/{{key_id}}/unwrap
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/keys/{{key_id}}/unwrap
```

- [ ] **Step 9: Commit**

```bash
git add docs/api/keys/
git commit -m "docs(api): vault-scope keys routes"
```

---

## Task 5: Rewrite URLs in `certificates/` folder

**Files:**
- Modify: `docs/api/certificates/list-certificates.bru`
- Modify: `docs/api/certificates/get-certificate.bru`
- Modify: `docs/api/certificates/create-certificate.bru`
- Modify: `docs/api/certificates/create-certificate-ca-signed.bru`
- Modify: `docs/api/certificates/update-certificate.bru`
- Modify: `docs/api/certificates/delete-certificate.bru`

The rule: replace `{{base_url}}/api/v1/certificates` with `{{base_url}}/api/v1/vaults/{{vault_name}}/certificates` in the URL line of every file.

- [ ] **Step 1: Update `list-certificates.bru`**

Change:
```
  url: {{base_url}}/api/v1/certificates?page=0&per_page=20
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/certificates?page=0&per_page=20
```

- [ ] **Step 2: Update `get-certificate.bru`**

Change:
```
  url: {{base_url}}/api/v1/certificates/{{certificate_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/certificates/{{certificate_id}}
```

- [ ] **Step 3: Update `create-certificate.bru`**

Change:
```
  url: {{base_url}}/api/v1/certificates
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/certificates
```

- [ ] **Step 4: Update `create-certificate-ca-signed.bru`**

Change:
```
  url: {{base_url}}/api/v1/certificates
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/certificates
```

- [ ] **Step 5: Update `update-certificate.bru`**

Change:
```
  url: {{base_url}}/api/v1/certificates/{{certificate_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/certificates/{{certificate_id}}
```

- [ ] **Step 6: Update `delete-certificate.bru`**

Change:
```
  url: {{base_url}}/api/v1/certificates/{{certificate_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/certificates/{{certificate_id}}
```

- [ ] **Step 7: Commit**

```bash
git add docs/api/certificates/
git commit -m "docs(api): vault-scope certificates routes"
```

---

## Task 6: Rewrite URLs in `access-policies/` folder

**Files:**
- Modify: `docs/api/access-policies/list-policies.bru`
- Modify: `docs/api/access-policies/get-policy.bru`
- Modify: `docs/api/access-policies/create-policy.bru`
- Modify: `docs/api/access-policies/update-policy.bru`
- Modify: `docs/api/access-policies/delete-policy.bru`
- Modify: `docs/api/access-policies/list-by-principal.bru`

The rule: replace `{{base_url}}/api/v1/access-policies` with `{{base_url}}/api/v1/vaults/{{vault_name}}/access-policies` in the URL line of every file.

- [ ] **Step 1: Update `list-policies.bru`**

Change:
```
  url: {{base_url}}/api/v1/access-policies
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/access-policies
```

- [ ] **Step 2: Update `get-policy.bru`**

Change:
```
  url: {{base_url}}/api/v1/access-policies/{{policy_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/access-policies/{{policy_id}}
```

- [ ] **Step 3: Update `create-policy.bru`**

Change:
```
  url: {{base_url}}/api/v1/access-policies
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/access-policies
```

- [ ] **Step 4: Update `update-policy.bru`**

Change:
```
  url: {{base_url}}/api/v1/access-policies/{{policy_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/access-policies/{{policy_id}}
```

- [ ] **Step 5: Update `delete-policy.bru`**

Change:
```
  url: {{base_url}}/api/v1/access-policies/{{policy_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/access-policies/{{policy_id}}
```

- [ ] **Step 6: Update `list-by-principal.bru`**

Change:
```
  url: {{base_url}}/api/v1/access-policies/principal/{{principal_id}}
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/access-policies/principal/{{principal_id}}
```

- [ ] **Step 7: Commit**

```bash
git add docs/api/access-policies/
git commit -m "docs(api): vault-scope access-policy routes"
```

---

## Task 7: Rewrite URLs in `soft-delete/` folder

**Files:**
- Modify: `docs/api/soft-delete/list-deleted-secrets.bru`
- Modify: `docs/api/soft-delete/restore-secret.bru`
- Modify: `docs/api/soft-delete/purge-secret.bru`
- Modify: `docs/api/soft-delete/list-deleted-keys.bru`
- Modify: `docs/api/soft-delete/restore-key.bru`
- Modify: `docs/api/soft-delete/purge-key.bru`
- Modify: `docs/api/soft-delete/list-deleted-certificates.bru`
- Modify: `docs/api/soft-delete/restore-certificate.bru`
- Modify: `docs/api/soft-delete/purge-certificate.bru`

The rule: replace `{{base_url}}/api/v1/deleted/` with `{{base_url}}/api/v1/vaults/{{vault_name}}/deleted/` in the URL line of every file.

- [ ] **Step 1: Update `list-deleted-secrets.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/secrets
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/secrets
```

- [ ] **Step 2: Update `restore-secret.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/secrets/{{secret_id}}/restore
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/secrets/{{secret_id}}/restore
```

- [ ] **Step 3: Update `purge-secret.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/secrets/{{secret_id}}/purge
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/secrets/{{secret_id}}/purge
```

- [ ] **Step 4: Update `list-deleted-keys.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/keys
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/keys
```

- [ ] **Step 5: Update `restore-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/keys/{{key_id}}/restore
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/keys/{{key_id}}/restore
```

- [ ] **Step 6: Update `purge-key.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/keys/{{key_id}}/purge
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/keys/{{key_id}}/purge
```

- [ ] **Step 7: Update `list-deleted-certificates.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/certificates
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/certificates
```

- [ ] **Step 8: Update `restore-certificate.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/certificates/{{certificate_id}}/restore
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/certificates/{{certificate_id}}/restore
```

- [ ] **Step 9: Update `purge-certificate.bru`**

Change:
```
  url: {{base_url}}/api/v1/deleted/certificates/{{certificate_id}}/purge
```
To:
```
  url: {{base_url}}/api/v1/vaults/{{vault_name}}/deleted/certificates/{{certificate_id}}/purge
```

- [ ] **Step 10: Commit**

```bash
git add docs/api/soft-delete/
git commit -m "docs(api): vault-scope soft-delete routes"
```

---

## Task 8: Add `vault_name` to environment files

**Files:**
- Modify: `docs/api/environments/local.bru`
- Modify: `docs/api/environments/staging.bru`
- Modify: `docs/api/environments/production.bru`

- [ ] **Step 1: Update `local.bru`**

Current content:
```
vars {
  base_url: http://localhost:8080
  token:
  username: admin
  password: admin123
  totp_code:
  ca_cert_id:
}

vars:secret [
  token,
  password,
  totp_code
]
```

New content (add `vault_name: default` inside the `vars` block):
```
vars {
  base_url: http://localhost:8080
  token:
  username: admin
  password: admin123
  totp_code:
  vault_name: default
  ca_cert_id:
}

vars:secret [
  token,
  password,
  totp_code
]
```

- [ ] **Step 2: Update `staging.bru`**

New content:
```
vars {
  base_url: https://staging.rocketvault.example.com
  token:
  username: admin
  password:
  totp_code:
  vault_name: default
  ca_cert_id:
}

vars:secret [
  token,
  password,
  totp_code
]
```

- [ ] **Step 3: Update `production.bru`**

New content:
```
vars {
  base_url: https://rocketvault.example.com
  token:
  username: admin
  password:
  totp_code:
  vault_name: default
  ca_cert_id:
}

vars:secret [
  token,
  password,
  totp_code
]
```

- [ ] **Step 4: Commit**

```bash
git add docs/api/environments/
git commit -m "docs(api): add vault_name env var to all environments"
```

---

## Task 9: Update `README.md`

**Files:**
- Modify: `docs/api/README.md`

- [ ] **Step 1: Add `vault_name` to the path parameters table**

Find this block:
```markdown
| Variable | Used in |
|---|---|
| `user_id` | users/get-user, update-user, delete-user |
```

Add a new first row for `vault_name`:
```markdown
| Variable | Used in |
|---|---|
| `vault_name` | All vault-scoped resource routes (secrets, keys, certificates, access-policies, soft-delete) |
| `user_id` | users/get-user, update-user, delete-user |
```

- [ ] **Step 2: Update the collection structure block**

Replace:
```
auth/              Login and token refresh
users/             User CRUD + session management
secrets/           Secret CRUD + generate, export, import, versioning
keys/              Key CRUD + rotate, wrap, unwrap
certificates/      Certificate CRUD (self-signed and CA-signed)
access-policies/   Policy CRUD + list by principal
soft-delete/       List, restore, purge for secrets/keys/certificates
service-accounts/  Service account CRUD + secret rotation
oauth2/            OAuth2 token endpoint (client_credentials grant)
health/            Health, readiness, and liveness checks
jwks/              JWKS public key set + rotation (admin)
config/            Public frontend configuration endpoint
```

With:
```
vaults/            Vault CRUD + recover, purge, list-deleted
auth/              Login and token refresh
users/             User CRUD + session management
secrets/           Secret CRUD + generate, export, import, versioning (vault-scoped)
keys/              Key CRUD + rotate, wrap, unwrap (vault-scoped)
certificates/      Certificate CRUD, self-signed and CA-signed (vault-scoped)
access-policies/   Policy CRUD + list by principal (vault-scoped)
soft-delete/       List, restore, purge for secrets/keys/certificates (vault-scoped)
service-accounts/  Service account CRUD + secret rotation
oauth2/            OAuth2 token endpoint (client_credentials grant)
health/            Health, readiness, and liveness checks
jwks/              JWKS public key set + rotation (admin)
config/            Public frontend configuration endpoint
```

- [ ] **Step 3: Commit**

```bash
git add docs/api/README.md
git commit -m "docs(api): update README for vault-scoped routes"
```
