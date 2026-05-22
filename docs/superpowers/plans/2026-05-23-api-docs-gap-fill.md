# API Docs Gap-Fill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `docs/api/` Bruno collection into sync with the current `api/` implementation by adding missing endpoint files and reorganising service-account requests into their own folder.

**Architecture:** Pure file-system changes inside `docs/api/` — no Go code is touched. Each task is independent: new folders with `.bru` request files, moves of existing files, and two small text edits (README and environment file).

**Tech Stack:** Bruno `.bru` file format (plain text), Markdown, Git.

---

## File Map

| Action | Path |
|--------|------|
| Create dir | `docs/api/service-accounts/` |
| Move | `docs/api/oauth2/create-service-account.bru` → `docs/api/service-accounts/` |
| Move | `docs/api/oauth2/list-service-accounts.bru` → `docs/api/service-accounts/` |
| Move | `docs/api/oauth2/get-service-account.bru` → `docs/api/service-accounts/` |
| Move | `docs/api/oauth2/delete-service-account.bru` → `docs/api/service-accounts/` |
| Move | `docs/api/oauth2/rotate-service-account-secret.bru` → `docs/api/service-accounts/` |
| Create dir | `docs/api/health/` |
| Create | `docs/api/health/health.bru` |
| Create | `docs/api/health/ready.bru` |
| Create | `docs/api/health/live.bru` |
| Create dir | `docs/api/jwks/` |
| Create | `docs/api/jwks/get-jwks.bru` |
| Create | `docs/api/jwks/rotate-jwks.bru` |
| Create dir | `docs/api/config/` |
| Create | `docs/api/config/get-config.bru` |
| Create | `docs/api/certificates/create-certificate-ca-signed.bru` |
| Modify | `docs/api/README.md` |
| Modify | `docs/api/environments/local.bru` |

---

## Task 1: Move service-account files to their own folder

**Files:**
- Delete from: `docs/api/oauth2/create-service-account.bru`, `list-service-accounts.bru`, `get-service-account.bru`, `delete-service-account.bru`, `rotate-service-account-secret.bru`
- Create at: `docs/api/service-accounts/` (same filenames, same content)

- [ ] **Step 1: Create the new folder and move files**

```bash
mkdir docs/api/service-accounts
git mv docs/api/oauth2/create-service-account.bru docs/api/service-accounts/
git mv docs/api/oauth2/list-service-accounts.bru docs/api/service-accounts/
git mv docs/api/oauth2/get-service-account.bru docs/api/service-accounts/
git mv docs/api/oauth2/delete-service-account.bru docs/api/service-accounts/
git mv docs/api/oauth2/rotate-service-account-secret.bru docs/api/service-accounts/
```

- [ ] **Step 2: Verify files are in the right place**

```bash
ls docs/api/service-accounts/
ls docs/api/oauth2/
```

Expected: `service-accounts/` has 5 files; `oauth2/` has only `token.bru`.

- [ ] **Step 3: Commit**

```bash
git commit -m "docs(api): move service-account requests to service-accounts/ folder"
```

---

## Task 2: Add health endpoint files

**Files:**
- Create: `docs/api/health/health.bru`
- Create: `docs/api/health/ready.bru`
- Create: `docs/api/health/live.bru`

- [ ] **Step 1: Create the folder**

```bash
mkdir docs/api/health
```

- [ ] **Step 2: Create `docs/api/health/health.bru`**

```
meta {
  name: Health Check
  type: http
  seq: 1
}

get {
  url: {{base_url}}/api/v1/health
  body: none
  auth: none
}
```

- [ ] **Step 3: Create `docs/api/health/ready.bru`**

```
meta {
  name: Readiness Check
  type: http
  seq: 2
}

get {
  url: {{base_url}}/api/v1/health/ready
  body: none
  auth: none
}
```

- [ ] **Step 4: Create `docs/api/health/live.bru`**

```
meta {
  name: Liveness Check
  type: http
  seq: 3
}

get {
  url: {{base_url}}/api/v1/health/live
  body: none
  auth: none
}
```

- [ ] **Step 5: Verify files exist**

```bash
ls docs/api/health/
```

Expected: `health.bru  live.bru  ready.bru`

- [ ] **Step 6: Commit**

```bash
git add docs/api/health/
git commit -m "docs(api): add health endpoint Bruno requests"
```

---

## Task 3: Add JWKS endpoint files

**Files:**
- Create: `docs/api/jwks/get-jwks.bru`
- Create: `docs/api/jwks/rotate-jwks.bru`

- [ ] **Step 1: Create the folder**

```bash
mkdir docs/api/jwks
```

- [ ] **Step 2: Create `docs/api/jwks/get-jwks.bru`**

Note: this endpoint is registered on the root router at `/jwks.json` (no `/api/v1` prefix) and requires no authentication.

```
meta {
  name: Get JWKS
  type: http
  seq: 1
}

get {
  url: {{base_url}}/jwks.json
  body: none
  auth: none
}
```

- [ ] **Step 3: Create `docs/api/jwks/rotate-jwks.bru`**

Note: admin-only. Generates a new RS256/ES256 signing key pair and adds it to the active key set.

```
meta {
  name: Rotate JWKS
  type: http
  seq: 2
}

post {
  url: {{base_url}}/api/v1/jwks/rotate
  body: none
  auth: bearer
}

auth:bearer {
  token: {{token}}
}
```

- [ ] **Step 4: Verify files exist**

```bash
ls docs/api/jwks/
```

Expected: `get-jwks.bru  rotate-jwks.bru`

- [ ] **Step 5: Commit**

```bash
git add docs/api/jwks/
git commit -m "docs(api): add JWKS endpoint Bruno requests"
```

---

## Task 4: Add config endpoint file

**Files:**
- Create: `docs/api/config/get-config.bru`

- [ ] **Step 1: Create the folder**

```bash
mkdir docs/api/config
```

- [ ] **Step 2: Create `docs/api/config/get-config.bru`**

Note: public endpoint — no authentication required. Returns `feature_flags`, `public_api_url`, and `sentry_dsn`.

```
meta {
  name: Get Config
  type: http
  seq: 1
}

get {
  url: {{base_url}}/api/v1/config
  body: none
  auth: none
}
```

- [ ] **Step 3: Verify**

```bash
ls docs/api/config/
```

Expected: `get-config.bru`

- [ ] **Step 4: Commit**

```bash
git add docs/api/config/
git commit -m "docs(api): add config endpoint Bruno request"
```

---

## Task 5: Add CA-signed certificate example

**Files:**
- Create: `docs/api/certificates/create-certificate-ca-signed.bru`

The existing `create-certificate.bru` (self-signed, no `ca_cert_id`) is untouched.

- [ ] **Step 1: Create `docs/api/certificates/create-certificate-ca-signed.bru`**

`ca_cert_id` is the UUID of an existing certificate that acts as the CA. `key_id` is the UUID of the key to sign with. Both must exist in the vault before calling this endpoint.

```
meta {
  name: Create Certificate (CA-Signed)
  type: http
  seq: 4
}

post {
  url: {{base_url}}/api/v1/certificates
  body: json
  auth: bearer
}

auth:bearer {
  token: {{token}}
}

body:json {
  {
    "name": "my-ca-signed-cert",
    "key_id": "{{key_id}}",
    "ca_cert_id": "{{ca_cert_id}}",
    "validity_days": 365,
    "auto_renew": true,
    "renewal_days": 30,
    "tags": ["env:dev"]
  }
}
```

- [ ] **Step 2: Verify both certificate create files exist**

```bash
ls docs/api/certificates/create-certificate*.bru
```

Expected:
```
docs/api/certificates/create-certificate-ca-signed.bru
docs/api/certificates/create-certificate.bru
```

- [ ] **Step 3: Commit**

```bash
git add docs/api/certificates/create-certificate-ca-signed.bru
git commit -m "docs(api): add CA-signed certificate create example"
```

---

## Task 6: Update README.md

**Files:**
- Modify: `docs/api/README.md`

- [ ] **Step 1: Replace the path-parameter env vars table**

Find this block:

```markdown
| `service_account_id` | oauth2/get, delete, rotate service account |
```

Replace it with:

```markdown
| `service_account_id` | service-accounts/get, delete, rotate service account |
| `ca_cert_id` | certificates/create-certificate-ca-signed |
```

- [ ] **Step 2: Replace the Collection Structure block**

Find:

```
auth/           Login and token refresh
users/          User CRUD + session management
secrets/        Secret CRUD + generate, export, import, versioning
keys/           Key CRUD + rotate, wrap, unwrap
certificates/   Certificate CRUD
access-policies/ Policy CRUD + list by principal
soft-delete/    List, restore, purge for secrets/keys/certificates
oauth2/         OAuth2 token endpoint + service account management
```

Replace with:

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

- [ ] **Step 3: Verify the README looks correct**

```bash
cat docs/api/README.md
```

Check: `ca_cert_id` row is present, collection structure has all 12 folders.

- [ ] **Step 4: Commit**

```bash
git add docs/api/README.md
git commit -m "docs(api): update README for new folders and ca_cert_id env var"
```

---

## Task 7: Update local environment file

**Files:**
- Modify: `docs/api/environments/local.bru`

- [ ] **Step 1: Replace the file content**

Current content:

```
vars {
  base_url: http://localhost:8080
  token:
  username: admin
  password: admin123
  totp_code:
}

vars:secret [
  token,
  password,
  totp_code
]
```

New content (add `ca_cert_id` variable):

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

- [ ] **Step 2: Verify**

```bash
cat docs/api/environments/local.bru
```

Expected: `ca_cert_id:` line is present inside the `vars { }` block.

- [ ] **Step 3: Apply the same change to staging and production environment files**

```bash
cat docs/api/environments/staging.bru
cat docs/api/environments/production.bru
```

Add `ca_cert_id:` to the `vars { }` block of each, matching the same pattern as local.

- [ ] **Step 4: Commit**

```bash
git add docs/api/environments/
git commit -m "docs(api): add ca_cert_id variable to environment files"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|-----------------|------|
| Move 5 service-account files to `service-accounts/` | Task 1 |
| Create `health/` with 3 files | Task 2 |
| Create `jwks/` with 2 files | Task 3 |
| Create `config/` with 1 file | Task 4 |
| Add `create-certificate-ca-signed.bru` | Task 5 |
| Update README structure table + oauth2 description + ca_cert_id env var | Task 6 |
| Update `environments/local.bru` with `ca_cert_id` | Task 7 |

All spec requirements covered. Staging and production env files added to Task 7 since they follow the same pattern and were implicitly needed for consistency.
