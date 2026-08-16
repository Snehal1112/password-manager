# Live Secrets Committed to Git — Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Task 7 of this plan is explicitly NOT for autonomous execution.** It requires
> a human to read its warning and type a real confirmation before any command in
> it runs. Every other task is normal automated execution.

**Goal:** Close pentest finding H4 — `.rocketvault.yaml` and ~9 other tracked
files leaking `master_key`, `jwt_secret`, `bootstrap_token` in plaintext, a
recurrence of the incident `.claude/security-incident-2026-03-07.md` already
"fixed" once. Fix the `.gitignore` pattern that never actually matched, ship a
committed `.rocketvault.yaml.example` template, untrack the real file, add a CI
guard so this can't regress silently a third time, and rotate every rotatable
secret (`bootstrap_token` directly; `master_key` via H3's tool, human-gated;
`hsm.pin` via a documented manual runbook). The git-history rewrite is a
separate, deferred document:
`docs/superpowers/plans/2026-08-16-git-history-secret-purge-followup.md`.

**Architecture:** No Go code changes except a one-line test-fixture swap
(`internal/backup/backup_test.go`) and a one-line shell-script fix
(`scripts/capture-manual-examples.sh`). Everything else is config, `.gitignore`,
docs, and CI YAML. Task order matters: `.gitignore` first (nothing else is safe
to build on a pattern that doesn't work), then the template + untracking, then
docs, then the actual secret edits, then the CI guard that proves the whole
tree is clean, then the two human-gated/manual tasks last (they depend on H3
being implemented and on real infrastructure respectively, so they are not
blocking for anything else in this plan).

**Tech Stack:** `.gitignore` glob patterns, YAML, GitHub Actions (`.github/workflows/go.yml`),
bash/`git`/`openssl`, `scripts/docsgen` (`./scripts/docs.sh build`), Go 1.24
stdlib `testing` (one fixture edit only).

**Spec:** `docs/superpowers/specs/2026-08-16-secrets-in-git-remediation-design.md`
— §"Recap: why this happened twice", §"Blast radius", §"Decision: `.gitignore`
fix + committed template", §"Decision: secret scanning in CI", §"Decision: what
runs automatically vs. what needs a human", §"Scope of the change" (1-8),
§"Explicitly out of scope", §"Verification gate".

## Global Constraints

- **Do not run `git filter-repo`, force-push, or any git-history rewrite as
  part of this plan.** That is the separate, deferred
  `docs/superpowers/plans/2026-08-16-git-history-secret-purge-followup.md`.
- **Do not edit the `jwt_secret`/`migration_window` lines in
  `doc/README_ADMIN_SETUP.md` or `docs/testing-guide.md`.** Those are H1's
  edits (`docs/superpowers/plans/2026-08-16-remove-hs256-jwt-fallback.md` Task
  4). This plan edits only the `master_key`/`bootstrap_token` lines in those
  same files. Use content-anchored edits (old_string/new_string), not raw line
  numbers, in any file H1 also touches — the two plans' edit regions do not
  overlap in content, but line numbers will drift depending on execution
  order.
- **Task 7 (`master-key rotate`, real run) hard-depends on
  `docs/superpowers/plans/2026-08-16-master-key-rotation.md` (H3) being
  implemented and merged.** The command does not exist before that. Every
  other task in this plan is independent of H1/H3's implementation status.
- **Never hardcode a newly-generated real secret value inside this plan
  document or any commit message.** Rotation steps capture generated values
  into shell variables and never echo them to a location that gets committed.
  The one exception is test-fixture values with zero production relevance
  (Task 5's `backup_test.go` key) — those are fine to write literally, the
  same way H3's own plan writes literal `testKey()` fixtures.
- Comments follow the project convention: short full sentences, ending with a
  punctuation mark. No emojis.
- Commits must be GPG-signed (repo convention); use the repo's existing `git
  commit` configuration, no `--no-gpg-sign`.
- `go build ./...` must pass after every task that touches a `.go` file
  (Task 5 only).

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `.gitignore` | Modify | Add the pattern block that actually matches `.rocketvault.yaml` and its siblings (Task 1) |
| `.rocketvault.yaml.example` | Create | Committed template with placeholder secrets, mirrors `.env.example` (Task 2) |
| `.rocketvault.yaml` | Untrack, then modify | `git rm --cached`; later, delete dead `jwt_secret`/`migration_window`, rotate `bootstrap_token` (Tasks 2, 4) |
| `CLAUDE.md` | Modify | Build-and-run + Configuration sections: `cp .rocketvault.yaml.example` step (Task 3) |
| `doc/setup.md` | Modify | Add the same setup step to the onboarding doc (Task 3) |
| `doc/README_ADMIN_SETUP.md` | Modify | `master_key`/`bootstrap_token` lines only — not `jwt_secret`/`migration_window`, that's H1's (Task 5) |
| `doc/README_ADMIN_SETUP.html` | Regenerate | Via `./scripts/docs.sh build` (Task 5) |
| `docs/testing-guide.md` | Modify | `master_key` line only — not `jwt_secret`, that's H1's (Task 5) |
| `docs/usage-guide.md` | Modify | `bootstrap_token` CLI example (Task 5) |
| `docs/usage-guide.html` | Regenerate | Via `./scripts/docs.sh build` (Task 5) |
| `docs/rocketvault-architecture.html` | Modify | Hand-written; not docsgen-rendered — edit directly (Task 5) |
| `scripts/capture-manual-examples.sh` | Modify | Read `bootstrap_token` from the copied config instead of hardcoding it (Task 5) |
| `internal/backup/backup_test.go` | Modify | Swap the compromised `master_key` literal for an unrelated test-only key (Task 5) |
| `scripts/README.md` | Modify | Genericize the `.password-manager-test.yaml` example block (Task 5) |
| `.github/workflows/go.yml` | Modify | Two new steps in the existing `security` job (Task 6) |
| `docs/runbooks/hsm-pin-rotation.md` | Create | Manual runbook, registered with docsgen (Task 8) |
| `scripts/docsgen/docs.go` | Modify | Register the new runbook (Task 8) |
| `.claude/known-bugs.md` | Modify | New entry **B10** (Task 9) |
| `.claude/security-incident-2026-03-07.md` | Modify | Append a short addendum closing the loop (Task 9) |

---

## Task 1: Fix the `.gitignore` pattern

The literal root cause: `rocketvault-*` (Application binaries section) never
matched `.rocketvault.yaml` (leading dot, no trailing dash). Nothing in the
2026-03-07 fix tested that its pattern actually worked.

**Files:**
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: a `.gitignore` block that Task 2 relies on to make `git rm --cached
  .rocketvault.yaml` stick (i.e., re-adding the file afterward is blocked).

- [ ] **Step 1: Prove the bug — verify the current pattern does NOT match**

Run: `git check-ignore -v .rocketvault.yaml`
Expected: no output, exit code `1`. This is the live regression: the file is
tracked, unignored, and nothing stops `git add .rocketvault.yaml` from
happening again.

- [ ] **Step 2: Add the fix**

In `.gitignore`, find the "Application binaries" block:

```
# Application binaries
rocketvault
rocketvault.exe
rocketvault-*
```

Replace it with:

```
# Application binaries. rocketvault-* is compiled release binaries only — it
# does NOT match .rocketvault*.yaml (leading dot, no trailing dash). See the
# dedicated block below for config files.
rocketvault
rocketvault.exe
rocketvault-*
```

Then add a new block immediately after the existing `# Config files contain
secrets — never commit` / `.password-manager*.yaml` line:

```
# RocketVault instance configuration — contains live secrets (master_key,
# bootstrap_token, hsm.pin). Never commit. Copy .rocketvault.yaml.example to
# .rocketvault.yaml and fill in generated values instead. This exact class of
# mistake shipped for 5+ months once already — see .claude/known-bugs.md (B10)
# and .claude/security-incident-2026-03-07.md.
.rocketvault.yaml
.rocketvault-*.yaml
.rocketvault.yaml.local
!.rocketvault.yaml.example
```

- [ ] **Step 3: Verify the fix — pattern now matches**

Run:
```bash
git check-ignore -v .rocketvault.yaml
git check-ignore -v .rocketvault-production.yaml
git check-ignore -v .rocketvault.yaml.local
git check-ignore -v .rocketvault.yaml.example
```
Expected: the first three each print a `.gitignore:<line>:<pattern>` match and
exit `0`. The fourth prints a match on the `!.rocketvault.yaml.example` line
(still exit `0` from `check-ignore`'s perspective — the file matches a rule,
that rule is a negation) — confirm with a second check that it is not actually
excluded:

Run: `git check-ignore -q .rocketvault.yaml.example && echo IGNORED || echo NOT_IGNORED`
Expected: `NOT_IGNORED` — the negation works, so the template stays trackable
once Task 2 creates it.

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "fix(gitignore): actually match .rocketvault.yaml and its siblings

rocketvault-* (leading-dash, no dot) never matched .rocketvault.yaml
(leading dot, no dash) — the exact reason the 2026-03-07 incident fix
regressed the very next day. Adds a dedicated block covering
.rocketvault.yaml, .rocketvault-*.yaml env-suffixed siblings, and a
.local override convention, with a negation for the committed
.rocketvault.yaml.example template (added next)."
```

---

## Task 2: `.rocketvault.yaml.example` template + untrack the real file

**Files:**
- Create: `.rocketvault.yaml.example`
- Modify: `.rocketvault.yaml` (untrack only — content edits are Task 4)

**Interfaces:**
- Consumes: Task 1's `.gitignore` block (the negation is what lets this file
  stay tracked).
- Produces: the exact structure Task 3's onboarding docs point at (`cp
  .rocketvault.yaml.example .rocketvault.yaml`).

- [ ] **Step 1: Create `.rocketvault.yaml.example`**

```yaml
# Copy this file to .rocketvault.yaml and fill in every secret value before
# running RocketVault:
#
#   cp .rocketvault.yaml.example .rocketvault.yaml
#   # then replace the two GENERATE_WITH placeholders below
#
# Generate random secrets with:
#   openssl rand -base64 32
#
# NEVER commit .rocketvault.yaml to version control — it is already in
# .gitignore. See .claude/known-bugs.md (search "B10") and
# .claude/security-incident-2026-03-07.md for what happens when a config file
# like this one gets committed anyway.

# Development Environment Configuration
# Optimized for local development and testing

# Security Configuration
# 32 random bytes, base64-encoded. Losing this key makes every stored secret
# permanently unrecoverable — back it up somewhere safe (a password manager or
# secrets vault, not another git-tracked file).
master_key: "GENERATE_WITH: openssl rand -base64 32"

# JWT signing configuration (asymmetric — RS256/ES256, no shared secret).
jwt:
  key_source: "os_store"      # os_store | self_pki | external_pki
  key_cn: "rocketvault"       # CN to search for in OS cert store
  expiry: "1h"                # token TTL
  rotation_overlap: "1h"      # old key stays in JWKS this long after rotation
  signing_key_file: ""        # ExternalPKIProvider: path to PEM private key file

# One-time token consumed by `rocketvault users admin` to bootstrap the first
# admin account. Rotate it again after that first run (set to "" or remove the
# line — seedBootstrapToken() only seeds it once).
bootstrap_token: "GENERATE_WITH: openssl rand -base64 32"

# Environment configuration affects database pool settings
environment: "development"

# Database Configuration
database:
  connection: "./dev-rocketvault.db"
  driver: "sqlite3"
  # Supported drivers: "sqlite3" (default, local file) and "postgres".
  #
  # PostgreSQL example (URL form):
  #   driver: "postgres"
  #   connection: "postgres://user:password@localhost:5432/rocketvault?sslmode=require"
  #
  # PostgreSQL example (DSN keyword form):
  #   driver: "postgres"
  #   connection: "host=localhost port=5432 user=rv password=secret dbname=rocketvault sslmode=require"
  #
  # sslmode options (Postgres): disable, require, verify-ca, verify-full.
  # Use "require" or stronger in production. If driver is omitted, it is
  # inferred from the connection string shape.

# Logging Configuration
log:
  level: "debug"
  file: "./logs/development.log"
  format: "text"
  pretty_print: true
  max_backups: 3
  max_age_days: 7
  max_size_mb: 10
  rotation_method: "size"

# Rate Limiting Configuration
rate_limit:
  default: 300  # requests per minute per IP for all endpoints
  auth: 5       # requests per minute per IP for login/refresh/oauth2 endpoints

# Server Configuration
server:
  listen_addr: ":8774"
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"
  cors_allowed_origins:
    - "http://localhost:3000"
    # Add your own frontend origin(s) here.
  http2:
    enabled: true   # HTTP/2 is enabled by default.
  tls:
    enabled: false     # Set true with cert_file/key_file to enable HTTPS.
    cert_file: ""      # Path to PEM TLS certificate.
    key_file: ""       # Path to PEM TLS private key.

# Performance Monitoring
monitoring:
  enable_metrics: true
  metrics_interval: "60s"
  slow_query_threshold: "500ms"

# Health Check Configuration
health:
  check_interval: "60s"
  database_timeout: "10s"
  enable_detailed_metrics: true

# Development-specific features
development:
  enable_debug_endpoints: true
  detailed_error_responses: true
  cors_enabled: true

# Retry Logic Configuration
retry:
  database:
    enabled: true
    max_attempts: 2
    initial_delay: "50ms"
    max_delay: "1s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "database is locked"
      - "busy"
      - "timeout"
    jitter_enabled: true

  external_services:
    enabled: true
    max_attempts: 3
    initial_delay: "100ms"
    max_delay: "5s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "no such host"
      - "timeout"
      - "temporary failure"
      - "service unavailable"
      - "too many requests"
      - "internal server error"
      - "bad gateway"
    jitter_enabled: true

  interactive:
    enabled: true
    max_attempts: 2
    initial_delay: "250ms"
    max_delay: "2s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "no such host"
      - "timeout"
      - "temporary failure"
      - "service unavailable"
      - "too many requests"
      - "internal server error"
      - "bad gateway"
    jitter_enabled: true

  service_operations:
    enabled: true
    max_attempts: 2
    initial_delay: "100ms"
    max_delay: "1s"
    backoff_multiplier: 1.5
    retryable_errors:
      - "connection refused"
      - "timeout"
      - "temporary failure"
    jitter_enabled: true

  circuit_breaker:
    failure_threshold: 3
    timeout: "30s"
    half_open_requests: 2

soft_delete:
  enabled: true
  retention_days: 30
  purge_protection: false

# Unified cache config for secrets, keys, vaults, and (reserved for future
# use) certificates/users. See docs/superpowers/specs/2026-08-14-generic-cache-config-design.md.
cache:
  secrets:
    enabled: true
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 1000
  keys:
    enabled: true
    ttl: "60s"
    cleanup_interval: "30s"
    max_entries: 500
  vaults:
    enabled: true
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
  certificates:
    enabled: false
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
  users:
    enabled: false
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500

oauth2:
  token_expiry: "30m"
  issuer: "http://localhost:8774"  # production: your real HTTPS issuer URL

# OIDC login is additive to local username/password/TOTP and disabled by
# default. Set enabled: true and fill in your issuer's real values to turn it
# on — see CLAUDE.md's OIDCService note for exactly what happens at startup
# when it's on.
oidc:
  enabled: false
  issuer_url: ""
  client_id: ""
  client_secret: ""
  redirect_url: ""
  scopes: ["openid", "profile", "email"]
  # Path to a PEM-encoded CA certificate to trust in addition to the system
  # store, for issuers whose TLS certificate is signed by a private CA. Leave
  # unset to use the system trust store only.
  ca_cert_path: ""

# Vault client configuration for secret consumption.
# Used by OTHER applications that need to fetch secrets from this RocketVault
# instance. RocketVault does NOT fetch from itself — leave client_id empty on
# the vault server itself. client_secret is intentionally absent here — set
# the VAULT_CLIENT_SECRET environment variable instead.
vault_client:
  url: "http://localhost:8774"
  client_id: ""  # service account NAME (not UUID) — leave empty on the vault server itself
  secrets: []
  # Example entry once you have a real secret to consume:
  #   secrets:
  #     - name: DB_PASSWORD
  #       uuid: "<secret-uuid-from-this-vault>"
  #       viper_key: "database.password"

# Frontend configuration exposed via GET /api/v1/config
frontend:
  public_api_url: "http://localhost:8774"
  sentry_dsn: ""

# HSM / PKCS#11 configuration.
# Set hsm.enabled: true and configure lib_path, token_label, and pin to route
# all key generation and crypto operations through a hardware security module
# or SoftHSM2. When disabled (default), the built-in Go crypto path is used
# and all keys are stored as AES-GCM encrypted PEM in the database.
#
# Dev/test setup with SoftHSM2:
#   sudo apt install softhsm2
#   softhsm2-util --init-token --slot 0 --label rocketvault --pin <your-pin> --so-pin <your-so-pin>
#
# Rotating an existing token's PIN is a separate manual procedure — see
# docs/runbooks/hsm-pin-rotation.md. Never reuse a PIN that was ever committed
# to version control.
hsm:
  enabled: false
  lib_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: rocketvault
  pin: "GENERATE_WITH: a PIN of your choosing, never committed"
  slot_id: 0   # 0 = auto-detect by token_label
```

- [ ] **Step 2: Verify the template is picked up by the `.gitignore` negation**

Run: `git status --porcelain .rocketvault.yaml.example`
Expected: `?? .rocketvault.yaml.example` (untracked, but *not* silently
ignored — if it were ignored, plain `git status` would print nothing for it at
all; confirm with `git status --ignored=matching | grep rocketvault.yaml.example`,
expected: no output).

- [ ] **Step 3: Untrack the real `.rocketvault.yaml`**

```bash
git rm --cached .rocketvault.yaml
```

This removes it from the index only — the working-tree file is untouched, so
the local dev server's config keeps working.

- [ ] **Step 4: Verify untracking took effect and the file is now protected**

```bash
git ls-files | grep -c '^\.rocketvault\.yaml$'   # expect: 0
git status --porcelain .rocketvault.yaml         # expect: "?? .rocketvault.yaml"
git check-ignore -v .rocketvault.yaml            # expect: still a real match — wait, see below
```

Note: once a path has been `git rm --cached`'d in this same working tree,
`git status` reports it as untracked (`??`) rather than ignored (`git status`
does not apply `.gitignore` retroactively to a path already removed from the
index until the next `git add -A`-style sweep, but `git check-ignore` — which
checks the pattern directly, independent of index state — must still report a
match). Confirm with `git check-ignore -v .rocketvault.yaml`: expected output
`​.gitignore:<N>:.rocketvault.yaml	.rocketvault.yaml`, exit `0`.

- [ ] **Step 5: Commit**

```bash
git add .rocketvault.yaml.example
git add -u .rocketvault.yaml   # stages the removal from tracking
git commit -m "feat(config): add .rocketvault.yaml.example, untrack the real file

Mirrors the existing .env / .env.example pattern already in this repo.
.rocketvault.yaml stays on disk (working tree untouched, local dev
keeps working) but is no longer tracked, and Task 1's .gitignore fix
now actually stops it from being re-added by accident."
```

---

## Task 3: Onboarding docs — `cp .rocketvault.yaml.example .rocketvault.yaml`

**Files:**
- Modify: `CLAUDE.md` (Build and Run → Development section; Configuration section)
- Modify: `doc/setup.md`

**Interfaces:**
- Consumes: `.rocketvault.yaml.example` (Task 2).
- Produces: nothing consumed elsewhere in this plan — purely operator-facing.

- [ ] **Step 1: Update `CLAUDE.md`'s "Development" section**

Find (under `## Build and Run`):

```markdown
### Development
```bash
go run main.go serve
```
```

Replace with:

```markdown
### Development

First-time setup (once per clone):
```bash
cp .rocketvault.yaml.example .rocketvault.yaml
# Edit .rocketvault.yaml: replace the two "GENERATE_WITH" placeholders with
# real values — for both, that means:
openssl rand -base64 32
```

Then:
```bash
go run main.go serve
```
```

- [ ] **Step 2: Update `CLAUDE.md`'s "Configuration" section**

Find:

```markdown
## Configuration

- **Main**: `.rocketvault.yaml` — the **only** config loaded at runtime
- **Test**: `test-config.yaml`
- **Docker**: `docker-compose.yml`
```

Replace with:

```markdown
## Configuration

- **Main**: `.rocketvault.yaml` — the **only** config loaded at runtime. Not
  committed (see `.rocketvault.yaml.example`); every fresh clone starts with
  `cp .rocketvault.yaml.example .rocketvault.yaml` and generates its own
  `master_key`/`bootstrap_token`.
- **Test**: `test-config.yaml`
- **Docker**: `docker-compose.yml` (`.rocketvault.docker.yaml.tmpl`, rendered
  via `envsubst` from `.env` at container start — never holds a literal secret)
```

Then, in the same file's "Config facts (2026-03-08)" list, add one bullet
after the `bootstrap_token` bullet:

```markdown
- `.rocketvault.yaml` is gitignored (fixed 2026-08-16 — see
  `.claude/known-bugs.md` § B10); `.rocketvault.yaml.example` is the committed
  template. Never add a real secret value to the `.example` file.
```

- [ ] **Step 3: Update `doc/setup.md`**

Read the current file first — it is short (24 lines: Prerequisites, Go install,
SoftHSM2 install). Append a new numbered step after the SoftHSM2 install step
(step 2), renumbering nothing else since it's the last step in the file:

```markdown

3.  Set up your local configuration:

    ```bash
    cp .rocketvault.yaml.example .rocketvault.yaml
    ```

    Then edit `.rocketvault.yaml` and replace both `GENERATE_WITH` placeholders
    (`master_key`, `bootstrap_token`) with real values from:

    ```bash
    openssl rand -base64 32
    ```

    Never commit `.rocketvault.yaml` — it is already in `.gitignore`.
```

- [ ] **Step 4: Verify the docs render correctly (no HTML source for either file)**

Neither `CLAUDE.md` nor `doc/setup.md` is in `scripts/docsgen/docs.go`'s
`docsList` — confirm with:

Run: `grep -n "CLAUDE.md\|doc/setup.md" scripts/docsgen/docs.go`
Expected: no output (neither is rendered to HTML; plain markdown files, no
regeneration step needed).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md doc/setup.md
git commit -m "docs: document the .rocketvault.yaml.example setup step

Fresh clones need a config file that doesn't exist in git anymore
after Task 2's untracking. CLAUDE.md and doc/setup.md now both point
at 'cp .rocketvault.yaml.example .rocketvault.yaml' plus openssl rand
-base64 32 for the two secrets."
```

---

## Task 4: Rotate the real `.rocketvault.yaml` — delete dead keys, rotate `bootstrap_token`

**Files:**
- Modify: `.rocketvault.yaml` (the real, now-untracked file on disk)

**Interfaces:**
- Consumes: `.rocketvault.yaml`'s current on-disk content (still has the
  compromised values from before Task 2 untracked it).
- Produces: a `.rocketvault.yaml` with no `jwt_secret`/`migration_window` keys
  and a freshly rotated `bootstrap_token`. `master_key` is untouched here —
  that's Task 7.

- [ ] **Step 1: Delete the dead `jwt_secret`/`migration_window` keys**

In `.rocketvault.yaml`, find:

```yaml
master_key: "***SECRET-REMOVED-2026-08-17***"

# Legacy HS256 secret — kept during migration window only.
jwt_secret: "***SECRET-REMOVED-2026-08-17***"

# JWT signing configuration (asymmetric, replaces jwt_secret over time).
jwt:
  key_source: "os_store"      # os_store | self_pki | external_pki
  key_cn: "rocketvault"       # CN to search for in OS cert store
  expiry: "1h"                # token TTL
  rotation_overlap: "1h"      # old key stays in JWKS this long after rotation
  migration_window: "24h"     # HS256 fallback active for this duration after upgrade
  signing_key_file: ""        # ExternalPKIProvider: path to PEM private key file
```

Replace with:

```yaml
master_key: "***SECRET-REMOVED-2026-08-17***"

# JWT signing configuration (asymmetric — RS256/ES256, no shared secret).
jwt:
  key_source: "os_store"      # os_store | self_pki | external_pki
  key_cn: "rocketvault"       # CN to search for in OS cert store
  expiry: "1h"                # token TTL
  rotation_overlap: "1h"      # old key stays in JWKS this long after rotation
  signing_key_file: ""        # ExternalPKIProvider: path to PEM private key file
```

(`master_key`'s value is untouched here on purpose — Task 7 rotates it via
H3's tool, which needs the *old* value present to decrypt existing rows.)

- [ ] **Step 2: Verify the keys are gone**

Run: `grep -n "jwt_secret\|migration_window" .rocketvault.yaml`
Expected: no output.

- [ ] **Step 3: Rotate `bootstrap_token`**

```bash
NEW_BOOTSTRAP_TOKEN="$(openssl rand -base64 32)"
sed -i "s#^bootstrap_token: .*#bootstrap_token: \"${NEW_BOOTSTRAP_TOKEN}\"#" .rocketvault.yaml
unset NEW_BOOTSTRAP_TOKEN
```

The old value (`***SECRET-REMOVED-2026-08-17***`) is now permanently
compromised — Task 9's known-bugs entry documents it as such. It is single-use
and already consumed by any instance with an existing admin, so this does not
require stopping the dev server; a future `rocketvault users admin` bootstrap
attempt (only relevant on a database with zero users) picks up the new value on
the next process restart.

- [ ] **Step 4: Verify the rotation**

```bash
grep '^bootstrap_token:' .rocketvault.yaml
```
Expected: a `bootstrap_token: "..."` line whose value is **not**
`***SECRET-REMOVED-2026-08-17***`.

- [ ] **Step 5: No commit — this file is untracked**

`.rocketvault.yaml` is no longer in the index (Task 2). There is nothing to
`git add` here; this step exists only to make explicit that Task 4 has no git
commit, unlike every other task in this plan.

---

## Task 5: Fix the ~9 other tracked files still holding the leaked literals

**Files:**
- Modify: `doc/README_ADMIN_SETUP.md`
- Modify: `docs/testing-guide.md`
- Modify: `docs/usage-guide.md`
- Modify: `docs/rocketvault-architecture.html`
- Modify: `scripts/capture-manual-examples.sh`
- Modify: `internal/backup/backup_test.go`
- Modify: `scripts/README.md`
- Regenerate: `doc/README_ADMIN_SETUP.html`, `docs/usage-guide.html`

**Interfaces:**
- Consumes: nothing from earlier tasks at compile/render time.
- Produces: the "before" state Task 6's CI grep gate checks against — every
  file in this task's list must be clean by the time Task 6 runs its
  verification.

- [ ] **Step 1: Confirm the "before" state (all nine files still dirty)**

```bash
git grep -lF \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -- . ':(exclude)docs/superpowers/' ':(exclude)docs/plans/' ':(exclude).claude/'
```
Expected output (order may vary): `.rocketvault.yaml` (already untracked by
Task 2, so it will no longer appear here — that's fine, it means one down
already), `doc/README_ADMIN_SETUP.html`, `doc/README_ADMIN_SETUP.md`,
`docs/rocketvault-architecture.html`, `docs/testing-guide.md`,
`docs/usage-guide.html`, `docs/usage-guide.md`, `internal/backup/backup_test.go`,
`scripts/README.md`, `scripts/capture-manual-examples.sh`.

- [ ] **Step 2: `doc/README_ADMIN_SETUP.md` — `master_key`/`bootstrap_token` only**

Edit 1 — the "Minimal working configuration" sample. Find:

```yaml
master_key: "***SECRET-REMOVED-2026-08-17***"
```

Replace with:

```yaml
master_key: "GENERATE_WITH: openssl rand -base64 32"
```

(Leave the `jwt_secret:` and `migration_window:` lines in this same block
untouched — H1's Task 4 edits those.)

Edit 2 — same block, find:

```yaml
bootstrap_token: "***SECRET-REMOVED-2026-08-17***"
```

Replace with:

```yaml
bootstrap_token: "GENERATE_WITH: openssl rand -base64 32"
```

Edit 3 — the "Option B — Direct CLI Command" example. Find:

```bash
./rocketvault users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token "***SECRET-REMOVED-2026-08-17***"
```

Replace with:

```bash
./rocketvault users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token "<value from your .rocketvault.yaml>"
```

Edit 4 — the "Full End-to-End Workflow" example has the identical block; apply
the same replacement there (`git grep -n
'***SECRET-REMOVED-2026-08-17***' doc/README_ADMIN_SETUP.md` after
edits 1-3 shows exactly one remaining hit at this point, plus the SQL example
below — Edit 5 gets that one).

Edit 5 — the troubleshooting SQL example. Find:

```bash
sqlite3 ./dev-rocketvault.db \
  "UPDATE bootstrap_tokens SET used=0 WHERE token='***SECRET-REMOVED-2026-08-17***';"
```

Replace with:

```bash
sqlite3 ./dev-rocketvault.db \
  "UPDATE bootstrap_tokens SET used=0 WHERE token='<your-bootstrap-token>';"
```

Also update the "Security Recommendations" section — find:

```markdown
2. Do not commit `.rocketvault.yaml` to version control — it contains the
   master key, JWT secret, and bootstrap token.
```

Replace with:

```markdown
2. `.rocketvault.yaml` is gitignored and untracked as of 2026-08-16 (see
   `.claude/known-bugs.md` § B10) — it is never committed. Copy
   `.rocketvault.yaml.example` to start a new one.
```

- [ ] **Step 3: `docs/testing-guide.md` — `master_key` only**

Find:

```yaml
master_key: "***SECRET-REMOVED-2026-08-17***"
jwt_secret: "test-jwt-secret-for-testing"
bootstrap_token: "test-bootstrap-token-12345"
```

Replace only the first line:

```yaml
master_key: "GENERATE_WITH: openssl rand -base64 32"
jwt_secret: "test-jwt-secret-for-testing"
bootstrap_token: "test-bootstrap-token-12345"
```

(`jwt_secret`/`bootstrap_token` here are already obviously-fake test values,
not the leaked literals — no change needed to them. `jwt_secret`'s *line*
itself is H1's to remove, not touched here.)

- [ ] **Step 4: `docs/usage-guide.md` — `bootstrap_token` example**

Find:

```bash
# One-time: create the first admin user using the bootstrap token from .rocketvault.yaml
./rocketvault users admin \
  --admin-username admin --admin-password admin123 \
  --bootstrap-token ***SECRET-REMOVED-2026-08-17***
```

Replace with:

```bash
# One-time: create the first admin user using the bootstrap token from .rocketvault.yaml
./rocketvault users admin \
  --admin-username admin --admin-password admin123 \
  --bootstrap-token "<value from your .rocketvault.yaml>"
```

- [ ] **Step 5: `docs/rocketvault-architecture.html` — hand-written example**

This file is in `scripts/docsgen/docs.go`'s `extraFiles` list (hand-written,
not markdown-rendered) — edit the HTML/JS content directly. Find:

```
  code:`# .rocketvault.yaml
master_key: "***SECRET-REMOVED-2026-08-17***"
# ^ base64(32 random bytes) — generate with: openssl rand -base64 32`,
```

Replace with:

```
  code:`# .rocketvault.yaml
master_key: "<GENERATE_WITH: openssl rand -base64 32>"
# ^ base64(32 random bytes)`,
```

- [ ] **Step 6: `scripts/capture-manual-examples.sh` — read the token, don't hardcode it**

Find:

```bash
CFG=/tmp/rv-capture.yaml
DB=/tmp/rv-capture.db
BIN=/tmp/rocketvault-capture
TOK="***SECRET-REMOVED-2026-08-17***"
B=http://localhost:8774

cp "$ROOT/.rocketvault.yaml" "$CFG"
sed -i "s#./dev-rocketvault.db#$DB#" "$CFG"
```

Replace with:

```bash
CFG=/tmp/rv-capture.yaml
DB=/tmp/rv-capture.db
BIN=/tmp/rocketvault-capture
B=http://localhost:8774

cp "$ROOT/.rocketvault.yaml" "$CFG"
sed -i "s#./dev-rocketvault.db#$DB#" "$CFG"
# Read the real bootstrap token from the copied config rather than hardcoding
# it here, so this script survives every future rotation automatically.
TOK=$(grep '^bootstrap_token:' "$CFG" | sed -E 's/bootstrap_token: *"([^"]*)"/\1/')
```

Verify: `bash -n scripts/capture-manual-examples.sh` (syntax check; the script
itself is not run as part of this plan — it requires a live server and
`oathtool`/`jq`).
Expected: no output (syntax OK).

- [ ] **Step 7: `internal/backup/backup_test.go` — swap the test fixture key**

Find:

```go
	os.Setenv("MASTER_KEY", "***SECRET-REMOVED-2026-08-17***") //nolint:errcheck,gosec
```

Replace with:

```go
	// A fresh, unrelated 32-byte key — not the compromised value that used to
	// ship in .rocketvault.yaml (rotated 2026-08-16, see .claude/known-bugs.md
	// § B10). This test only needs *a* valid master key, never a specific one.
	os.Setenv("MASTER_KEY", "i7I2y3WZofTpqkICx3HuWe8BJldU6TFDQk4HIlUF0K4=") //nolint:errcheck,gosec
```

Run: `go build ./... && go test ./internal/backup/... -v`
Expected: PASS — identical behavior, since any syntactically valid 32-byte
base64 key works here.

- [ ] **Step 8: `scripts/README.md` — genericize the `.password-manager-test.yaml` block**

Find:

```markdown
### Test Config (`.password-manager-test.yaml`)
```yaml
database:
  connection: "./test_restore.db"
log:
  level: "debug"
  file: "password_manager.log"
master_key: "***SECRET-REMOVED-2026-08-17***"
jwt_secret: "***SECRET-REMOVED-2026-08-17***"
bootstrap_token: "***SECRET-REMOVED-2026-08-17***"
```
```

Replace with:

```markdown
### Test Config (`.password-manager-test.yaml`)
```yaml
database:
  connection: "./test_restore.db"
log:
  level: "debug"
  file: "password_manager.log"
master_key: "your-master-key-here"
jwt_secret: "your-jwt-secret-here"
bootstrap_token: "your-bootstrap-token-here"
```
```

(This matches the placeholder style already used two sections above it in the
same file for the "Production Config" block — the test config block was the
one place this file still had real, if very old, leaked values.)

- [ ] **Step 9: Regenerate the rendered HTML docs**

Run: `./scripts/docs.sh build`
Expected: success, `doc/README_ADMIN_SETUP.html` and `docs/usage-guide.html`
rewritten from their edited markdown sources.

- [ ] **Step 10: Verify the "after" state — all nine files now clean**

```bash
git grep -lF \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -- . ':(exclude)docs/superpowers/' ':(exclude)docs/plans/' ':(exclude).claude/'
```
Expected: no output.

Note this grep runs against the **working tree via git's index/tracked-file
list**, so it will include not-yet-committed edits from this step. It does not
require the commit below to have happened first.

- [ ] **Step 11: Full build/test sanity check**

Run: `go build ./... && go test ./internal/backup/... ./...`
Expected: PASS.

- [ ] **Step 12: Commit**

```bash
git add doc/README_ADMIN_SETUP.md doc/README_ADMIN_SETUP.html \
  docs/testing-guide.md docs/usage-guide.md docs/usage-guide.html \
  docs/rocketvault-architecture.html scripts/capture-manual-examples.sh \
  internal/backup/backup_test.go scripts/README.md
git commit -m "fix(security): remove leaked secret literals from tracked docs/scripts/tests

Nine files duplicated the master_key/bootstrap_token values that were
committed in .rocketvault.yaml (plus one, scripts/README.md, still
carrying the even older .password-manager-test.yaml generation).
Replaced with placeholders, a config-driven read, or an unrelated
test-only key as appropriate. Regenerated the two docsgen-rendered
HTML files."
```

---

## Task 6: CI guard — two new steps in the `security` job

**Files:**
- Modify: `.github/workflows/go.yml`

**Interfaces:**
- Consumes: the clean state Task 2 (untracked config) and Task 5 (docs/scripts)
  produced.
- Produces: a CI gate that fails on either (a) a real RocketVault config file
  becoming tracked again, or (b) any of the six known-compromised literal
  values reappearing in a tracked, non-historical file.

- [ ] **Step 1: Add the two steps**

In `.github/workflows/go.yml`, find the `security` job:

```yaml
  security:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: govulncheck
        uses: golang/govulncheck-action@v1
        with:
          go-version-input: ""   # reads from go.mod
          go-package: ./...
```

Replace with (two new steps appended; `Set up Go`/`govulncheck` steps
unchanged):

```yaml
  security:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: govulncheck
        uses: golang/govulncheck-action@v1
        with:
          go-version-input: ""   # reads from go.mod
          go-package: ./...

      - name: No tracked RocketVault config files
        run: |
          # H4 (.claude/known-bugs.md § B10): a real .rocketvault.yaml was
          # tracked in git for 5+ months because the .gitignore pattern
          # meant to catch it never matched. This is the structural half of
          # that fix — it must never be trackable again, under any of its
          # sibling names either.
          if git ls-files | grep -E '^\.rocketvault(-.*)?\.yaml$|^\.rocketvault\.yaml\.local$'; then
            echo "::error::a real RocketVault config file is tracked in git — see .claude/known-bugs.md § B10" >&2
            exit 1
          fi

      - name: No known-compromised secret literals
        run: |
          # The specific values leaked by H4 and its 2026-03-07 predecessor.
          # This is a denylist of exact, already-compromised bytes, not a
          # general secret scanner — see the design doc for why (gitleaks
          # produced 50 findings here, nearly all false positives on test
          # fixtures; this check produces zero by construction). Docs that
          # intentionally discuss these values as history are excluded.
          if git grep -lF \
              -e '***SECRET-REMOVED-2026-08-17***' \
              -e '***SECRET-REMOVED-2026-08-17***' \
              -e '***SECRET-REMOVED-2026-08-17***' \
              -e '***SECRET-REMOVED-2026-08-17***' \
              -e '***SECRET-REMOVED-2026-08-17***' \
              -e '***SECRET-REMOVED-2026-08-17***' \
              -- . ':(exclude)docs/superpowers/' ':(exclude)docs/plans/' ':(exclude).claude/'; then
            echo "::error::a known-compromised secret literal (rotated 2026-08-16) reappeared in a tracked file — see .claude/known-bugs.md § B10" >&2
            exit 1
          fi
```

- [ ] **Step 2: Verify both checks pass locally against the current tree**

```bash
git ls-files | grep -E '^\.rocketvault(-.*)?\.yaml$|^\.rocketvault\.yaml\.local$'
echo "exit code: $?"   # expect 1 (grep found nothing)

git grep -lF \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -- . ':(exclude)docs/superpowers/' ':(exclude)docs/plans/' ':(exclude).claude/'
echo "exit code: $?"   # expect 1 (git grep found nothing)
```
Expected: both `grep`/`git grep` invocations print nothing and exit `1`
("not found" — the success case for these two checks).

- [ ] **Step 3: Verify both checks actually fail on a reintroduced secret (red/green proof)**

```bash
git rm --cached .gitignore >/dev/null 2>&1 || true   # no-op safety, ignore error
cp .rocketvault.yaml.example /tmp/rv-ci-gate-test.yaml
git add -f /tmp/rv-ci-gate-test.yaml 2>&1 | head -1   # will fail — outside repo, expected
```

That path doesn't work (outside the repo root); instead prove it inline
without ever actually staging anything real:

```bash
echo 'bootstrap_token: "***SECRET-REMOVED-2026-08-17***"' > /tmp/leak-check.txt
grep -F '***SECRET-REMOVED-2026-08-17***' /tmp/leak-check.txt
echo "exit code: $?"   # expect 0 — proves the literal-match logic itself works
rm /tmp/leak-check.txt
```
Expected: the `grep -F` line prints the match and exits `0`, confirming the
exact-string matching this CI step relies on behaves as intended. (A true
end-to-end red/green proof — actually committing a leak on a throwaway branch
and watching the workflow fail — is left to the first real CI run after this
PR opens; that is the standard way this repo's other CI gates, like
`scope-gate`, get their first real exercise too.)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/go.yml
git commit -m "ci(security): gate on tracked config files and known-leaked secrets

Two new steps in the existing security job: (1) fail if any
.rocketvault*.yaml variant is ever tracked again, (2) fail if any of
the six secret values already compromised by H4/the 2026-03-07
incident reappear in a tracked, non-historical file. Chose a precise
denylist over gitleaks after running gitleaks locally and finding 50
findings, the overwhelming majority false positives on test fixtures
— see the design doc's 'Decision: secret scanning in CI' section."
```

---

## Task 7: **HUMAN CONFIRMATION REQUIRED** — rotate `master_key` for real

**This task is not for autonomous execution.** Everything through Task 6 is
normal, reviewable, low-risk automated work. This task rewrites every
master-key-sealed row in the live dev database (`dev-rocketvault.db`, backing
the server on port 8774). **Stop here and get explicit human sign-off before
running any command in this task.**

**Prerequisite:** `docs/superpowers/plans/2026-08-16-master-key-rotation.md`
(H3) must already be implemented and merged — `rocketvault master-key rotate`
does not exist before that.

**Files:**
- Modify: `.rocketvault.yaml` (the real, untracked file — `master_key` value)
- Modify: `dev-rocketvault.db` (via the rotation tool, not a direct edit)

**Interfaces:**
- Consumes: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY
  [--dry-run]` (H3's CLI, once implemented).
- Produces: nothing consumed by later tasks in this plan.

- [ ] **Step 1: STOP — obtain explicit human go-ahead**

Do not proceed past this line without a human explicitly confirming, in this
conversation, that they want the following commands run against the real dev
database right now. If that confirmation has not been given, stop this task
here and leave it unchecked; Tasks 8-10 do not depend on it and can proceed
independently.

- [ ] **Step 2: Back up the database**

```bash
cp ./dev-rocketvault.db ./dev-rocketvault.db.pre-rotation
```

- [ ] **Step 3: Stop the running dev server**

The rotation tool detects concurrent writes and aborts, but a clean stop
avoids that abort entirely. Find and stop the process listening on `:8774`
before continuing.

- [ ] **Step 4: Generate the new key and log in**

```bash
export NEW_MASTER_KEY="$(openssl rand -base64 32)"
./rocketvault users login --username admin --password '<real admin password>' --totp-code <real code>
```

(Do not name the exported variable `MASTER_KEY` — Viper gives environment
variables precedence over the config file, which would make the rotation
tool's "old key from config" default resolve to the new key and abort with
"the new master key is identical to the old one." `NEW_MASTER_KEY` avoids the
collision, matching H3's own runbook.)

- [ ] **Step 5: Dry run**

```bash
./rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
```

Expected: a per-table report (`secrets`, `secret_versions`, `keys`,
`key_versions`, `certificates`) with `ALREADY NEW KEY` at `0` and no errors.
Read the report before continuing — do not proceed on any unexpected row count
or error.

- [ ] **Step 6: Real run**

```bash
./rocketvault master-key rotate --new-key-env NEW_MASTER_KEY
```

Confirm at the interactive prompt. Wait for "Rotation complete."

- [ ] **Step 7: Update `.rocketvault.yaml` and restart**

```bash
sed -i "s#^master_key: .*#master_key: \"${NEW_MASTER_KEY}\"#" .rocketvault.yaml
unset NEW_MASTER_KEY
./rocketvault serve
```

Expected: the server boots (H3's startup guard now passes — the key is no
longer the compromised default) and existing secret/key/certificate reads
succeed against the rotated data.

- [ ] **Step 8: Document the old value as compromised**

The old `master_key` (`***SECRET-REMOVED-2026-08-17***`) is already
documented as compromised in Task 9's known-bugs entry regardless of whether
this task has run — no further action needed here beyond confirming that entry
exists.

- [ ] **Step 9: No commit — this file is untracked, and the database is data, not code**

Same as Task 4: nothing here is staged to git. This step exists only to make
the absence of a commit explicit.

---

## Task 8: `hsm.pin` — manual runbook (no automated rotation)

**Files:**
- Create: `docs/runbooks/hsm-pin-rotation.md`
- Modify: `scripts/docsgen/docs.go` (`docsList`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `docs/runbooks/hsm-pin-rotation.md`, rendered to
  `docs/runbooks/hsm-pin-rotation.html` by `./scripts/docs.sh build`. This
  task's entire deliverable is documentation — it makes no config or database
  change itself.

- [ ] **Step 1: Write the runbook**

Create `docs/runbooks/hsm-pin-rotation.md`:

````markdown
# Runbook: Rotating the SoftHSM2 Token PIN

`.rocketvault.yaml`'s `hsm.pin` authenticates to the real SoftHSM2 (or other
PKCS#11) token named by `hsm.token_label`. **Editing the config value alone
does nothing** — PIN state lives in the token itself, not in RocketVault. If
you change `hsm.pin` in config without also changing the token's real PIN,
every HSM-routed key operation starts failing to authenticate.

This is why rotation is a manual, human-run procedure and not a CLI command:
the token may be shared with other software or other RocketVault instances,
and re-initializing it destroys every key it holds unless you use the
PIN-change form specifically (not `--init-token`, which wipes the token).

## 1. Confirm what uses this token

```bash
grep -A5 '^hsm:' .rocketvault.yaml
```

Note `token_label` and `slot_id`. If anything other than this RocketVault
instance uses the same token (shared SoftHSM2 install, another service), you
must coordinate with it before changing the PIN — its config needs the new PIN
too, at the same time, or it starts failing.

## 2. Stop RocketVault

Concurrent HSM operations during a PIN change can fail loudly (safe) but there
is no reason to risk it — stop the server first.

## 3. Change the token's PIN (not re-init)

```bash
softhsm2-util --pin '<current PIN>' --new-pin '<new PIN>' --token-label rocketvault
```

Use a freshly generated PIN, not something typed by hand:

```bash
openssl rand -base64 18 | tr -d '=+/' | head -c 24
```

**Do not use `softhsm2-util --init-token`** for this — that wipes every key
the token holds. `--pin ... --new-pin ...` changes the PIN of the existing
token in place, keeping its keys.

## 4. Update `.rocketvault.yaml`

```bash
sed -i "s#^  pin: .*#  pin: \"<new PIN>\"#" .rocketvault.yaml
```

(Indentation must match the existing `hsm:` block — it is a nested key, not
top-level.)

## 5. Restart and verify

```bash
./rocketvault serve
./rocketvault keys list --vault default
```

A successful list proves the new PIN authenticates. If it fails with a PKCS#11
authentication error, the token still has the old PIN, or step 3 targeted the
wrong `--token-label` — check `softhsm2-util --show-slots` to confirm the
token label and slot actually changed.

## 6. If something goes wrong

| Symptom | Cause | Action |
|---|---|---|
| `CKR_PIN_INCORRECT` after restart | Config and token PIN disagree | Re-run step 3 with the PIN you actually set, or step 4 with the PIN you actually changed to — whichever was mistyped. |
| `softhsm2-util --pin` itself fails | Wrong current PIN, or wrong `--token-label` | `softhsm2-util --show-slots` to find the real label; retry with the correct current PIN. |
| Other software using the same token now fails | This token is shared and its config wasn't updated | Update that software's PIN config too — this is why step 1's coordination check matters. |

## Never do this

- Never commit a PIN — real or placeholder — into any tracked file. The
  previous PIN (`1234`) was committed in `.rocketvault.yaml` for 5+ months
  (`.claude/known-bugs.md` § B10) and must be treated as permanently
  compromised even after this rotation.
- Never reuse an old, possibly-compromised PIN as the "new" PIN.
````

- [ ] **Step 2: Register the runbook with the docs generator**

In `scripts/docsgen/docs.go`, add this entry to `docsList`, keeping the list's
alphabetical-by-path ordering (immediately before the
`docs/runbooks/master-key-rotation.md` entry that H3's plan adds, if that has
landed — otherwise, before `docs/usage-guide.md`):

```go
	{"docs/runbooks/hsm-pin-rotation.md", "docs/runbooks/hsm-pin-rotation.html"},
```

- [ ] **Step 3: Verify the docs site builds**

Run: `./scripts/docs.sh build`
Expected: completes without error and creates `docs/runbooks/hsm-pin-rotation.html`.

- [ ] **Step 4: Commit**

```bash
git add docs/runbooks/hsm-pin-rotation.md scripts/docsgen/docs.go
git commit -m "docs: add SoftHSM2 PIN rotation runbook

hsm.pin authenticates to real, possibly-shared PKCS#11 token state --
changing config alone breaks HSM auth without rotating anything. This
is a documented manual procedure (softhsm2-util --pin ... --new-pin
..., never --init-token), not a CLI command; no code change in this
commit."
```

---

## Task 9: `.claude/known-bugs.md` entry + incident-doc addendum

**Files:**
- Modify: `.claude/known-bugs.md` (insert after the B8 entry, before `##
  Deferred Refactors` — or after whichever of B9's four competing claimants
  landed first; see note below)
- Modify: `.claude/security-incident-2026-03-07.md` (append addendum)

**Interfaces:**
- Consumes: everything from Tasks 1-8 — the entry documents the shipped fix.
- Produces: entry id **B10**, referenced by every doc/CI-comment in this plan
  that says "§ B10".

- [ ] **Step 1: Verify the B-number assignment is still current**

`.claude/known-bugs.md`'s current highest entry, as of this plan's writing, is
`B8`. Five 2026-08-16 pentest-finding plans were coordinated to use
sequential numbers to avoid a collision: H1 = B9
(`docs/superpowers/plans/2026-08-16-remove-hs256-jwt-fallback.md`), H2 = B11
(`docs/superpowers/plans/2026-08-16-flat-route-vault-scope-fix.md`), H3 = B12
(`docs/superpowers/plans/2026-08-16-master-key-rotation.md`), H4 (this plan) =
**B10**, and H5 = B13
(`docs/superpowers/plans/2026-08-16-cli-audit-authz-fix.md`). Run this check
before inserting, in case implementation order or a later edit changed that:

```bash
grep -n "^### B9\b\|^### B10\b\|^### B11\b\|^### B12\b\|^### B13\b" .claude/known-bugs.md
```

If `B10` already exists, something renumbered after this plan was written —
stop and reconcile with the other four plans rather than guessing a new
number.

- [ ] **Step 2: Insert the entry**

In `.claude/known-bugs.md`, immediately after the B8 entry's closing `---` and
before the `## Deferred Refactors` header, insert:

```markdown
### B10 — Live secrets committed to git, recurrence of a fixed incident

**Status**: Fixed 2026-08-16 (structural fix + rotation) — see
`docs/superpowers/plans/2026-08-16-secrets-in-git-remediation.md`. Git history
still contains every value listed below; purging it is a separate, deferred
task — `docs/superpowers/plans/2026-08-16-git-history-secret-purge-followup.md`.
**Severity**: Resolved — was High (full offline decryption of every stored
secret, admin-token forgery via the paired H1 finding, and first-admin-bootstrap
takeover, confirmed by live git-history inspection in
`.claude/pentest-report-2026-08-16.md` § H4)
**File**: `.gitignore`, `.rocketvault.yaml`, `.rocketvault.yaml.example`,
`.github/workflows/go.yml`, plus 9 tracked docs/scripts/tests that duplicated
the same values

**Root cause**: `.claude/security-incident-2026-03-07.md` (2026-03-07) already
fixed this exact class of leak once — `git rm --cached` on the then-named
`.password-manager*.yaml` files, plus a `.gitignore` entry for that name
pattern. The very next commit touching this area, one day later, renamed the
project to RocketVault and introduced a brand-new `.rocketvault.yaml` — under a
name the old `.gitignore` pattern didn't cover. It has been tracked and
unrotated ever since. A second, unrelated `.gitignore` line
(`rocketvault-*`, under "Application binaries") looks like it might have been
meant to catch this too; it never could, because it requires no leading dot and
a trailing dash, and `.rocketvault.yaml` has neither. Nothing ever tested that
either pattern actually matched the file it needed to match — that is the
literal, specific root cause, verified with `git check-ignore -v
.rocketvault.yaml` (no output, exit 1, before this fix).

The same four secret values (`master_key`, `jwt_secret`, `bootstrap_token`,
`hsm.pin`) were also duplicated, in whole or in part, across 9 other tracked
files (docs, a test fixture, a capture script) — including one,
`scripts/README.md`, still quoting an even older, already-`git rm`'d secret
generation from `.password-manager-test.yaml` (removed from the working tree in
commit `cb93bc9`, but never purged from history, and apparently copy-pasted
into a doc before that removal).

**What was fixed**:
1. `.gitignore` — new block matching `.rocketvault.yaml`, `.rocketvault-*.yaml`,
   and `.rocketvault.yaml.local`, with a negation for the new
   `.rocketvault.yaml.example` template. Verified with `git check-ignore -v`
   against all four names.
2. `.rocketvault.yaml.example` — committed template with instructional
   placeholders, mirroring the existing `.env`/`.env.example` pattern. The real
   `.rocketvault.yaml` is `git rm --cached`'d (working tree untouched).
3. Two new CI steps in `.github/workflows/go.yml`'s `security` job: a
   structural check that no `.rocketvault*.yaml` variant is ever tracked again,
   and a denylist check for the exact secret bytes already known to be
   compromised. A gitleaks-based alternative was evaluated and rejected after
   producing 50 findings locally, nearly all false positives on test fixtures —
   see the design doc.
4. `bootstrap_token` rotated to a freshly generated value; the old one
   (`***SECRET-REMOVED-2026-08-17***`) is permanently compromised,
   never to be reused.
5. `jwt_secret`/`jwt.migration_window` deleted from `.rocketvault.yaml` outright
   rather than rotated — H1 (`docs/superpowers/plans/2026-08-16-remove-hs256-jwt-fallback.md`)
   made both keys fully unread by any Go code, so rotating a value nothing
   reads would be motion without effect.
6. `master_key` rotated for real via H3's `rocketvault master-key rotate` tool
   (`docs/superpowers/plans/2026-08-16-master-key-rotation.md`), run manually
   with explicit human confirmation — not autonomous, since it rewrites every
   master-key-sealed row in the live database.
7. `hsm.pin` — documented as a manual `softhsm2-util --pin ... --new-pin ...`
   runbook (`docs/runbooks/hsm-pin-rotation.md`), not automated: it is real,
   shared PKCS#11 token state, not a config value.
8. Nine other tracked files with duplicated literal values fixed to placeholders
   or config-driven reads.

**Regression tests**: none in the traditional sense (no Go logic changed beyond
one test-fixture swap) — the "tests" for this fix are the CI gate itself
(Task 6) and the verification gate in the design doc, both grep-based against
the real repository content, run and confirmed clean before this entry was
written.

**Remaining, tracked separately**: the git history itself still contains every
value listed above, recoverable by anyone who has ever cloned this repository —
`docs/superpowers/plans/2026-08-16-git-history-secret-purge-followup.md` is the
deferred `git filter-repo` + coordinated force-push procedure to actually purge
it. Until that runs, treat every value named in this entry as permanently
public, rotation notwithstanding.

---
```

- [ ] **Step 3: Verify the entry renders and reads correctly**

Run: `grep -n "^### B\|^## " .claude/known-bugs.md`
Expected: `B10` (or whatever number Step 1 settled on) appears after the
highest existing entry and before `## Deferred Refactors`.

- [ ] **Step 4: Append the incident-doc addendum**

In `.claude/security-incident-2026-03-07.md`, append at the end of the file:

```markdown

---

## Addendum (2026-08-16): this fix regressed one day later

The `.gitignore` entry added by this incident's fix
(`.password-manager*.yaml`) never covered the project's next name — commit
`5dd5490`, the very next day, renamed the project to RocketVault and
introduced a new `.rocketvault.yaml` that this pattern didn't match. It stayed
tracked and unrotated for over five months until a 2026-08-16 penetration test
found it again. Full root-cause and fix:
`.claude/known-bugs.md` § B10,
`docs/superpowers/specs/2026-08-16-secrets-in-git-remediation-design.md`.

The lesson that fix draws from this one: a `.gitignore` pattern change with no
test proving it matches, and no CI backstop catching a future miss, is not a
durable fix. Both gaps are closed this time — see the CI guard described in
the documents above.
```

- [ ] **Step 5: Commit**

```bash
git add .claude/known-bugs.md .claude/security-incident-2026-03-07.md
git commit -m "docs(known-bugs): add B10 — live secrets in git, recurrence fixed

Root cause (the gitignore pattern that never matched), the fix across
gitignore/template/CI/rotation/runbooks, and what's still deferred
(the git-history purge). Also appends a short addendum to the original
2026-03-07 incident doc closing the loop on why its fix regressed."
```

---

## Task 10: Final verification pass

**Files:**
- No changes expected.

**Interfaces:**
- Consumes: everything from Tasks 1-6, 8-9 (Task 7 is optional/human-gated and
  not required for this gate to pass).

- [ ] **Step 1: Run the spec's verification gate**

```bash
git check-ignore -v .rocketvault.yaml
git check-ignore -v .rocketvault-production.yaml
git check-ignore -v .rocketvault.yaml.local
git check-ignore -q .rocketvault.yaml.example && echo IGNORED || echo NOT_IGNORED

git ls-files | grep -E '^\.rocketvault(-.*)?\.yaml$|^\.rocketvault\.yaml\.local$'

git grep -lF \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -e '***SECRET-REMOVED-2026-08-17***' \
  -- . ':(exclude)docs/superpowers/' ':(exclude)docs/plans/' ':(exclude).claude/'

go build ./...
go test ./...
./scripts/docs.sh build
```

Expected:
- First three `check-ignore` calls: each prints a match, exit `0`.
- Fourth: prints `NOT_IGNORED`.
- `git ls-files | grep ...`: no output.
- `git grep -lF ...`: no output.
- `go build`, `go test ./...`: PASS.
- `./scripts/docs.sh build`: succeeds.

- [ ] **Step 2: Confirm the deferred items are genuinely deferred, not silently dropped**

```bash
test -f docs/superpowers/plans/2026-08-16-git-history-secret-purge-followup.md && echo "followup doc exists"
grep -c "REQUIRES EXPLICIT HUMAN CONFIRMATION" docs/superpowers/plans/2026-08-16-secrets-in-git-remediation.md
```
Expected: `followup doc exists`, and a count of at least `1`.

- [ ] **Step 3: Report status**

No commit for this task — it is a read-only gate. If every check above passes,
this plan's automated scope (Tasks 1-6, 8-9) is complete. Report to the human
whether Task 7 (master-key rotation) was run, and remind them the git-history
purge is still outstanding and requires its own scheduled window.
