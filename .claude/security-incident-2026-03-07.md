# Security Incident: Config Files with Secrets in Git History

**Date:** 2026-03-07
**Branch:** fix/architecture-review-2026-03-07

## What happened

Four config files containing `master_key`, `jwt_secret`, and `bootstrap_token`
in plaintext were tracked in git history:

- `.rocketvault.yaml`
- `.rocketvault-production.yaml`
- `.rocketvault-staging.yaml`
- `.rocketvault-test.yaml`

## Immediate actions taken

- All four files removed from git tracking (`git rm --cached`)
- `.rocketvault*.yaml` added to `.gitignore`

## OPERATOR ACTION REQUIRED

### 1. Rotate all secrets immediately

Generate new values and update your local config files:

```bash
# New master_key (32 bytes, base64)
openssl rand -base64 32

# New jwt_secret (32 bytes, base64)
openssl rand -base64 32

# New bootstrap_token (32 bytes, base64)
openssl rand -base64 32
```

### 2. Purge secrets from git history

Install git-filter-repo if needed: `pip install git-filter-repo`

```bash
git filter-repo \
  --path .rocketvault.yaml \
  --path .rocketvault-production.yaml \
  --path .rocketvault-staging.yaml \
  --path .rocketvault-test.yaml \
  --invert-paths
```

### 3. Force-push and coordinate with collaborators

All collaborators must re-clone or reset their local repos after the
force-push, as their local history will diverge.
