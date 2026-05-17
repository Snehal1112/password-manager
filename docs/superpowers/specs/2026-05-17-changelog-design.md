---
name: changelog-ci-cd
description: Add git-cliff changelog generation to rocketvault GitHub Actions release workflow, mirroring the rocket project pattern
metadata:
  type: project
---

# Changelog CI/CD — Design Spec

**Date**: 2026-05-17
**Scope**: `cliff.toml` (new), `.github/workflows/release.yml` (modified)

## Goal

GitHub Releases for rocketvault currently have no changelog body. Add auto-generated changelogs using git-cliff, grouped by conventional commit type, matching the style of the rocket project's releases (e.g. https://github.com/Snehal1112/rocket/releases/tag/v0.6.10). Releases are created as drafts so the changelog can be reviewed before publishing.

## Reference

The rocket project (`../rocket`) uses:
- `orhun/git-cliff-action@v4` in a dedicated `changelog` job
- `cliff.toml` at the repo root for grouping and formatting rules
- `releaseBody: ${{ needs.changelog.outputs.body }}` passed to the release step
- `releaseDraft: true` so releases require manual publish

## Changes

### 1. Add `cliff.toml`

New file at repo root. Mirrors the rocket config with one addition: `docs` commits are shown under a "Documentation" group.

```toml
[changelog]
header = ""
body = """
{% for group, commits in commits | group_by(attribute="group") %}
### {{ group }}
{% for commit in commits %}
- {% if commit.scope %}**{{ commit.scope }}:** {% endif %}{{ commit.message }}\
{% endfor %}
{% endfor %}
"""
trim = true

[git]
conventional_commits = true
filter_unconventional = true
split_commits = false

commit_parsers = [
  { message = "^feat", group = "Features" },
  { message = "^fix", group = "Bug Fixes" },
  { message = "^perf", group = "Performance" },
  { message = "^refactor", group = "Refactoring" },
  { message = "^doc", group = "Documentation" },
  { message = "^test", skip = true },
  { message = "^chore", skip = true },
  { message = "^revert", skip = true },
  { message = "^ci", skip = true },
  { message = "^style", skip = true },
]

filter_commits = true
tag_pattern = "v[0-9].*"
skip_tags = ""
ignore_tags = ""
topo_order = false
sort_commits = "oldest"
```

### 2. Update `.github/workflows/release.yml`

Add a `changelog` job that runs before the build matrix:

```yaml
jobs:
  changelog:
    runs-on: ubuntu-latest
    outputs:
      body: ${{ steps.cliff.outputs.content }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Generate changelog
        uses: orhun/git-cliff-action@v4
        id: cliff
        with:
          config: cliff.toml
          args: --latest --strip header
```

Update the existing `release` job:
- Add `needs: [build, changelog]` (currently `needs: build`)
- Change `gh release create` to add `--draft` flag and pass the changelog body:

```bash
gh release create "${VERSION}" \
  --draft \
  --title "RocketVault ${VERSION}" \
  --notes "${{ needs.changelog.outputs.body }}" \
  dist/*.tar.gz dist/*.tar.gz.sha256 \
  dist/*.zip dist/*.zip.sha256
```

Note: `--generate-notes` is replaced by `--notes` with the git-cliff output. `--generate-notes` would override the changelog body.

### 3. No changes to `release.sh`

The script pushes a signed tag — the workflow handles everything else.

## Changelog format (example output for v4.0.2)

```
### Features
- **cert-renewal:** implement CertificateRenewalScheduler
- **cert-renewal:** add certificates HTTP API and CLI flags
- **key-wrap:** add WrapKey and UnwrapKey to CryptoService
- **content-type:** add ContentType field to Secret domain and schema

### Bug Fixes
- **security:** replace math/rand with crypto/rand in password generator
- **security:** block role self-promotion and fix substring role validation

### Documentation
- update cli-guide with content types, key wrap/unwrap, and cert auto-renewal
```

## Out of Scope

- No `CHANGELOG.md` file — changelog lives only in GitHub Releases.
- No changes to `release.sh`.
- No changes to any other workflow file.

## Success Criteria

- `cliff.toml` exists at repo root with correct groups.
- Release workflow has a `changelog` job that outputs `content`.
- `release` job depends on both `build` and `changelog`.
- GitHub Release is created as a draft.
- Release body contains grouped conventional commit entries for commits since the previous tag.
- `feat`, `fix`, `perf`, `refactor`, `doc` commits appear; `test`, `chore`, `ci`, `style`, `revert` are excluded.
