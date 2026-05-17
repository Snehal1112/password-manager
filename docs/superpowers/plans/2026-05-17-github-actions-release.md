# GitHub Actions Release Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a GitHub Actions release workflow that, on every semver tag push, builds native binaries for Linux (amd64), macOS (arm64), and Windows (amd64), packages them as tarballs/zips with SHA256 checksums, and publishes a GitHub Release with all artifacts attached.

**Architecture:** A new workflow file `.github/workflows/release.yml` is triggered by `push: tags: ['v*.*.*']`. It uses a matrix of three native runners (ubuntu-latest, macos-latest, windows-latest) so CGO (required for SQLite3) works without cross-compilers. Each runner builds its artifact, uploads it, and a final `release` job downloads everything and publishes the GitHub Release using `gh`. The existing `go.yml` CI workflow is unchanged.

**Tech Stack:** GitHub Actions, Go 1.24.2, CGO/SQLite3, `actions/checkout@v4`, `actions/setup-go@v5`, `actions/upload-artifact@v4`, `actions/download-artifact@v4`, `gh` CLI (pre-installed on GitHub runners)

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `.github/workflows/release.yml` | Create | Release workflow — matrix build + GitHub Release publish |
| `.github/workflows/go.yml` | No change | Existing CI — already covers lint/test/security |

---

### Task 1: Create the release workflow

**Files:**

- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create the workflow file**

Create `/home/numericlabs/data/rocket/rocketvault/.github/workflows/release.yml` with the following content:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*.*.*'

permissions:
  contents: write

jobs:
  build:
    name: Build (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            goos: linux
            goarch: amd64
            ext: ""
            archive: tar.gz
          - os: macos-latest
            goos: darwin
            goarch: arm64
            ext: ""
            archive: tar.gz
          - os: windows-latest
            goos: windows
            goarch: amd64
            ext: ".exe"
            archive: zip

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # needed so git describe works for VERSION

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Install Linux build deps
        if: matrix.os == 'ubuntu-latest'
        run: sudo apt-get update && sudo apt-get install -y gcc

      - name: Set version
        id: version
        shell: bash
        run: echo "VERSION=${GITHUB_REF_NAME}" >> "$GITHUB_OUTPUT"

      - name: Build binary
        shell: bash
        env:
          CGO_ENABLED: "1"
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
          VERSION: ${{ steps.version.outputs.VERSION }}
        run: |
          COMMIT_HASH=$(git rev-parse --short HEAD)
          BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
          GO_VERSION=$(go version | awk '{print $3}')
          BINARY_NAME="rocketvault-${VERSION}-${{ matrix.goos }}-${{ matrix.goarch }}${{ matrix.ext }}"
          mkdir -p dist
          go build \
            -trimpath \
            -ldflags="-s -w \
              -X 'main.Version=${VERSION}' \
              -X 'main.CommitHash=${COMMIT_HASH}' \
              -X 'main.BuildTime=${BUILD_TIME}' \
              -X 'main.GoVersion=${GO_VERSION}'" \
            -o "dist/${BINARY_NAME}" \
            .

      - name: Package (tar.gz)
        if: matrix.archive == 'tar.gz'
        shell: bash
        env:
          VERSION: ${{ steps.version.outputs.VERSION }}
        run: |
          BINARY="rocketvault-${VERSION}-${{ matrix.goos }}-${{ matrix.goarch }}"
          ARCHIVE="dist/${BINARY}.tar.gz"
          tar -czf "${ARCHIVE}" -C dist "${BINARY}"
          sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256"

      - name: Package (zip)
        if: matrix.archive == 'zip'
        shell: bash
        env:
          VERSION: ${{ steps.version.outputs.VERSION }}
        run: |
          BINARY="rocketvault-${VERSION}-${{ matrix.goos }}-${{ matrix.goarch }}${{ matrix.ext }}"
          ARCHIVE="rocketvault-${VERSION}-${{ matrix.goos }}-${{ matrix.goarch }}.zip"
          7z a "dist/${ARCHIVE}" "dist/${BINARY}"
          sha256sum "dist/${ARCHIVE}" > "dist/${ARCHIVE}.sha256"

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: rocketvault-${{ matrix.goos }}-${{ matrix.goarch }}
          path: |
            dist/*.tar.gz
            dist/*.tar.gz.sha256
            dist/*.zip
            dist/*.zip.sha256
          if-no-files-found: error

  release:
    name: Publish GitHub Release
    needs: build
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true

      - name: Create GitHub Release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ github.ref_name }}
        run: |
          gh release create "${VERSION}" \
            --title "RocketVault ${VERSION}" \
            --generate-notes \
            dist/*.tar.gz dist/*.tar.gz.sha256 \
            dist/*.zip dist/*.zip.sha256
```

- [ ] **Step 2: Verify YAML syntax**

Run:

```bash
python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/release.yml'))" && echo "YAML valid"
```

Expected: `YAML valid`

If python3 is unavailable, use:

```bash
cat .github/workflows/release.yml | head -5  # Confirm file exists and is readable
```

- [ ] **Step 3: Verify the existing go.yml is unchanged**

Run:

```bash
git diff .github/workflows/go.yml
```

Expected: no output (no changes).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat(ci): add GitHub Actions release workflow for v*.*.* tags"
```

---

### Task 2: Validate the workflow triggers and matrix

**Files:**

- Read: `.github/workflows/release.yml` (no edits — validation only)

This task has no code changes. It is a manual checklist to run before pushing a real tag.

- [ ] **Step 1: Confirm workflow trigger**

Run:

```bash
grep -A3 "^on:" .github/workflows/release.yml
```

Expected output:

```
on:
  push:
    tags:
      - 'v*.*.*'
```

- [ ] **Step 2: Confirm matrix platforms**

Run:

```bash
grep -E "os:|goos:|goarch:" .github/workflows/release.yml
```

Expected to see three entries: `ubuntu-latest / linux / amd64`, `macos-latest / darwin / arm64`, `windows-latest / windows / amd64`.

- [ ] **Step 3: Confirm `permissions: contents: write` is present**

Run:

```bash
grep -A2 "^permissions:" .github/workflows/release.yml
```

Expected:

```
permissions:
  contents: write
```

This permission is required for `gh release create` to write to the repository's releases. Without it the job will fail with a 403.

- [ ] **Step 4: Dry-run a tag locally (optional smoke test)**

To verify the ldflags version injection works before pushing a real tag:

```bash
VERSION=v4.0.0-test
COMMIT_HASH=$(git rev-parse --short HEAD)
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
GO_VERSION=$(go version | awk '{print $3}')
go build \
  -trimpath \
  -ldflags="-s -w \
    -X 'main.Version=${VERSION}' \
    -X 'main.CommitHash=${COMMIT_HASH}' \
    -X 'main.BuildTime=${BUILD_TIME}' \
    -X 'main.GoVersion=${GO_VERSION}'" \
  -o /tmp/rocketvault-smoke \
  .
/tmp/rocketvault-smoke --version 2>/dev/null || /tmp/rocketvault-smoke version 2>/dev/null || echo "binary built, check version flag manually"
```

Expected: binary builds without error. Version string should contain `v4.0.0-test`.

- [ ] **Step 5: Commit task-2 validation notes**

No files changed in this task. Nothing to commit.

---

### Task 3: Update README Roadmap to mark CI/CD integration as shipped

**Files:**

- Modify: `README.md` (~line 760 — the `### Planned` section)

- [ ] **Step 1: Move the CI/CD item from Planned to Shipped**

In `README.md`, find:

```markdown
*(Feb–May 2026)*

- [x] Secret `content_type` field — domain, schema, repository, service validation, API and CLI
- [x] Key wrap/unwrap operations — CryptoService, HTTP endpoints, CLI subcommands
- [x] Certificate auto-renewal — ExpiresAt field, RenewalScheduler, HTTP API, CLI flags
- [x] Security hardening: crypto/rand enforcement, role self-promotion blocking, ownership enforcement on rotation
```

Replace with:

```markdown
*(Feb–May 2026)*

- [x] Secret `content_type` field — domain, schema, repository, service validation, API and CLI
- [x] Key wrap/unwrap operations — CryptoService, HTTP endpoints, CLI subcommands
- [x] Certificate auto-renewal — ExpiresAt field, RenewalScheduler, HTTP API, CLI flags
- [x] Security hardening: crypto/rand enforcement, role self-promotion blocking, ownership enforcement on rotation
- [x] GitHub Actions release workflow — matrix build for Linux/macOS/Windows, GitHub Release publish
```

Then find in the `### Planned` section:

```markdown
- [ ] Integration with popular CI/CD pipelines (GitHub Actions, GitLab CI)
```

Remove that line entirely (the GitHub Actions part is now done; GitLab CI remains future work if needed, but YAGNI — remove the whole line).

- [ ] **Step 2: Verify**

Run:

```bash
grep -n "CI/CD\|GitHub Actions release\|Integration with popular" README.md
```

Expected: one line showing the new `[x]` shipped entry; no `[ ] Integration with popular` line.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: mark GitHub Actions release workflow as shipped in README"
```

---

## How to trigger a real release

After all tasks are committed and pushed to `v-4.0.0`:

```bash
git tag v4.0.1
git push origin v4.0.1
```

This triggers the release workflow. Monitor at:
`https://github.com/Snehal1112/rocketvault/actions`

The resulting GitHub Release will appear at:
`https://github.com/Snehal1112/rocketvault/releases`
