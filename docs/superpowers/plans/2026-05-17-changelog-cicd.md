# Changelog CI/CD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add git-cliff changelog generation to the rocketvault GitHub Actions release workflow so every GitHub Release includes a grouped changelog body, and releases are created as drafts.

**Architecture:** A new `cliff.toml` at the repo root defines commit grouping rules. A new `changelog` job in `release.yml` runs `orhun/git-cliff-action@v4` before the build matrix, outputs the changelog as a job output, and the existing `release` job consumes it via `needs.changelog.outputs.body`. The `--generate-notes` flag is replaced by `--notes` + `--draft`.

**Tech Stack:** git-cliff (`orhun/git-cliff-action@v4`), GitHub Actions, TOML, YAML

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `cliff.toml` | Create | Defines changelog groups, commit parsers, and body template |
| `.github/workflows/release.yml` | Modify | Add `changelog` job, update `release` job dependencies and `gh release create` flags |

---

### Task 1: Add cliff.toml

**Files:**

- Create: `cliff.toml`

- [ ] **Step 1: Create cliff.toml**

Create `/home/numericlabs/data/rocket/rocketvault/cliff.toml` with exactly this content:

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

- [ ] **Step 2: Verify the file exists and is valid TOML**

Run:

```bash
python3 -c "
import tomllib, sys
with open('/home/numericlabs/data/rocket/rocketvault/cliff.toml', 'rb') as f:
    data = tomllib.load(f)
print('TOML valid')
print('Groups:', [p.get('group') for p in data['git']['commit_parsers'] if 'group' in p])
"
```

Expected output:

```
TOML valid
Groups: ['Features', 'Bug Fixes', 'Performance', 'Refactoring', 'Documentation']
```

- [ ] **Step 3: Commit**

```bash
git -C /home/numericlabs/data/rocket/rocketvault add cliff.toml
git -C /home/numericlabs/data/rocket/rocketvault commit -m "feat(release): add cliff.toml for git-cliff changelog generation"
```

---

### Task 2: Update release.yml with changelog job

**Files:**

- Modify: `.github/workflows/release.yml`

The current `release.yml` has two jobs: `build` (matrix) and `release` (`needs: build`). This task adds a `changelog` job and wires it into `release`.

- [ ] **Step 1: Replace the full content of release.yml**

Write `/home/numericlabs/data/rocket/rocketvault/.github/workflows/release.yml` with:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*.*.*'

permissions:
  contents: write

jobs:
  changelog:
    name: Generate Changelog
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

  build:
    name: Build (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          # Each runner must match its own GOOS/GOARCH — CGO cannot cross-compile.
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
          fetch-depth: 0

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Build binary
        shell: bash
        env:
          CGO_ENABLED: "1"
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
        run: |
          VERSION="${{ github.ref_name }}"
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
        run: |
          VERSION="${{ github.ref_name }}"
          BINARY="rocketvault-${VERSION}-${{ matrix.goos }}-${{ matrix.goarch }}"
          ARCHIVE="dist/${BINARY}.tar.gz"
          tar -czf "${ARCHIVE}" -C dist "${BINARY}"
          # sha256sum on Linux, shasum on macOS
          command -v sha256sum >/dev/null 2>&1 && sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256" || shasum -a 256 "${ARCHIVE}" > "${ARCHIVE}.sha256"

      - name: Package (zip)
        if: matrix.archive == 'zip'
        shell: bash
        run: |
          VERSION="${{ github.ref_name }}"
          BINARY="rocketvault-${VERSION}-${{ matrix.goos }}-${{ matrix.goarch }}${{ matrix.ext }}"
          ARCHIVE="rocketvault-${VERSION}-${{ matrix.goos }}-${{ matrix.goarch }}.zip"
          7z a "dist/${ARCHIVE}" "dist/${BINARY}"
          command -v sha256sum >/dev/null 2>&1 && sha256sum "dist/${ARCHIVE}" > "dist/${ARCHIVE}.sha256" || shasum -a 256 "dist/${ARCHIVE}" > "dist/${ARCHIVE}.sha256"

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
    needs: [build, changelog]
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true

      - name: Create GitHub Release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          VERSION="${{ github.ref_name }}"
          gh release create "${VERSION}" \
            --draft \
            --title "RocketVault ${VERSION}" \
            --notes "${{ needs.changelog.outputs.body }}" \
            dist/*.tar.gz dist/*.tar.gz.sha256 \
            dist/*.zip dist/*.zip.sha256
```

- [ ] **Step 2: Verify YAML syntax**

Run:

```bash
python3 -c "import yaml; yaml.safe_load(open('/home/numericlabs/data/rocket/rocketvault/.github/workflows/release.yml'))" && echo "YAML valid"
```

Expected: `YAML valid`

- [ ] **Step 3: Verify key changes are present**

Run:

```bash
grep -n "changelog\|--draft\|--notes\|--generate-notes\|needs:" /home/numericlabs/data/rocket/rocketvault/.github/workflows/release.yml
```

Expected output must show:

- `changelog:` job defined
- `needs: [build, changelog]` on the release job
- `--draft` present
- `--notes` present
- `--generate-notes` NOT present

- [ ] **Step 4: Commit**

```bash
git -C /home/numericlabs/data/rocket/rocketvault add .github/workflows/release.yml
git -C /home/numericlabs/data/rocket/rocketvault commit -m "feat(release): add git-cliff changelog job and draft release to release workflow"
```
