#!/usr/bin/env bash

# RocketVault Build Script
#
# Usage:
#   ./build.sh              # Build for current platform
#   ./build.sh --all        # Cross-compile for all platforms
#   ./build.sh --release    # Run tests + cross-compile + release notes
#   ./build.sh --test       # Run tests only
#   ./build.sh --coverage   # Run tests with coverage report
#   ./build.sh --lint       # Run go vet + staticcheck
#   ./build.sh --clean      # Remove build artifacts
#   ./build.sh --verify-only  # Verify environment and dependencies only

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
COMMIT_HASH="${COMMIT_HASH:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GO_VERSION="$(go version | awk '{print $3}')"

MODULE_NAME="rocketvault"
BINARY_NAME="rocketvault"
MAIN_PACKAGE="."

BUILD_DIR="./build"
DIST_DIR="./dist"
COVERAGE_DIR="./coverage"

# Minimum Go version required.
REQUIRED_GO_MAJOR=1
REQUIRED_GO_MINOR=25

# Platform targets for cross-compilation.
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

# ld flags injected at build time.
LDFLAGS=(
    "-s"
    "-w"
    "-X 'main.Version=${VERSION}'"
    "-X 'main.CommitHash=${COMMIT_HASH}'"
    "-X 'main.BuildTime=${BUILD_TIME}'"
    "-X 'main.GoVersion=${GO_VERSION}'"
)

# ============================================================================
# Color output
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ============================================================================
# Build functions
# ============================================================================

verify_environment() {
    log_info "Verifying build environment..."

    if ! command -v go &>/dev/null; then
        log_error "Go is not installed or not in PATH."
        exit 1
    fi

    # Parse major.minor from "go1.25.0" — strip leading "go", split on dots.
    local current_major current_minor ver_string
    ver_string=$(go version | awk '{print $3}' | sed 's/^go//')
    current_major=$(echo "${ver_string}" | cut -d. -f1)
    current_minor=$(echo "${ver_string}" | cut -d. -f2)

    log_info "Go version: ${GO_VERSION}"

    if (( current_major < REQUIRED_GO_MAJOR )) || \
       (( current_major == REQUIRED_GO_MAJOR && current_minor < REQUIRED_GO_MINOR )); then
        log_error "Go ${REQUIRED_GO_MAJOR}.${REQUIRED_GO_MINOR}+ required (found ${GO_VERSION})."
        exit 1
    fi

    if [[ ! -f "go.mod" ]]; then
        log_error "go.mod not found. Run 'go mod init' first."
        exit 1
    fi

    log_success "Environment verification complete."
}

verify_dependencies() {
    log_info "Verifying dependencies..."

    go mod download

    if ! go mod verify; then
        log_error "Dependency verification failed."
        exit 1
    fi

    log_success "Dependencies verified."
}

run_vet() {
    log_info "Running go vet..."
    if ! go vet ./...; then
        log_error "go vet reported issues."
        exit 1
    fi
    log_success "go vet passed."
}

run_lint() {
    run_vet

    if command -v staticcheck &>/dev/null; then
        log_info "Running staticcheck..."
        if ! staticcheck ./...; then
            log_error "staticcheck reported issues."
            exit 1
        fi
        log_success "staticcheck passed."
    else
        log_warn "staticcheck not found — skipping (install: go install honnef.co/go/tools/cmd/staticcheck@latest)."
    fi
}

run_tests() {
    log_info "Running tests..."
    # -count=1 disables the test cache so every run re-executes all tests.
    if go test -race -count=1 -timeout 5m ./...; then
        log_success "All tests passed."
    else
        log_error "Tests failed."
        exit 1
    fi
}

run_coverage() {
    log_info "Running tests with coverage..."
    mkdir -p "${COVERAGE_DIR}"

    # -count=1 disables the test cache; -coverprofile implies coverage instrumentation.
    go test -race -count=1 -timeout 5m \
        -coverprofile="${COVERAGE_DIR}/coverage.out" \
        -covermode=atomic \
        ./...

    go tool cover -html="${COVERAGE_DIR}/coverage.out" \
        -o "${COVERAGE_DIR}/coverage.html"

    local total
    total=$(go tool cover -func="${COVERAGE_DIR}/coverage.out" | grep '^total' | awk '{print $3}')
    log_success "Total coverage: ${total}"
    log_info "HTML report: ${COVERAGE_DIR}/coverage.html"
}

build_current() {
    log_info "Building for current platform..."

    local output="${BUILD_DIR}/${BINARY_NAME}"
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        output="${output}.exe"
    fi

    mkdir -p "${BUILD_DIR}"

    # CGO_ENABLED=1 is required for go-sqlite3.
    CGO_ENABLED=1 go build \
        -trimpath \
        -ldflags="${LDFLAGS[*]}" \
        -o "${output}" \
        "${MAIN_PACKAGE}"

    log_success "Built: ${output}"

    command -v file &>/dev/null && file "${output}"
    log_info "Binary size: $(du -h "${output}" | cut -f1)"
}

build_all() {
    log_info "Building for all platforms..."
    mkdir -p "${DIST_DIR}"

    local failed=()

    for platform in "${PLATFORMS[@]}"; do
        local goos="${platform%/*}"
        local goarch="${platform#*/}"
        local base_name="${BINARY_NAME}-${VERSION}-${goos}-${goarch}"
        local output_name="${base_name}"
        [[ "${goos}" == "windows" ]] && output_name="${base_name}.exe"
        local output_path="${DIST_DIR}/${output_name}"

        log_info "Building ${goos}/${goarch}..."

        # Cross-compilation with CGO requires a matching C cross-compiler.
        # Skip silently if the toolchain is unavailable rather than failing the
        # entire build — native build is handled separately by build_current.
        if ! CGO_ENABLED=1 GOOS="${goos}" GOARCH="${goarch}" go build \
               -trimpath \
               -ldflags="${LDFLAGS[*]}" \
               -o "${output_path}" \
               "${MAIN_PACKAGE}" 2>/dev/null; then
            log_warn "Skipping ${goos}/${goarch} — CGO cross-compiler not available."
            failed+=("${goos}/${goarch}")
            continue
        fi

        _checksum "${output_path}"
        _archive "${goos}" "${goarch}" "${output_path}" "${base_name}"
    done

    if [[ ${#failed[@]} -gt 0 ]]; then
        log_warn "Skipped platforms (no cross-compiler): ${failed[*]}"
        log_warn "Install the appropriate gcc cross-compiler to enable those targets."
    fi

    log_success "Platform builds complete."
    ls -lh "${DIST_DIR}"
}

# Write a sha256 checksum file next to the given file.
_checksum() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "${file}" > "${file}.sha256"
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "${file}" > "${file}.sha256"
    fi
}

# Create a tar.gz (Unix) or zip (Windows) archive from a built binary.
_archive() {
    local goos="$1" goarch="$2" binary="$3" base_name="$4"

    if [[ "${goos}" != "windows" ]]; then
        local tarball="${DIST_DIR}/${base_name}.tar.gz"
        tar -czf "${tarball}" -C "${DIST_DIR}" "$(basename "${binary}")"
        _checksum "${tarball}"
        log_success "Created: ${tarball}"
    else
        local zipfile="${DIST_DIR}/${base_name}.zip"
        # Use an absolute path for the zip target to avoid path issues with cd.
        (cd "${DIST_DIR}" && zip -q "$(basename "${zipfile}")" "$(basename "${binary}")")
        _checksum "${zipfile}"
        log_success "Created: ${zipfile}"
    fi
}

build_release() {
    log_info "Building release binaries..."
    run_vet
    run_tests
    build_all
    _generate_release_notes
    log_success "Release build complete."
}

_generate_release_notes() {
    local notes_file="${DIST_DIR}/RELEASE_NOTES.md"
    log_info "Generating release notes..."

    cat > "${notes_file}" << EOF
# ${MODULE_NAME} ${VERSION}

**Build Date**: ${BUILD_TIME}
**Commit**: ${COMMIT_HASH}
**Go Version**: ${GO_VERSION}

## Build Artifacts

EOF

    shopt -s nullglob
    for file in "${DIST_DIR}"/*.tar.gz "${DIST_DIR}"/*.zip; do
        local checksum_file="${file}.sha256"
        if [[ -f "${checksum_file}" ]]; then
            local checksum
            checksum=$(cut -d' ' -f1 "${checksum_file}")
            echo "- \`$(basename "${file}")\` — SHA256: \`${checksum}\`" >> "${notes_file}"
        fi
    done
    shopt -u nullglob

    log_success "Release notes: ${notes_file}"
}

clean() {
    log_info "Cleaning build artifacts..."
    rm -rf "${BUILD_DIR}" "${DIST_DIR}" "${COVERAGE_DIR}"
    go clean -cache -testcache
    log_success "Clean complete."
}

show_info() {
    log_info "Build information:"
    echo "  Version:     ${VERSION}"
    echo "  Commit:      ${COMMIT_HASH}"
    echo "  Build Time:  ${BUILD_TIME}"
    echo "  Go Version:  ${GO_VERSION}"
    echo "  Module:      ${MODULE_NAME}"
    echo "  Binary:      ${BINARY_NAME}"
}

usage() {
    cat << EOF
RocketVault Build Script

Usage:
    $0 [OPTIONS]

Options:
    --help          Show this help message
    --info          Display build metadata
    --clean         Remove build artifacts (build/, dist/, coverage/)
    --verify-only   Verify environment and dependencies, then exit
    --lint          Run go vet and staticcheck
    --test          Run tests only
    --coverage      Run tests with coverage report
    --current       Build for the current platform (default)
    --all           Cross-compile for all platforms
    --release       go vet + tests + all platforms + release notes
    --skip-tests    Skip tests before building

Environment Variables:
    VERSION         Override version string (default: git describe)
    COMMIT_HASH     Override commit hash  (default: git rev-parse HEAD)

Examples:
    $0                 Build for current platform
    $0 --all           Cross-compile for all platforms
    $0 --release       Full release build
    $0 --coverage      Test coverage report
    $0 --clean         Remove all build artifacts
EOF
}

# ============================================================================
# Main
# ============================================================================

main() {
    local skip_tests=false
    local action="current"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)       usage;                        exit 0 ;;
            --info)          show_info;                    exit 0 ;;
            --clean)         clean;                        exit 0 ;;
            --verify-only)   verify_environment; verify_dependencies; exit 0 ;;
            --lint)          verify_environment; run_lint; exit 0 ;;
            --test)          action="test" ;;
            --coverage)      action="coverage" ;;
            --current)       action="current" ;;
            --all)           action="all" ;;
            --release)       action="release" ;;
            --skip-tests)    skip_tests=true ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    show_info
    echo

    verify_environment
    verify_dependencies

    case "$action" in
        test)
            run_tests
            ;;
        coverage)
            run_coverage
            ;;
        current)
            [[ "$skip_tests" == false ]] && run_tests
            build_current
            ;;
        all)
            [[ "$skip_tests" == false ]] && run_tests
            build_all
            ;;
        release)
            build_release
            ;;
    esac

    echo
    log_success "Done."
}

main "$@"
