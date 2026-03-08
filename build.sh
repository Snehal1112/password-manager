#!/usr/bin/env bash

# Password Manager Build Script
# Following 2025 Go build best practices
#
# Usage:
#   ./build.sh              # Build for current platform
#   ./build.sh --all        # Build for all platforms
#   ./build.sh --release    # Build optimized release binaries
#   ./build.sh --clean      # Clean build artifacts

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

# Build metadata
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
COMMIT_HASH="${COMMIT_HASH:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GO_VERSION="$(go version | awk '{print $3}')"

# Module and binary info
MODULE_NAME="rocketvault"
BINARY_NAME="rocketvault"
MAIN_PACKAGE="."

# Build directories
BUILD_DIR="./build"
DIST_DIR="./dist"
COVERAGE_DIR="./coverage"

# Platform targets for cross-compilation
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

# Build flags
LDFLAGS=(
    "-s"  # Strip symbol table
    "-w"  # Strip DWARF debug info
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
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# ============================================================================
# Build functions
# ============================================================================

# Verify build environment
verify_environment() {
    log_info "Verifying build environment..."

    # Check Go installation
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not in PATH"
        exit 1
    fi

    # Check Go version
    local required_version="1.24"
    local current_version=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')

    log_info "Go version: ${current_version}"

    # Verify go.mod exists
    if [[ ! -f "go.mod" ]]; then
        log_error "go.mod not found. Run 'go mod init' first"
        exit 1
    fi

    log_success "Environment verification complete"
}

# Verify dependencies
verify_dependencies() {
    log_info "Verifying dependencies..."

    # Download dependencies
    go mod download

    # Verify dependencies
    if ! go mod verify; then
        log_error "Dependency verification failed"
        exit 1
    fi

    # Tidy up go.mod and go.sum
    go mod tidy

    log_success "Dependencies verified"
}

# Run tests before building
run_tests() {
    log_info "Running tests..."

    if go test -race -timeout 5m ./...; then
        log_success "All tests passed"
    else
        log_error "Tests failed"
        exit 1
    fi
}

# Build for current platform
build_current() {
    log_info "Building for current platform..."

    local output="${BUILD_DIR}/${BINARY_NAME}"

    # Add .exe extension for Windows
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        output="${output}.exe"
    fi

    # Create build directory
    mkdir -p "${BUILD_DIR}"

    # Build with optimizations
    # Note: CGO_ENABLED=1 required for sqlite3
    CGO_ENABLED=1 go build \
        -trimpath \
        -ldflags="${LDFLAGS[*]}" \
        -o "${output}" \
        "${MAIN_PACKAGE}"

    log_success "Built: ${output}"

    # Display binary info
    if command -v file &> /dev/null; then
        file "${output}"
    fi

    # Display size
    local size=$(du -h "${output}" | cut -f1)
    log_info "Binary size: ${size}"
}

# Build for all platforms
build_all() {
    log_info "Building for all platforms..."

    mkdir -p "${DIST_DIR}"

    for platform in "${PLATFORMS[@]}"; do
        local GOOS="${platform%/*}"
        local GOARCH="${platform#*/}"
        local output_name="${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}"

        # Add .exe extension for Windows
        if [[ "$GOOS" == "windows" ]]; then
            output_name="${output_name}.exe"
        fi

        local output_path="${DIST_DIR}/${output_name}"

        log_info "Building ${GOOS}/${GOARCH}..."

        # Note: CGO_ENABLED=1 required for sqlite3
        # Cross-compilation with CGO requires appropriate cross-compilers
        env CGO_ENABLED=1 GOOS="${GOOS}" GOARCH="${GOARCH}" go build \
            -trimpath \
            -ldflags="${LDFLAGS[*]}" \
            -o "${output_path}" \
            "${MAIN_PACKAGE}"

        # Generate checksum
        if command -v sha256sum &> /dev/null; then
            sha256sum "${output_path}" > "${output_path}.sha256"
        fi

        # Create tarball (except for Windows)
        if [[ "$GOOS" != "windows" ]]; then
            local tarball="${DIST_DIR}/${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}.tar.gz"
            tar -czf "${tarball}" -C "${DIST_DIR}" "$(basename "${output_path}")"

            if command -v sha256sum &> /dev/null; then
                sha256sum "${tarball}" > "${tarball}.sha256"
            fi

            log_success "Created: ${tarball}"
        else
            # Create zip for Windows
            local zipfile="${DIST_DIR}/${BINARY_NAME}-${VERSION}-${GOOS}-${GOARCH}.zip"
            (cd "${DIST_DIR}" && zip -q "${zipfile##*/}" "$(basename "${output_path}")")

            if command -v sha256sum &> /dev/null; then
                sha256sum "${zipfile}" > "${zipfile}.sha256"
            fi

            log_success "Created: ${zipfile}"
        fi
    done

    log_success "All platform builds complete"
    ls -lh "${DIST_DIR}"
}

# Build optimized release
build_release() {
    log_info "Building optimized release binaries..."

    # Run tests first
    run_tests

    # Build for all platforms
    build_all

    # Generate release notes
    generate_release_notes

    log_success "Release build complete"
}

# Generate release notes
generate_release_notes() {
    local notes_file="${DIST_DIR}/RELEASE_NOTES.md"

    log_info "Generating release notes..."

    cat > "${notes_file}" << EOF
# ${MODULE_NAME} ${VERSION}

**Build Date**: ${BUILD_TIME}
**Commit**: ${COMMIT_HASH}
**Go Version**: ${GO_VERSION}

## Build Artifacts

EOF

    # List all artifacts with checksums
    shopt -s nullglob
    for file in "${DIST_DIR}"/*.tar.gz "${DIST_DIR}"/*.zip; do
        if [[ -f "$file" ]]; then
            local checksum_file="${file}.sha256"
            if [[ -f "$checksum_file" ]]; then
                local checksum=$(cut -d' ' -f1 "${checksum_file}")
                echo "- \`$(basename "$file")\` - SHA256: \`${checksum}\`" >> "${notes_file}"
            fi
        fi
    done
    shopt -u nullglob

    log_success "Release notes created: ${notes_file}"
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."

    rm -rf "${BUILD_DIR}" "${DIST_DIR}" "${COVERAGE_DIR}"
    go clean -cache -testcache -modcache

    log_success "Clean complete"
}

# Display build information
show_info() {
    log_info "Build Information:"
    echo "  Version:     ${VERSION}"
    echo "  Commit:      ${COMMIT_HASH}"
    echo "  Build Time:  ${BUILD_TIME}"
    echo "  Go Version:  ${GO_VERSION}"
    echo "  Module:      ${MODULE_NAME}"
    echo "  Binary:      ${BINARY_NAME}"
}

# Display usage
usage() {
    cat << EOF
Password Manager Build Script

Usage:
    $0 [OPTIONS]

Options:
    --help              Show this help message
    --info              Display build information
    --clean             Clean build artifacts
    --verify-only       Only verify environment and dependencies
    --test              Run tests only
    --current           Build for current platform (default)
    --all               Build for all platforms
    --release           Build optimized release (runs tests + all platforms)
    --skip-tests        Skip running tests before build

Examples:
    $0                  # Build for current platform
    $0 --all            # Cross-compile for all platforms
    $0 --release        # Create release build with all platforms
    $0 --clean          # Clean all build artifacts

Environment Variables:
    VERSION             Override version (default: git tag or 'dev')
    COMMIT_HASH         Override commit hash (default: git rev-parse)

EOF
}

# ============================================================================
# Main
# ============================================================================

main() {
    local skip_tests=false
    local action="current"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                usage
                exit 0
                ;;
            --info)
                show_info
                exit 0
                ;;
            --clean)
                clean
                exit 0
                ;;
            --verify-only)
                verify_environment
                verify_dependencies
                exit 0
                ;;
            --test)
                run_tests
                exit 0
                ;;
            --current)
                action="current"
                shift
                ;;
            --all)
                action="all"
                shift
                ;;
            --release)
                action="release"
                shift
                ;;
            --skip-tests)
                skip_tests=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Show build info
    show_info
    echo

    # Verify environment
    verify_environment
    verify_dependencies

    # Run tests unless skipped
    if [[ "$skip_tests" == false && "$action" != "release" ]]; then
        run_tests
    fi

    # Execute build action
    case "$action" in
        current)
            build_current
            ;;
        all)
            build_all
            ;;
        release)
            build_release
            ;;
    esac

    echo
    log_success "Build completed successfully!"
}

# Run main function
main "$@"
