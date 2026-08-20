#!/usr/bin/env bash

# RocketVault Install Script
#
# Downloads the latest (or a pinned) release binary for the current
# platform straight from GitHub Releases and installs it. Because this
# downloads via curl instead of a browser, macOS does NOT tag the file
# with the com.apple.quarantine extended attribute that triggers
# Gatekeeper's "Apple could not verify ... is free of malware" dialog —
# unlike a browser download of the same asset, this script's binary runs
# immediately with no extra steps.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Snehal1112/rocketvault/v-4.0.0/install.sh | bash
#   VERSION=v0.2.5 ./install.sh          # install a specific tag
#   INSTALL_DIR=~/.local/bin ./install.sh  # install somewhere other than /usr/local/bin

set -euo pipefail

REPO="Snehal1112/rocketvault"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="rocketvault"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

detect_platform() {
    local os arch
    case "$(uname -s)" in
        Darwin) os="darwin" ;;
        Linux)  os="linux" ;;
        *)
            log_error "Unsupported OS: $(uname -s). Windows users: download the .zip asset manually from https://github.com/${REPO}/releases"
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    # macOS releases are Apple Silicon only; there is no Intel build to download.
    if [[ "${os}" == "darwin" && "${arch}" == "amd64" ]]; then
        log_error "Intel Macs are not supported. RocketVault ships macOS binaries for Apple Silicon (arm64) only; build from source instead."
        exit 1
    fi

    echo "${os} ${arch}"
}

resolve_version() {
    if [[ -n "${VERSION:-}" ]]; then
        echo "${VERSION}"
        return
    fi

    log_info "Resolving latest release..." >&2
    local latest
    latest=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

    if [[ -z "${latest}" ]]; then
        log_error "Could not resolve the latest release. Set VERSION=vX.Y.Z and re-run."
        exit 1
    fi

    echo "${latest}"
}

main() {
    if ! command -v curl &>/dev/null; then
        log_error "curl is required but not installed."
        exit 1
    fi
    if ! command -v tar &>/dev/null; then
        log_error "tar is required but not installed."
        exit 1
    fi

    read -r os arch <<< "$(detect_platform)"
    local version
    version=$(resolve_version)

    log_info "Installing rocketvault ${version} for ${os}/${arch}..."

    local base_name="rocketvault-${version}-${os}-${arch}"
    local archive="${base_name}.tar.gz"
    local download_url="https://github.com/${REPO}/releases/download/${version}/${archive}"
    local checksum_url="${download_url}.sha256"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "${tmp_dir}"' EXIT

    log_info "Downloading ${download_url}..."
    if ! curl -fsSL -o "${tmp_dir}/${archive}" "${download_url}"; then
        log_error "Download failed. Check that ${version} has a ${os}/${arch} release asset: https://github.com/${REPO}/releases/tag/${version}"
        exit 1
    fi

    log_info "Verifying checksum..."
    if curl -fsSL -o "${tmp_dir}/${archive}.sha256" "${checksum_url}"; then
        (
            cd "${tmp_dir}"
            if command -v sha256sum &>/dev/null; then
                sha256sum -c "${archive}.sha256"
            else
                shasum -a 256 -c "${archive}.sha256"
            fi
        )
        log_success "Checksum verified."
    else
        log_error "Could not download checksum file — refusing to install an unverified binary."
        exit 1
    fi

    tar -xzf "${tmp_dir}/${archive}" -C "${tmp_dir}"

    local extracted="${tmp_dir}/${base_name}"
    if [[ ! -f "${extracted}" ]]; then
        log_error "Expected binary not found in archive: ${base_name}"
        exit 1
    fi
    chmod +x "${extracted}"

    if [[ -w "${INSTALL_DIR}" ]]; then
        mv "${extracted}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        log_info "Elevated permissions required to write to ${INSTALL_DIR}..."
        sudo mv "${extracted}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    log_success "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
    "${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || true
}

main "$@"
