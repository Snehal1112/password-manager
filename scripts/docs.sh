#!/usr/bin/env bash
# Build, package, or preview the RocketVault docs site.
# Thin wrapper around scripts/docsgen (a standalone Go module — its own
# go.mod keeps goldmark and friends out of the rocketvault binary's
# dependency graph) so the day-to-day command stays a plain shell script.
#
#   scripts/docs.sh build              # markdown -> styled html
#   scripts/docs.sh package [version]  # build + tar.gz/zip under dist/
#   scripts/docs.sh serve <dir> [port] # preview a built/packaged site
set -euo pipefail
export DOCSGEN_CALLER_DIR="$PWD"
cd "$(dirname "${BASH_SOURCE[0]}")/docsgen"
exec go run . "$@"
