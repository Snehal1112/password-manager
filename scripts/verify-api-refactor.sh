#!/usr/bin/env bash
# Verification gate for the api/ generic-primitive refactor.
# Every plan in the chain runs this before committing. It fails loudly rather
# than reporting partial success, because a refactor that only mostly works is
# a regression that has not been found yet.
set -euo pipefail

BASELINE_COVERAGE=86.0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> go build ./..."
go build ./...

echo "==> go vet ./api/..."
go vet ./api/...

echo "==> go test ./... -count=1"
go test ./... -count=1

echo "==> go test ./api/... -count=1 -cover"
coverage_line="$(go test ./api/... -count=1 -cover | tee /dev/stderr | grep -o 'coverage: [0-9.]*%')"
coverage="${coverage_line#coverage: }"
coverage="${coverage%\%}"

# awk rather than bash arithmetic: these are decimals, and bash only does
# integers, so a plain [ ] comparison would silently accept a drop.
if awk -v c="$coverage" -v b="$BASELINE_COVERAGE" 'BEGIN { exit !(c < b) }'; then
    echo "FAIL: api/ coverage ${coverage}% is below the ${BASELINE_COVERAGE}% baseline."
    exit 1
fi

echo "PASS: build, vet, full test suite green; api/ coverage ${coverage}% (baseline ${BASELINE_COVERAGE}%)."
