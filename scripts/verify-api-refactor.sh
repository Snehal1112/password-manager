#!/usr/bin/env bash
# Verification gate for the api/ generic-primitive refactor.
# Every plan in the chain runs this before committing. It fails loudly rather
# than reporting partial success, because a refactor that only mostly works is
# a regression that has not been found yet.
set -euo pipefail

# The coverage invariant is the count of UNCOVERED statements, not the covered
# ratio. A dedup refactor deletes boilerplate that was always covered, which
# shrinks numerator and denominator together and drags the ratio down even
# though nothing tested was lost. Plan 02 measured exactly that: 91 statements
# removed, 89 of them covered, ratio 86.0% -> 85.7%, uncovered 406 -> 404.
# A ratio floor would have failed that plan for succeeding.
#
# Uncovered count is the invariant that actually means "no tested behavior was
# lost": it can only rise if new untested code appeared or a tested path stopped
# being exercised.
BASELINE_UNCOVERED=406
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> go build ./..."
go build ./...

echo "==> go vet ./api/..."
go vet ./api/...

echo "==> go test ./... -count=1"
go test ./... -count=1

echo "==> go test ./api/... -count=1 -coverprofile"
profile="$(mktemp)"
trap 'rm -f "$profile"' EXIT
go test ./api/... -count=1 -coverprofile="$profile"

read -r total covered uncovered ratio <<<"$(
    awk 'NR > 1 && NF {
        n = $(NF - 1)
        c = $NF
        tot += n
        if (c > 0) cov += n
    }
    END {
        printf "%d %d %d %.1f", tot, cov, tot - cov, (tot ? 100 * cov / tot : 0)
    }' "$profile"
)"

echo "==> api/ statements: ${total} total, ${covered} covered, ${uncovered} uncovered (${ratio}%)"

if [ "$uncovered" -gt "$BASELINE_UNCOVERED" ]; then
    echo "FAIL: ${uncovered} uncovered statements, above the ${BASELINE_UNCOVERED} baseline."
    echo "      Something new is untested, or a previously exercised path no longer runs."
    exit 1
fi

echo "PASS: build, vet, full test suite green; ${uncovered} uncovered statements (baseline ${BASELINE_UNCOVERED})."
