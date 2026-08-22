#!/bin/sh

set -e

BASEDIR=${BASEDIR:-$(realpath "$(dirname "$0")")}

cd "${BASEDIR}"

exec git describe --tags --always --dirty --match="v*" 2>/dev/null | sed 's/^v//' || \
    cat .version 2> /dev/null || echo 0.0.0-unreleased
