#!/usr/bin/env bash
# Pulsar-M SBOM generation.
#
# Produces an SPDX SBOM for the reference implementation, capturing every
# transitive dependency. Required as part of the MPTC submission package.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT="bench/results/sbom.spdx.json"
mkdir -p "$(dirname "$OUT")"

if command -v cyclonedx-gomod >/dev/null 2>&1; then
    ( cd ref/go && cyclonedx-gomod mod -json -output "$REPO_ROOT/$OUT" )
elif command -v go-licenses >/dev/null 2>&1; then
    echo "    [info] cyclonedx-gomod not found; falling back to go-licenses report"
    ( cd ref/go && go-licenses csv ./... > "$REPO_ROOT/${OUT%.json}.csv" )
else
    echo "    [warn] no SBOM tool found (install cyclonedx-gomod or go-licenses)"
    exit 1
fi

echo "==> SBOM written to $OUT"
