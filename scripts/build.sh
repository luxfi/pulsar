#!/usr/bin/env bash
# Pulsar-M reproducible build.
#
# Builds the Go reference implementation and the LaTeX spec PDF. Exits
# non-zero on any failure. Designed to be the CI gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Build the reference impl in module-only mode. A surrounding workspace
# (e.g. ~/work/lux/go.work) does not own this repo's deps and must be
# bypassed deliberately so reviewers get the same view CI gets.
export GOWORK=off

echo "==> Go reference build"
go build ./ref/go/...

echo "==> Spec PDF build (skipped if latexmk not installed)"
if command -v latexmk >/dev/null 2>&1; then
    ( cd spec && latexmk -pdf -interaction=nonstopmode pulsar-m.tex )
else
    echo "    [warn] latexmk not found — skipping. Install TeX Live for full build."
fi

echo "==> done"
