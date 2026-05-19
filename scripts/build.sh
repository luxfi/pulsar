#!/usr/bin/env bash
# Pulsar reproducible build.
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

# macOS MacTeX installs latexmk under /Library/TeX/texbin but does not
# put it on $PATH for non-login shells. Add it explicitly so CI and
# fresh-clone runs find it without operator intervention.
if [[ -x /Library/TeX/texbin/latexmk ]] && ! command -v latexmk >/dev/null 2>&1; then
    export PATH="/Library/TeX/texbin:$PATH"
fi

echo "==> Spec PDF build"
if command -v latexmk >/dev/null 2>&1; then
    ( cd spec && latexmk -pdf -interaction=nonstopmode -file-line-error pulsar.tex )
else
    echo "    [warn] latexmk not found. Install MacTeX (macOS) or TeX Live."
    echo "    macOS: brew install --cask mactex  (then re-run this script)"
    exit 1
fi

echo "==> done"
