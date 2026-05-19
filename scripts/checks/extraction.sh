#!/usr/bin/env bash
# scripts/checks/extraction.sh — Jasmin → EasyCrypt extraction sanity.
#
# `scripts/extract-jasmin-ec.sh` runs jasmin2ec over the threshold-
# layer .jazz files and confirms the extracted EC theories type-
# check standalone. This gate fails the build if extraction breaks.
#
# Requires jasminc + easycrypt. Skips silently otherwise.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

JASMIN_ROOT="$REPO_ROOT/jasmin"
LIBJADE_DIR="$JASMIN_ROOT/ml-dsa-65/libjade/oldsrc-should-delete"

have_jasmin=0
have_ec=0
command -v jasminc   >/dev/null 2>&1 && have_jasmin=1
command -v easycrypt >/dev/null 2>&1 && have_ec=1

if [[ $have_jasmin -eq 0 || $have_ec -eq 0 || ! -d "$LIBJADE_DIR" ]]; then
    echo "==> Jasmin → EC extraction"
    echo "    [skip] missing jasminc / easycrypt / libjade"
    exit 0
fi

echo "==> Jasmin → EC extraction sanity check"
if bash "$REPO_ROOT/scripts/extract-jasmin-ec.sh" >/tmp/extract.log 2>&1; then
    n_ok=$(grep -c '\[ok\]' /tmp/extract.log || echo 0)
    echo "    [ok]   $n_ok .jazz files extracted + type-checked"
    exit 0
else
    echo "    [FAIL] extraction sanity check failed — see /tmp/extract.log"
    tail -20 /tmp/extract.log | sed 's/^/      /'
    exit 2
fi
