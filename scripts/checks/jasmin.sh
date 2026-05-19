#!/usr/bin/env bash
# scripts/checks/jasmin.sh — Jasmin type-check + jasmin-ct gates.
#
# Two independent obligations:
#
#   1. The threshold-layer .jazz files (round1, round2, combine) MUST
#      type-check under jasminc and MUST pass jasmin-ct (without
#      --infer). Failure of either is BLOCKING; this script exits 2.
#
#   2. The libjade ML-DSA-65 sign.jazz is run through jasmin-ct
#      --infer as ADVISORY (tracked under #2). Findings are reported
#      but do not fail the gate.
#
# Skip-friendly: exits 0 with [skip] message when jasminc or libjade
# is not on the path, so the orchestrator gate stays additive.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

JASMIN_ROOT="$REPO_ROOT/jasmin"
LIBJADE_DIR="$JASMIN_ROOT/ml-dsa-65/libjade/oldsrc-should-delete"

if ! command -v jasminc >/dev/null 2>&1; then
    echo "==> jasmin"
    echo "    [skip] jasminc not on PATH (opam install jasmin)"
    exit 0
fi
echo "==> jasminc found ($(jasminc -version 2>&1 | head -1))"

if [[ ! -d "$LIBJADE_DIR" ]]; then
    echo "    [info] libjade not fetched; skipping jasmin gates"
    echo "           fetch: $JASMIN_ROOT/ml-dsa-65/fetch.sh"
    exit 0
fi

JAZZ_FILES=(
    "$JASMIN_ROOT/threshold/round1.jazz"
    "$JASMIN_ROOT/threshold/round2.jazz"
    "$JASMIN_ROOT/threshold/combine.jazz"
)

# ----- threshold layer: type check -----
JASMIN_FAIL=0
for f in "${JAZZ_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "    [warn] missing: $f"
        continue
    fi
    echo "    [check] $f"
    if ! jasminc -until_typing -I "Jade=$LIBJADE_DIR" "$f" 2>&1 | grep -E "^.*error"; then
        echo "    [ok]   $f type-checks"
    else
        echo "    [FAIL] $f"
        JASMIN_FAIL=1
    fi
done
if [[ $JASMIN_FAIL -ne 0 ]]; then
    echo
    echo "    Jasmin type-check gate FAILED."
    exit 2
fi

# ----- threshold layer: jasmin-ct BLOCKING -----
if ! command -v jasmin-ct >/dev/null 2>&1; then
    echo "    [skip] jasmin-ct not on PATH"
    exit 0
fi

echo
echo "==> jasmin-ct (BLOCKING — threshold layer)"
CT_FAIL=0
for f in "${JAZZ_FILES[@]}"; do
    [[ -f "$f" ]] || continue
    CT_OUT=$(jasmin-ct -I "Jade=$LIBJADE_DIR" "$f" 2>&1)
    if [[ -z "$CT_OUT" ]]; then
        echo "    [ok]   $f"
    else
        echo "    [FAIL] $f"
        echo "$CT_OUT" | sed 's/^/      /'
        CT_FAIL=1
    fi
done
if [[ $CT_FAIL -ne 0 ]]; then
    echo
    echo "    jasmin-ct gate FAILED — threshold layer no longer CT-clean."
    exit 2
fi

# ----- libjade sign: jasmin-ct ADVISORY -----
LIBJADE_SIGN="$LIBJADE_DIR/crypto_sign/dilithium/dilithium3/amd64/ref/sign.jazz"
if [[ -f "$LIBJADE_SIGN" ]]; then
    echo
    echo "==> jasmin-ct (advisory — libjade ML-DSA-65 sign, #2)"
    CT_OUT=$(jasmin-ct --infer -I "Jade=$LIBJADE_DIR" "$LIBJADE_SIGN" 2>&1 | tail -2 || true)
    if [[ -z "$CT_OUT" ]]; then
        echo "    [advisory-ok] $LIBJADE_SIGN"
    else
        echo "    [advisory-note] $LIBJADE_SIGN"
        echo "$CT_OUT" | sed 's/^/      /'
    fi
    echo "    (see ct/jasmin-ct-libjade.md for the documented fix path)"
fi

exit 0
