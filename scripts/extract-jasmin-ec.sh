#!/usr/bin/env bash
# Regenerate the jasmin2ec extraction artifacts under
# proofs/easycrypt/extraction/build/.
#
# This script is invoked by the high-assurance gate. It does NOT vendor
# the extracted EC into the repo — see proofs/easycrypt/extraction/README.md
# for the rationale.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LIBJADE="$REPO_ROOT/jasmin/ml-dsa-65/libjade/oldsrc-should-delete"
OUT="$REPO_ROOT/proofs/easycrypt/extraction/build"
JAZZ_FILES=(
    "$REPO_ROOT/jasmin/threshold/round1.jazz"
    "$REPO_ROOT/jasmin/threshold/round2.jazz"
    "$REPO_ROOT/jasmin/threshold/combine.jazz"
)

# Libjade Dilithium sign — extraction target for the libjade ↔ FIPS 204
# refinement (the discharge path for Pulsar_N1's S_functional_spec).
# Conditional on libjade being present at the pinned commit.
LIBJADE_DILITHIUM_SIGN="$LIBJADE/crypto_sign/dilithium/dilithium3/amd64/ref/sign.jazz"
if [[ -f "$LIBJADE_DILITHIUM_SIGN" ]]; then
    JAZZ_FILES+=("$LIBJADE_DILITHIUM_SIGN")
fi

if ! command -v jasmin2ec >/dev/null 2>&1; then
    echo "[skip] jasmin2ec not on PATH"
    echo "       install: opam install jasmin --switch=jasmin"
    exit 0
fi

if [[ ! -d "$LIBJADE" ]]; then
    echo "[skip] libjade not fetched"
    echo "       run: $REPO_ROOT/jasmin/ml-dsa-65/fetch.sh"
    exit 0
fi

mkdir -p "$OUT"
rm -rf "$OUT"/*.ec

echo "==> jasmin2ec on threshold layer (output → $OUT)"
for f in "${JAZZ_FILES[@]}"; do
    [[ -f "$f" ]] || { echo "    [warn] missing: $f"; continue; }
    base=$(basename "$f" .jazz)
    out_ec="$OUT/${base}.ec"
    echo "    [extract] $f → $out_ec"
    jasmin2ec \
        -I "Jade=$LIBJADE" \
        --output "$out_ec" \
        "$f"
done

echo
echo "==> Sanity check: extracted EC parses + type-checks"
for f in "${JAZZ_FILES[@]}"; do
    base=$(basename "$f" .jazz)
    ec_file="$OUT/${base}.ec"
    [[ -f "$ec_file" ]] || continue
    if easycrypt compile -I "$OUT" "$ec_file" 2>&1 | grep -q '\[critical\]' ; then
        echo "    [FAIL] $ec_file"
        exit 2
    else
        echo "    [ok]   $ec_file compiles ($(wc -l < "$ec_file") lines)"
    fi
done
