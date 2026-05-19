#!/usr/bin/env bash
# Fetch libjade at the pinned commit used by Pulsar's high-assurance track.
#
# We do not vendor libjade into this repository - see ./README.md for the
# fetch-on-demand rationale. This script reproduces the libjade tree on
# demand and pins it to a known-good commit so the submission artifact
# reproduces deterministically across reviewers.

set -euo pipefail

LIBJADE_REPO="https://github.com/formosa-crypto/libjade.git"

# Pinned at submission-tag time. Update at the same time as the
# Pulsar submission tag so the artifact chain stays reproducible.
#
# 9426b32 (2025-12-09) "Dilithium: remove suspicious annotations" is the
# last commit before the libjade dilithium tree restructure that breaks
# our require paths. The dilithium ML-DSA sources are at
#
#     <libjade>/oldsrc-should-delete/crypto_sign/dilithium/dilithium3/amd64/ref/
#     <libjade>/oldsrc-should-delete/crypto_sign/dilithium/common/amd64/
#
# We expose them through a stable `upstream/` symlink (see below) so our
# threshold-layer require paths are insulated from upstream restructures.
LIBJADE_COMMIT="9426b320031ea121c9b07b1a7d7d616dd97c1a75"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -d libjade/.git ]]; then
    echo "==> libjade already cloned at $SCRIPT_DIR/libjade"
    ( cd libjade && git fetch --quiet origin && git checkout --quiet "$LIBJADE_COMMIT" )
else
    echo "==> cloning libjade at $LIBJADE_COMMIT"
    git clone --quiet "$LIBJADE_REPO" libjade
    ( cd libjade && git checkout --quiet "$LIBJADE_COMMIT" )
fi

# Pulsar's Jasmin sources reference libjade through Jasmin's `from Jade
# require ...` mechanism, with the Jade root resolved to the SRC_ROOT
# directory below at compile time via `jasminc -I Jade=$SRC_ROOT`. We
# document the canonical SRC_ROOT for this libjade commit here:
SRC_ROOT="$SCRIPT_DIR/libjade/oldsrc-should-delete"

# Sanity-check that the expected dilithium3 ref tree is in place.
DIL3_REF="$SRC_ROOT/crypto_sign/dilithium/dilithium3/amd64/ref"
if [[ ! -d "$DIL3_REF" ]]; then
    echo "!! libjade tree at $LIBJADE_COMMIT does not contain $DIL3_REF" >&2
    echo "!! upstream may have restructured; re-pin LIBJADE_COMMIT in this script" >&2
    exit 1
fi

# Expose a stable 'upstream/' path that our threshold layer can reference
# even if libjade's internal layout shifts again. We symlink rather than
# copy so a `git pull` in libjade/ stays consistent. Prefer a
# repository-relative target so a `git mv` of the whole tree stays
# coherent; fall back to absolute on platforms that can't compute it.
if [[ -L upstream || -d upstream ]]; then
    rm -rf upstream
fi
REL_TARGET="libjade/oldsrc-should-delete/crypto_sign/dilithium/dilithium3/amd64/ref"
if [[ -d "$SCRIPT_DIR/$REL_TARGET" ]]; then
    ln -s "$REL_TARGET" upstream
else
    ln -s "$DIL3_REF" upstream
fi

# Print the jasminc -I flag the caller should use.
echo "==> libjade ready at $SCRIPT_DIR/libjade ($LIBJADE_COMMIT)"
echo "    ML-DSA-65 sources: $DIL3_REF"
echo "    Stable symlink:    $SCRIPT_DIR/upstream -> $DIL3_REF"
echo
echo "    To compile Pulsar threshold .jazz files, pass:"
echo "      jasminc -I Jade=$SRC_ROOT -I Pulsar=$(realpath "$SCRIPT_DIR/..") <file>.jazz"
