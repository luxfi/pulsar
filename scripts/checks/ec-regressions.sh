#!/usr/bin/env bash
# scripts/checks/ec-regressions.sh — Regression-axiom guards.
#
# Specific axiom SHAPES that have been retired but would silently
# expand the trust footprint if re-introduced. CI grep-fails if
# they ever come back.
#
# Currently guarded:
#
#   - `declare axiom reshare_preserves_secret`
#     Was the v0.1 behavioral axiom on an abstract R; replaced by
#     a concrete `ReshareHonest` module + an algebraic lemma
#     `reshare_preserves_secret_honest` reducing to Shamir-zero
#     re-randomisation. Reintroducing the bad shape would silently
#     re-open the trust footprint.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC_ROOT="$REPO_ROOT/proofs/easycrypt"

echo "==> Regression guard: behavioral reshare_preserves_secret axiom"
if grep -RE "^[[:space:]]*declare axiom[[:space:]]+reshare_preserves_secret" \
   "$EC_ROOT" >/dev/null 2>&1 ; then
    echo "    [FAIL] behavioral reshare_preserves_secret axiom reintroduced"
    echo "           (must remain a discharged lemma on ReshareHonest,"
    echo "            not a declare axiom on an abstract R)."
    exit 2
fi
echo "    [ok]   no abstract reshare_preserves_secret axiom present"
exit 0
