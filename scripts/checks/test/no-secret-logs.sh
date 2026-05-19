#!/usr/bin/env bash
# scripts/checks/test/no-secret-logs.sh — DD-007 linter.
#
# Secret-touching files MUST NOT use stdlib `log.*`, `fmt.Print*`,
# or `panic()`. The forbidden surface would leak partial secrets
# under a panic stack trace or in shipped logs.
#
# This list is the implementation surface that touches secrets.
# Keep in sync when new secret-bearing files land.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

echo "==> No-secret-logs linter (DD-007)"

SECRET_FILES=(
    "ref/go/pkg/pulsar/keygen.go"
    "ref/go/pkg/pulsar/sign.go"
    "ref/go/pkg/pulsar/dkg.go"
    "ref/go/pkg/pulsar/threshold.go"
    "ref/go/pkg/pulsar/reshare.go"
    "ref/go/pkg/pulsar/shamir.go"
)

FAIL=0
for f in "${SECRET_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        # Allow comments mentioning these tokens, but forbid actual use:
        # filter out lines starting with // and import-comment blocks.
        if grep -nE '^[^/]*(\<log\.(Print|Fatal|Panic)|fmt\.(Print|Fprint)|panic\()' "$f" \
            | grep -vE '^\s*//' ; then
            echo "    [FAIL] secret-touching file $f contains forbidden logging or panic" >&2
            FAIL=1
        fi
    fi
done

if [[ $FAIL -ne 0 ]]; then
    exit 1
fi
echo "    [ok]   no forbidden logging/panic in ${#SECRET_FILES[@]} secret-touching files"
