#!/usr/bin/env bash
# Pulsar-M test suite runner.
#
# Runs unit tests, KAT validation (when available), and the no-secret-logs
# linter. Designed to be the CI gate alongside scripts/build.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Module-only build. See note in scripts/build.sh.
export GOWORK=off

echo "==> Go unit tests"
go test -count=1 -race ./ref/go/...

echo "==> No-secret-logs linter"
# DD-007: secret-touching files MUST NOT use stdlib log.* / fmt.Print* /
# panic. This list is the implementation surface that touches secrets.
SECRET_FILES=(
    "ref/go/pkg/pulsarm/keygen.go"
    "ref/go/pkg/pulsarm/sign.go"
    "ref/go/pkg/pulsarm/dkg.go"
    "ref/go/pkg/pulsarm/threshold.go"
    "ref/go/pkg/pulsarm/reshare.go"
    "ref/go/pkg/pulsarm/shamir.go"
)
for f in "${SECRET_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        # Allow comments mentioning these tokens, but forbid actual use:
        # filter out lines starting with // and import-comment blocks.
        if grep -nE '^[^/]*(\<log\.(Print|Fatal|Panic)|fmt\.(Print|Fprint)|panic\()' "$f" \
            | grep -vE '^\s*//' ; then
            echo "FAIL: secret-touching file $f contains forbidden logging or panic" >&2
            exit 1
        fi
    fi
done

echo "==> KAT validation"
if [[ -f vectors/keygen.json ]]; then
    go test -count=1 -run "^TestKAT_" ./ref/go/pkg/pulsarm/
else
    echo "    [info] vectors/ not generated — run scripts/gen_vectors.sh"
fi

echo "==> done"
