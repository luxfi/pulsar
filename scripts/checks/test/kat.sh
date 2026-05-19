#!/usr/bin/env bash
# scripts/checks/test/kat.sh — KAT validation.
#
# Replays the canonical Known-Answer Tests (Keygen, Sign, Verify,
# ThresholdSign, DKG) against the reference Go implementation.
# Skips silently when vectors/ hasn't been generated; this stays
# additive for fresh checkouts.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

export GOWORK=off

echo "==> KAT validation"
if [[ -f vectors/keygen.json ]]; then
    go test -count=1 -run "^TestKAT_" ./ref/go/pkg/pulsar/
else
    echo "    [info] vectors/ not generated — run scripts/gen_vectors.sh"
fi
