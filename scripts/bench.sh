#!/usr/bin/env bash
# Pulsar-M reproducible benchmarks.
#
# Runs the experimental-evaluation harness and writes results to
# bench/results/. Hardware fingerprint is captured so reviewers can compare.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export GOWORK=off

OUT_DIR="bench/results"
mkdir -p "$OUT_DIR"

echo "==> hardware fingerprint"
{
    uname -a
    if command -v sysctl >/dev/null 2>&1; then
        sysctl -a 2>/dev/null | grep -E 'machdep\.cpu\.brand_string|hw\.ncpu|hw\.memsize' || true
    fi
    if [[ -f /proc/cpuinfo ]]; then
        grep -E 'model name|cpu MHz' /proc/cpuinfo | head -2
    fi
    go version
} > "$OUT_DIR/fingerprint.txt"

echo "==> Go benchmarks"
go test -bench=. -benchmem -count=3 -run=^$ -benchtime=2s ./ref/go/... | tee "$OUT_DIR/go-bench.txt"

echo "==> done — results in $OUT_DIR/"
