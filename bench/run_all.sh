#!/usr/bin/env bash
# Run all benchmarks. Thin wrapper around scripts/bench.sh.

set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/../scripts/bench.sh" "$@"
