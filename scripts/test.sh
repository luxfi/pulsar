#!/usr/bin/env bash
# Pulsar test gate — orchestrator (per-push, REAL tests only).
#
# Each check below lives in its own script under scripts/checks/test/.
# This file is intentionally THIN: it sequences the checks and
# propagates their exit codes. Each per-check is independently
# runnable.
#
# The checks, in order:
#
#   1. go-unit.sh        — go test ./ref/go/... with -race (real)
#   2. no-secret-logs.sh — DD-007 linter on secret-touching files
#   3. kat.sh            — KAT validation against every vector
#                          (skip if vectors/ absent)
#   4. interop.sh        — Class N1 cross-validation under
#                          cloudflare/circl FIPS 204 verifier
#
# NOT in this gate (intentionally): fuzz-smoke + dudect-smoke. Those
# at per-push budget (5-30s fuzz, 40k-sample dudect) don't exercise
# the code at a budget that finds real bugs — they're theater. Run
# them at real budget from the nightly gate:
#
#   scripts/nightly.sh                — runs everything below
#   make -C ref/go/pkg/pulsar -f Makefile.fuzz fuzz-nightly
#                                       (1h per parser-fuzz target)
#   make -C ref/go/pkg/pulsar -f Makefile.fuzz fuzz-diff-nightly
#                                       (1h differential fuzz)
#   bash ct/dudect/run-submission.sh   (10^9 samples per target;
#                                       hours per run on pinned CPU)
#
# Any per-check failure (non-zero exit) fails the orchestrator with
# the same code.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CHECKS=(
    "scripts/checks/test/go-unit.sh"
    "scripts/checks/test/no-secret-logs.sh"
    "scripts/checks/test/kat.sh"
    "scripts/checks/test/interop.sh"
)

OVERALL=0
for check in "${CHECKS[@]}"; do
    rc=0
    bash "$REPO_ROOT/$check" || rc=$?
    if [[ $rc -ne 0 ]]; then
        OVERALL=$rc
        echo
        echo "==> $check exited rc=$rc — aborting gate"
        break
    fi
    echo
done

if [[ $OVERALL -eq 0 ]]; then
    echo "==> done — test gate green"
fi
exit $OVERALL
