#!/usr/bin/env bash
# Pulsar nightly gate — REAL-budget runs for the things that the
# per-push gates skip because their per-push budget is too small to
# be meaningful.
#
# This script is what should run from CRON / scheduled CI, NOT the
# per-push hook. Expected runtime: hours, not seconds.
#
# The runs, in order:
#
#   1. fuzz (parser): 1h per target — Makefile.fuzz fuzz-nightly.
#      Five parser-surface targets at ~200k-400k execs/sec each.
#      Approx 5h total.
#
#   2. fuzz (differential): 1h — Makefile.fuzz fuzz-diff-nightly.
#      ~150-450 execs/sec (heavy: full DKG + threshold-sign +
#      reconstruct + centralized-sign each iter). ~500k-1M iters.
#
#   3. dudect submission: 10^9 samples per target via
#      ct/dudect/run-submission.sh. Hours per target on a pinned CPU.
#      Produces ct/dudect/results/submission-<commit>-<utc>.* with
#      audit metadata.
#
# Per-push gates (test.sh + check-high-assurance.sh) cover everything
# else (Go unit tests, KAT, interop, jasmin-ct, EC compile, bridge
# guard, etc.) at real-budget. Run those first via:
#
#   bash scripts/test.sh
#   bash scripts/check-high-assurance.sh
#
# This nightly script does NOT re-run those — it assumes a green
# per-push gate (otherwise the longer runs are wasted).
#
# Override per-target budgets via env:
#
#   FUZZ_TIME=2h                        per parser-fuzz target window
#   DIFF_FUZZ_TIME=2h                   differential-fuzz window
#   DUDECT_SAMPLES=...                  per-batch sample count
#   DUDECT_MAX_BATCHES=...              max batches per target
#   CPU=N                               CPU to pin to (Linux taskset)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FUZZ_TIME="${FUZZ_TIME:-1h}"
DIFF_FUZZ_TIME="${DIFF_FUZZ_TIME:-1h}"

echo "==> Pulsar nightly gate"
echo "    fuzz_time          $FUZZ_TIME"
echo "    diff_fuzz_time     $DIFF_FUZZ_TIME"
echo "    dudect_samples     ${DUDECT_SAMPLES:-1000000}"
echo "    dudect_max_batches ${DUDECT_MAX_BATCHES:-1000}"
echo "    cpu_pin            ${CPU:-autodetect on Linux, none on Darwin}"
echo

OVERALL=0

# ---------------------------------------------------------------------------
# 1. Parser-surface fuzz (REAL budget — 1h per target by default).
# ---------------------------------------------------------------------------
echo "==> Layer-6 parser fuzz (REAL — $FUZZ_TIME per target)"
if ! NIGHTLY_TIME="$FUZZ_TIME" make -C ref/go/pkg/pulsar -f Makefile.fuzz fuzz-nightly; then
    rc=$?
    echo "    [FAIL] parser fuzz exited rc=$rc"
    OVERALL=$rc
fi
echo

# ---------------------------------------------------------------------------
# 2. Differential fuzz (REAL — 1h by default).
# ---------------------------------------------------------------------------
if [[ $OVERALL -eq 0 ]]; then
    echo "==> Layer-6 differential fuzz (REAL — $DIFF_FUZZ_TIME)"
    if ! NIGHTLY_TIME="$DIFF_FUZZ_TIME" make -C ref/go/pkg/pulsar -f Makefile.fuzz fuzz-diff-nightly; then
        rc=$?
        echo "    [FAIL] differential fuzz exited rc=$rc"
        OVERALL=$rc
    fi
    echo
fi

# ---------------------------------------------------------------------------
# 3. dudect submission-grade run (REAL — 10^9 samples per target).
# ---------------------------------------------------------------------------
if [[ $OVERALL -eq 0 ]]; then
    echo "==> dudect submission-grade run (REAL — pinned-CPU, 10^9 samples)"
    if ! bash ct/dudect/run-submission.sh; then
        rc=$?
        echo "    [FAIL] dudect submission exited rc=$rc"
        OVERALL=$rc
    fi
    echo
fi

if [[ $OVERALL -eq 0 ]]; then
    echo "==> done — nightly gate green"
else
    echo "==> nightly gate FAILED with rc=$OVERALL"
fi
exit $OVERALL
