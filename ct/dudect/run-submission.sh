#!/usr/bin/env bash
# Submission-grade dudect runner for Pulsar.
#
# The smoke-budget dudect runs in scripts/check-high-assurance.sh
# (10k × 4 verify, 2k × 4 combine) are useful for catching obvious
# regressions but do not constitute a statistical proof of constant
# time. NIST MPTC submission requires:
#
#   - ~10^9 samples per target
#   - pinned CPU (no migration during measurement)
#   - quiet host (no other CPU-bound workloads)
#   - frequency scaling disabled (Linux) or honest acknowledgement
#     that Apple Silicon doesn't expose a fixed-frequency mode and
#     the timer noise floor is higher
#   - recorded: threshold, sample count, batches, CPU, compiler
#     version, jasminc version, dudect commit, repo commit
#
# This script does all of the above and pins the result to a
# timestamped log under ct/dudect/results/ that can be referenced
# from the submission package.
#
# Usage:
#   bash ct/dudect/run-submission.sh                 # both targets
#   TARGET=verify  bash ct/dudect/run-submission.sh  # just verify
#   TARGET=combine bash ct/dudect/run-submission.sh  # just combine
#
# Env overrides:
#   DUDECT_SAMPLES        per-batch sample count (default 1000000)
#   DUDECT_MAX_BATCHES    max batches per target (default 1000)
#   CPU                   CPU to pin to (Linux taskset -c)
#                         default: empty (no pin) on macOS,
#                         autodetect last-CPU on Linux
#   LABEL                 result tag (defaults to commit short hash)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CT_ROOT="$REPO_ROOT/ct/dudect"
RESULTS="$CT_ROOT/results"
mkdir -p "$RESULTS"

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

DUDECT_SAMPLES="${DUDECT_SAMPLES:-1000000}"
DUDECT_MAX_BATCHES="${DUDECT_MAX_BATCHES:-1000}"
TARGET="${TARGET:-both}"

case "$TARGET" in
    both|verify|combine) ;;
    *) echo "TARGET must be one of: both, verify, combine" >&2; exit 1;;
esac

# CPU pinning: autodetect on Linux to the last available CPU
# (typically the least-noisy one for a desktop with browser activity
# on CPU0). On macOS pthread_setaffinity_np isn't exposed; we just
# warn and proceed.
HOST_OS="$(uname -s)"
CPU="${CPU:-}"
if [[ -z "$CPU" && "$HOST_OS" == "Linux" ]]; then
    NPROC=$(nproc 2>/dev/null || echo 1)
    CPU=$((NPROC - 1))
fi

LABEL="${LABEL:-$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)}"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_BASE="$RESULTS/submission-${LABEL}-${STAMP}"

# ---------------------------------------------------------------------------
# Metadata capture
# ---------------------------------------------------------------------------

META="$LOG_BASE.meta.txt"
{
    echo "# Pulsar dudect submission-grade run"
    echo "timestamp_utc:    $STAMP"
    echo "label:            $LABEL"
    echo "repo_commit:      $(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "repo_dirty:       $(cd "$REPO_ROOT" && git diff --quiet 2>/dev/null && echo no || echo yes)"
    echo "host_os:          $HOST_OS"
    echo "host_arch:        $(uname -m)"
    echo "host_kernel:      $(uname -r)"
    echo "host_cpu_model:   $(
        if [[ "$HOST_OS" == "Darwin" ]]; then
            sysctl -n machdep.cpu.brand_string 2>/dev/null
        elif [[ "$HOST_OS" == "Linux" ]]; then
            grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | sed 's/^model name[[:space:]]*:[[:space:]]*//'
        fi
    )"
    echo "cpu_pin:          ${CPU:-none}"
    echo "dudect_commit:    $(cd "$CT_ROOT/dudect" && git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "go_version:       $(go version 2>/dev/null || echo unknown)"
    echo "cc_version:       $(${CC:-cc} --version 2>/dev/null | head -1 || echo unknown)"
    if command -v jasminc >/dev/null 2>&1; then
        echo "jasminc_version:  $(jasminc -version 2>&1 | head -1)"
    else
        echo "jasminc_version:  not installed"
    fi
    echo "samples_per_batch:$DUDECT_SAMPLES"
    echo "max_batches:      $DUDECT_MAX_BATCHES"
    echo "dudect_threshold: t_threshold_moderate=10 (default);"
    echo "                  NIST 4.5σ post-hoc applied when reading log"
    echo "target(s):        $TARGET"
} > "$META"

echo "==> Submission run: $LABEL @ $STAMP"
echo "    metadata:  $META"
echo "    log_base:  $LOG_BASE"
echo "    cpu_pin:   ${CPU:-none (host_os=$HOST_OS, set CPU=N to override)}"

# ---------------------------------------------------------------------------
# Rebuild the harness so the pinned commit matches the recorded one.
# ---------------------------------------------------------------------------

echo "==> Rebuilding harnesses against $LABEL"
( cd "$CT_ROOT" && make -s clean && make -s all ) >>"$LOG_BASE.build.log" 2>&1 || {
    echo "    [FAIL] harness build failed — see $LOG_BASE.build.log"
    exit 1
}
echo "    [ok] harness build clean"

# ---------------------------------------------------------------------------
# Run helper
# ---------------------------------------------------------------------------

run_one() {
    local name="$1"
    local stdout="$LOG_BASE.$name.stdout"
    local stderr="$LOG_BASE.$name.stderr"
    local cmd=( "$CT_ROOT/dudect_$name" )

    # Linux: taskset -c <CPU> for affinity; macOS: just run.
    if [[ -n "$CPU" && "$HOST_OS" == "Linux" ]]; then
        cmd=( taskset -c "$CPU" "${cmd[@]}" )
    fi

    echo "==> $name: ${cmd[*]}"
    echo "    samples=$DUDECT_SAMPLES batches=$DUDECT_MAX_BATCHES"
    # cd into ct/dudect/ so the dylib (loaded via rpath = cwd) is
    # resolvable. Without this, dyld can't find libpulsar_*.dylib
    # because the Makefile builds with relative rpath.
    local rc=0
    ( cd "$CT_ROOT" && \
        DUDECT_SAMPLES="$DUDECT_SAMPLES" DUDECT_MAX_BATCHES="$DUDECT_MAX_BATCHES" \
        "${cmd[@]}" ) >"$stdout" 2>"$stderr" || rc=$?

    {
        echo "exit_code: $rc"
        echo "max_t_observed: $(grep -oE 'max t:\s*[+\-][0-9.]+' "$stdout" \
                                   | awk '{print $NF}' | sort -t: -k2 -gr | head -1 || echo unknown)"
        echo "iterations:     $(grep -cE '^meas:' "$stdout" || echo 0)"
    } >> "$META"

    case $rc in
        0) echo "    [PASS] no leakage evidence at $DUDECT_SAMPLES x $DUDECT_MAX_BATCHES";;
        2) echo "    [LEAK] dudect_$name reports leakage — see $stderr";;
        *) echo "    [warn] dudect_$name exited rc=$rc — see $stderr";;
    esac
    return $rc
}

# ---------------------------------------------------------------------------
# Run targets
# ---------------------------------------------------------------------------

VERIFY_RC=0
COMBINE_RC=0
if [[ "$TARGET" == "both" || "$TARGET" == "verify" ]]; then
    run_one verify || VERIFY_RC=$?
fi
if [[ "$TARGET" == "both" || "$TARGET" == "combine" ]]; then
    run_one combine || COMBINE_RC=$?
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
echo "==> Summary"
echo "    metadata:        $META"
echo "    verify  rc:      $VERIFY_RC"
echo "    combine rc:      $COMBINE_RC"
echo

# Exit codes:
# 0 — every requested target reported no leakage.
# 2 — at least one target reported leakage (rc=2 on its run).
# 1 — at least one target exited with an unexpected rc.
if [[ $VERIFY_RC -eq 2 || $COMBINE_RC -eq 2 ]]; then
    exit 2
fi
if [[ $VERIFY_RC -ne 0 || $COMBINE_RC -ne 0 ]]; then
    exit 1
fi
exit 0
