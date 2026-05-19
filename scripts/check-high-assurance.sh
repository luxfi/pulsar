#!/usr/bin/env bash
# Pulsar high-assurance gate — orchestrator (per-push, REAL checks).
#
# Each check below lives in its own script under scripts/checks/ (or
# scripts/, for the cross-prover Lean↔EC bridge guard). This file
# is intentionally THIN: it sequences the checks and propagates
# their exit codes. Each per-check script is independently runnable.
#
# The checks, in order:
#
#   1. jasmin.sh                  — jasminc type-check + jasmin-ct
#                                   on the threshold layer (blocking).
#                                   libjade sign is advisory under #2.
#   2. ec-admits.sh               — EasyCrypt admit-budget (0/0 today).
#   3. ec-regressions.sh          — Retired-axiom-shape regression
#                                   guards.
#   4. ec-refinement-scaffold.sh  — declare-axiom hygiene in the
#                                   Refinement files.
#   5. check-lean-bridge.sh       — Lean↔EC Shamir bridge guard.
#   6. extraction.sh              — Jasmin → EC extraction sanity.
#   7. ec-compile.sh              — All EC files compile clean.
#
# NOT in this gate (intentionally): dudect at smoke budget. A
# 40k-sample dudect run can't certify constant time; the budget
# isn't statistically meaningful. The REAL dudect gate is the
# submission-grade run from ct/dudect/run-submission.sh (10^9
# samples per target on a pinned CPU). It belongs in the nightly
# gate (scripts/nightly.sh), not per-push.
#
# Any per-check failure (exit 2) fails the orchestrator with the
# same code. Per-check skips (exit 0 with a [skip] message) do not
# fail the gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CHECKS=(
    "scripts/checks/jasmin.sh"
    "scripts/checks/ec-admits.sh"
    "scripts/checks/ec-regressions.sh"
    "scripts/checks/ec-refinement-scaffold.sh"
    "scripts/check-lean-bridge.sh"
    "scripts/checks/extraction.sh"
    "scripts/checks/ec-compile.sh"
)

echo "==> Pulsar high-assurance track"
echo "    jasmin/   $REPO_ROOT/jasmin"
echo "    easycrypt $REPO_ROOT/proofs/easycrypt"
echo "    dudect    $REPO_ROOT/ct/dudect"
echo

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
    echo "==> done — high-assurance gate green"
fi
exit $OVERALL
