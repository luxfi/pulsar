#!/usr/bin/env bash
# scripts/checks/ec-compile.sh — EasyCrypt compile gate for all
# tracked EC files.
#
# Runs `easycrypt compile` on each file in EC_FILES and fails the
# gate if any reports [critical] (which `easycrypt compile` emits
# to stderr even when the exit code is 0). Skips silently if
# easycrypt is not installed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC_ROOT="$REPO_ROOT/proofs/easycrypt"

EC_FILES=(
    "$EC_ROOT/Pulsar_N1.ec"
    "$EC_ROOT/Pulsar_N4.ec"
    "$EC_ROOT/lemmas/Pulsar_CT.ec"
    "$EC_ROOT/lemmas/MLDSA65_Functional.ec"
    "$EC_ROOT/Pulsar_N1_Memory.ec"
    "$EC_ROOT/Pulsar_N1_Signature_Codec.ec"
    "$EC_ROOT/Pulsar_N1_Combine_Layout.ec"
    "$EC_ROOT/Pulsar_N1_Sign_Layout.ec"
    "$EC_ROOT/Pulsar_N1_Combine_Refinement.ec"
    "$EC_ROOT/Pulsar_N1_Sign_Refinement.ec"
    "$EC_ROOT/Pulsar_N1_Combine_Wrapper.ec"
    "$EC_ROOT/Pulsar_N1_Sign_Wrapper.ec"
    "$EC_ROOT/Pulsar_N1_Extracted.ec"
)

if ! command -v easycrypt >/dev/null 2>&1; then
    echo "==> EasyCrypt compile gate"
    echo "    [skip] easycrypt not on PATH"
    echo "           install (source build): https://github.com/EasyCrypt/easycrypt"
    exit 0
fi

EC_HASH=$(easycrypt config 2>&1 | grep "git-hash" | head -1)
echo "==> easycrypt found ($EC_HASH)"

# Use the EXIT CODE of easycrypt, not the grep of its stderr.
# Earlier versions of this script grepped for `[critical]` in the
# combined stdout/stderr, but easycrypt's stderr buffering races
# with the grep pipeline (the [critical] line is sometimes flushed
# AFTER easycrypt exits, after grep has already returned NO_MATCH),
# producing false [ok] reports. Exit codes are deterministic:
# easycrypt exits 0 on success, non-zero on any error.

EC_FAIL=0
EC_FAIL_LIST=()
for f in "${EC_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "    [warn] missing: $f"
        continue
    fi
    # Capture stderr so we can show it on failure without polluting
    # the [ok] case. Compile in a subshell so any non-zero exit
    # doesn't trip the script's set -e before we branch.
    log="/tmp/ec-compile-$$.$(basename "$f").log"
    rc=0
    easycrypt compile -I "$EC_ROOT" -I "$EC_ROOT/lemmas" "$f" \
        > "$log" 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "    [ok]   $f compiles"
        rm -f "$log"
    else
        echo "    [FAIL] $f (rc=$rc) — last lines of easycrypt output:"
        # Strip the carriage-return-laden progress bar so the error
        # message is readable. The [critical] tag usually follows
        # the last progress update on the same physical line.
        tr '\r' '\n' < "$log" | grep -E "\[critical\]|^[[:space:]]*unknown|error" | head -5 | sed 's/^/      /'
        EC_FAIL=1
        EC_FAIL_LIST+=("$f")
    fi
done

if [[ $EC_FAIL -ne 0 ]]; then
    echo
    echo "    EasyCrypt compile gate FAILED on ${#EC_FAIL_LIST[@]} file(s):"
    for f in "${EC_FAIL_LIST[@]}"; do
        echo "      $f"
    done
    exit 2
fi
exit 0
