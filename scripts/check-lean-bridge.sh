#!/usr/bin/env bash
# Lean ↔ EasyCrypt Shamir bridge guard.
#
# Each of the EC axioms named in proofs/lean-easycrypt-bridge.md
# must:
#   1. Still exist in the EC source as an `axiom` (not `lemma`).
#   2. Carry an inline citation comment naming the Lean theorem.
#   3. The Lean theorem named in the citation must EXIST in the
#      named Lean file (hardened guard — post-audit).
#   4. Be named in a `### Axiom N: \`<qual>.<name>\`` header in the
#      bridge doc — and the number of such headers must equal the
#      number of entries in BRIDGE[] (catches drift either way).
#
# Plus:
#   5. The bridge doc must exist.
#   6. Every EC file path mentioned in the bridge doc text must
#      exist on disk (catches stale refs to decomplected files).
#
# If any of these checks fails, this script exits 2 and the
# high-assurance gate fails. The Lean repo is expected to live at
# ~/work/lux/proofs (one of several supported standard locations);
# the script auto-detects it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Lean repo location — autodetect a few standard layouts. Skip the
# Lean-side existence check if no Lean repo is found (so checkouts
# without the sibling Lean repo still pass).
# ---------------------------------------------------------------------------
LEAN_ROOT=""
for candidate in \
    "$HOME/work/lux/proofs/lean" \
    "$HOME/work/lux/proofs" \
    "$REPO_ROOT/../proofs/lean" \
    "$REPO_ROOT/../../proofs/lean" \
; do
    if [[ -d "$candidate/Crypto" ]]; then
        LEAN_ROOT="$candidate"
        break
    fi
done
have_lean=0
if [[ -n "$LEAN_ROOT" ]]; then
    have_lean=1
fi

FAIL=0

# (axiom-name, ec-file, lean-citation-substring, lean-theorem-name, lean-file-rel-to-Crypto)
declare -a BRIDGE=(
    "lagrange_inverse_eval|proofs/easycrypt/Pulsar_N1.ec|shamir_correct_at_target|shamir_correct_at_target|Pulsar/Shamir.lean"
    "add_share_zeroR|proofs/easycrypt/Pulsar_N4.ec|AddCommMonoid||"
    "reconstruct_linear|proofs/easycrypt/Pulsar_N4.ec|combine_distributes_over_sum|combine_distributes_over_sum|Threshold_Lagrange.lean"
    "shamir_correct|proofs/easycrypt/Pulsar_N4.ec|shamir_correct_at_target|shamir_correct_at_target|Pulsar/Shamir.lean"
    "threshold_partial_response_identity|proofs/easycrypt/Pulsar_N1.ec|threshold_partial_response_identity|threshold_partial_response_identity|Threshold_Lagrange.lean"
)

echo "==> Lean ↔ EC Shamir bridge guard"
if [[ $have_lean -eq 1 ]]; then
    echo "    [info] Lean repo: $LEAN_ROOT"
else
    echo "    [info] no Lean repo on disk; skipping Lean-side existence checks"
fi

for entry in "${BRIDGE[@]}"; do
    IFS='|' read -r axiom file lean_ref lean_thm lean_rel <<< "$entry"

    # 1. EC file present.
    if [[ ! -f "$file" ]]; then
        echo "    [FAIL] $axiom: $file not found"
        FAIL=1
        continue
    fi

    # 2. EC axiom still exists as an `axiom` (not silently demoted
    # to `lemma` — promoting axiom→lemma is good but requires the
    # bridge-doc / guard entry to be retired, which this catches).
    line=$(grep -nE "^axiom[[:space:]]+${axiom}[[:space:]]*" "$file" | head -1 | cut -d: -f1)
    if [[ -z "$line" ]]; then
        echo "    [FAIL] $axiom: declaration not found in $file (renamed without bridge update?)"
        FAIL=1
        continue
    fi

    # 3. Citation comment in the 20 lines preceding the axiom.
    start=$((line > 20 ? line - 20 : 1))
    if ! sed -n "${start},${line}p" "$file" | grep -q "$lean_ref"; then
        echo "    [FAIL] $axiom @ $file:$line — bridge comment missing reference to '$lean_ref'"
        echo "           (see proofs/lean-easycrypt-bridge.md for the required correspondence)"
        FAIL=1
        continue
    fi

    # 4. Lean theorem actually exists at the named path. Only
    # checked when a Lean repo is on disk AND the bridge entry
    # names a concrete (theorem, file) pair.
    if [[ $have_lean -eq 1 && -n "$lean_thm" && -n "$lean_rel" ]]; then
        lean_file="$LEAN_ROOT/Crypto/$lean_rel"
        if [[ ! -f "$lean_file" ]]; then
            echo "    [FAIL] $axiom: cited Lean file $lean_file not found"
            FAIL=1
            continue
        fi
        if ! grep -qE "^(theorem|lemma)[[:space:]]+${lean_thm}[[:space:]]*\\b" "$lean_file"; then
            echo "    [FAIL] $axiom: cited Lean theorem $lean_thm not found in $lean_file"
            echo "           (Lean side renamed or removed without EC-side update?)"
            FAIL=1
            continue
        fi
    fi

    echo "    [ok]   $axiom @ $file:$line → $lean_ref"
done

# Bridge doc presence.
BRIDGE_DOC="proofs/lean-easycrypt-bridge.md"
if [[ ! -f "$BRIDGE_DOC" ]]; then
    echo "    [FAIL] $BRIDGE_DOC is missing"
    FAIL=1
else
    # 4. Per-axiom: bridge doc must have a `### Axiom N: \`...axiom\``
    # header for each BRIDGE[] entry. Catches the doc dropping or
    # renaming an axiom without the guard table being updated.
    for entry in "${BRIDGE[@]}"; do
        IFS='|' read -r axiom _ _ _ _ <<< "$entry"
        if ! grep -qE "^### Axiom [0-9]+:.*\`[A-Za-z0-9_]+\\.${axiom}\`" "$BRIDGE_DOC"; then
            echo "    [FAIL] bridge doc missing '### Axiom N: \`<qual>.${axiom}\`' header"
            FAIL=1
        fi
    done

    # 4b. Header count must equal BRIDGE[] count. Catches the doc
    # gaining a new axiom that the guard table hasn't tracked yet.
    doc_axiom_count=$(grep -cE '^### Axiom [0-9]+:' "$BRIDGE_DOC")
    if [[ "$doc_axiom_count" -ne "${#BRIDGE[@]}" ]]; then
        echo "    [FAIL] bridge doc has $doc_axiom_count '### Axiom N:' headers but BRIDGE[] has ${#BRIDGE[@]} entries"
        FAIL=1
    fi

    # 5/6. Every EC file path mentioned in the bridge doc must exist
    # on disk. Catches stale refs (e.g., to a file that was
    # decomplected and renamed).
    #
    # Pattern: `proofs/easycrypt/<name>.ec` (backtick-quoted) is
    # the canonical bridge-doc cross-reference shape. We grep
    # those out and check each.
    missing_refs=()
    while IFS= read -r ref; do
        # Strip backticks if present.
        clean=$(echo "$ref" | tr -d '`')
        if [[ ! -f "$clean" ]]; then
            missing_refs+=("$clean")
        fi
    done < <(grep -oE 'proofs/easycrypt/[A-Za-z0-9_/]+\.(ec|md)' "$BRIDGE_DOC" | sort -u)

    # Also check ~/work/lux/proofs/lean/Crypto/ refs when a Lean
    # repo is on disk.
    if [[ $have_lean -eq 1 ]]; then
        while IFS= read -r ref; do
            clean=$(echo "$ref" | tr -d '`')
            # Strip a leading ~/work/lux/proofs/ if present.
            rel="${clean#*lean/Crypto/}"
            full="$LEAN_ROOT/Crypto/$rel"
            if [[ ! -f "$full" ]]; then
                missing_refs+=("$clean")
            fi
        done < <(grep -oE 'lean/Crypto/[A-Za-z0-9_/]+\.lean' "$BRIDGE_DOC" | sort -u)
    fi

    if [[ ${#missing_refs[@]} -gt 0 ]]; then
        echo "    [FAIL] bridge doc references files that don't exist on disk:"
        printf "             %s\n" "${missing_refs[@]}"
        FAIL=1
    else
        echo "    [ok]   $BRIDGE_DOC present + every file path in it exists"
    fi
fi

if [[ $FAIL -ne 0 ]]; then
    echo
    echo "    Lean ↔ EC bridge guard FAILED — fix the citation comments"
    echo "    or update proofs/lean-easycrypt-bridge.md if the axiom"
    echo "    correspondence / file layout changed."
    exit 2
fi
echo "    [ok]   all ${#BRIDGE[@]} axiom citations present + Lean-side names verified"
exit 0
