# PROOF-CLAIMS — Pulsar (assurance-vocabulary, HONEST)

> **What the Pulsar proof artifacts establish, and — critically — what
> they do NOT.** Every claim below carries one assurance-vocabulary tag
> that MATCHES the artifact's actual state. Read this before reading the
> code.
>
> Canonical companions: `AXIOM-INVENTORY.md` (bucketed axiom census),
> `BLOCKERS.md` (open findings), `docs/proof-claims.md` and
> `docs/proof-axiom-inventory.md` (deep dives). This root file is the one
> the high-assurance gate reads (`claims-vs-reality.sh`).

## Assurance vocabulary (canonical)

| Tag | Meaning |
|---|---|
| **machine-checked** | A proof assistant verifies it; the named EasyCrypt or Lean theory has ZERO `sorry` / `admit.` / `:= True` (real tactics, per the repo's own admit gate). No EasyCrypt toolchain on this host — "machine-checked" here means *structurally complete and intended to compile*; `scripts/checks/ec-compile.sh` is the CI gate, skipped locally when easycrypt is absent. |
| **sound-by-reduction** | A pen-and-paper reduction to a stated assumption exists; not mechanized. |
| **interop-tested** | Validated by running against ≥2 INDEPENDENT implementations (CIRCL + pq-crystals), not the signer's own library. |
| **asserted-axiom** | Taken as an axiom in EC; bucketed in AXIOM-INVENTORY.md (A/B). Not proved here. |
| **fail-closed-pending-review** | Implemented but gated to REFUSE until external review; not claimed correct. |
| **open-research** | Not done; multi-month roadmap. |

## §1 The headline claim — with its true assurance tag

> **Class N1 byte-equality (extracted corollary).** Every signature byte
> string produced by the Pulsar Combine procedure on honest-quorum inputs
> `(group_pk, m, ctx, quorum, shares, rho_rnd)` satisfying the
> well-formedness invariants is **bit-identical** to a single-party
> FIPS 204 ML-DSA-65 signature on the Lagrange-reconstructed group secret
> under the same `(m, ctx, rho_rnd)`.
> — Lemma `pulsar_n1_byte_equality_extracted`
> (`proofs/easycrypt/Pulsar_N1_Extracted.ec`).

**Assurance: machine-checked (EC structure, 0 admits) MODULO an
asserted-axiom trust cone — and that cone is reconstruct-then-sign.**

Read this carefully:

- The EC lemma is structurally complete (no `admit.` / `sorry`). But it is
  proved **relative to** the axioms bucketed C in `AXIOM-INVENTORY.md`. The
  central ones (`combine_body_axiom`, `S_functional_spec`, and the per-stage
  `combine_body_*_spec` / `sign_body_*_spec`) assert that the extracted
  threshold/libjade code equals the centralised signer **applied to the
  Lagrange-reconstructed master secret**. That is a **reconstruct-then-sign
  model**.
- Reconstruct-then-sign is exactly the abstraction that `BLOCKERS.md`
  § PULSAR-V13-HINT-LEAK says the **production leaderless path must never
  instantiate** (reconstructing `c·s2`/`c·t0`/the master secret leaks the
  long-term key). So the EC byte-equality is a statement about an
  *idealised centralised-equivalent signer*, NOT a proof that the no-leak
  (BCC/CEF) production path is correct or leak-free.
- The production no-leak property is **interop-tested**: the BCC single-key
  signature verifies **byte-for-byte under CIRCL + pq-crystals**
  (ML-DSA-65/87), per the BLOCKERS V13-HINT-LEAK resolution criteria. It is
  **NOT EC-proven**. The novel ZK boundary-clearance / partial-z parts are
  **fail-closed-pending-review**.

## §2 Claim-by-claim assurance table

| Claim | Assurance | Evidence |
|---|---|---|
| EC threshold↔centralised refinement (`pulsar_n1_byte_equality`) | machine-checked modulo C-cone (asserted-axiom) | lemma in the N1 theory; 0 real `admit.` tactics (`scripts/checks/ec-admits.sh`); cone in AXIOM-INVENTORY.md §C |
| Class N4 reshare preserves `(rho,t1)` group key | machine-checked modulo A-cone | lemma in the N4 theory; 0 real `admit.` tactics; rests on `shamir_correct`/`reconstruct_linear`/`add_share_zeroR` (Lean-bridged) |
| The byte-walk = centralised signer on reconstructed secret (C-cone) | asserted-axiom (OPEN) | `combine_body_axiom`, `S_functional_spec`, `*_body_*_spec` — reconstruct-then-sign; BLOCKERS.md |
| Final BCC signature interchangeable with FIPS 204 | interop-tested | 19/19 N1 subtests vs CIRCL; BCC no-leak sig byte-equal under CIRCL + pq-crystals (`test/interoperability/`, BLOCKERS V13) |
| Production no-leak (no `c·s2`/`c·t0`/master reconstruction) | interop-tested (single-key) + fail-closed-pending-review (threshold ZK) | BLOCKERS.md V13-HINT-LEAK / V13-W-LEAK / V13-PARTIAL-Z-PROOF |
| Constant-time, threshold layer | sound-by-reduction (jasmin-CT) + fail-closed on dudect-submission-grade | jasmin-ct 3/3; dudect 10⁹-sample run open-research |
| 5 Lagrange/algebra identities | machine-checked (Lean 4 + Mathlib), asserted-axiom (EC side) | `proofs/lean-easycrypt-bridge.md`; `scripts/check-lean-bridge.sh` |
| FIPS 204 per-type codec round-trips (B-cone) | asserted-axiom | AXIOM-INVENTORY.md §B; closing = Dilithium codec mechanization (open-research) |
| ML-DSA post-quantum hardness (M-LWE/M-SIS) | open-research (inherited) | NIST FIPS 204 analysis; NOT a Pulsar claim |

## §3 What is NOT proved (the load-bearing honesty disclosure)

1. **The production threshold path is NOT EC-proven.** The EC proof models
   reconstruct-then-sign; the production path (which must never reconstruct
   the secret) is covered by `BLOCKERS.md` open items + interop tests +
   fail-closed gates, not by the EC byte-equality.
2. **No-leak is interop-tested, not EC-proven.** See §1.
3. **ML-DSA hardness, side-channels beyond jasmin-CT, adaptive-corruption
   unforgeability, robust completion, async identifiable-abort** — not
   proved here (see `docs/proof-claims.md` §3 for the full list).

## §4 The honest one-paragraph version

> Pulsar's EasyCrypt artifact is a structurally-complete (0-admit)
> refinement showing the threshold combine is bit-identical to single-party
> FIPS 204 ML-DSA-65 sign on the Lagrange-reconstructed group secret —
> **relative to a trust cone of asserted axioms that model
> reconstruct-then-sign** (bucketed in AXIOM-INVENTORY.md). That model is
> deliberately NOT the production leaderless path, which must never
> reconstruct the secret (BLOCKERS.md V13). The production no-leak signature
> is **interop-tested** byte-equal under CIRCL + pq-crystals, not EC-proven;
> the novel threshold-ZK parts are **fail-closed-pending-review**. The proof
> says nothing about ML-DSA's post-quantum hardness, which inheres in NIST's
> FIPS 204 analysis.

---
- Name: `PROOF-CLAIMS.md` (root; gate-read) · supersedes the scope summary
  in `docs/proof-claims.md`, which remains the deep-dive narrative.
