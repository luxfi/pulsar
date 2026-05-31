# PROOF-CLAIMS — Pulsar Class N1 byte-equality

> **What this proof actually establishes — and what it does NOT.**
> Companion document to `proof-axiom-inventory.md` (trust footprint),
> `fips-204-traceability.md` (op→FIPS § map), and
> `tcb.md` (TCB).
>
> Read this before reading the EasyCrypt code. The framing matters
> as much as the proofs.

## §1 The narrow claim

The strongest precise statement supported by the v10 proof artifact:

> **Class N1 byte-equality (extracted corollary).** Under the
> trusted-computing base in `tcb.md` and the
> residual axioms enumerated in `proof-axiom-inventory.md`, every
> signature byte string produced by the Pulsar Combine procedure
> on inputs `(group_pk, m, ctx, quorum, shares, rho_rnd)`
> satisfying the protocol's well-formedness invariants (uniq
> quorum, size match, polynomial-degree bound, honest sharing,
> protocol consistency, accepted-path) is **bit-identical** to a
> signature produced by single-party FIPS 204 ML-DSA-65 Sign on
> the Lagrange-reconstructed group secret under the same
> `(m, ctx, rho_rnd)`.

Formal statement:
```ec
lemma pulsar_n1_byte_equality_extracted :
  equiv [ Pulsar_N1.ThresholdRun(CombineExtractedWrapper).run
        ~ Pulsar_N1.SinglePartyRun(SignExtractedWrapper).run :
          ={group_pk, shares, quorum, m, ctx, rho_rnd}
        /\ uniq quorum{1}
        /\ size shares{1} = size quorum{1}
        /\ group_pk{1} = Pulsar_N1.derive_pk
                          (Pulsar_N1.reconstruct quorum{1} shares{1})
        /\ Pulsar_N1.accept_signing_attempt
             (Pulsar_N1.reconstruct quorum{1} shares{1})
             m{1} ctx{1} rho_rnd{1}
        /\ Pulsar_N1.poly_degree
             (Pulsar_N1.reconstruct quorum{1} shares{1}) < size quorum{1}
        /\ shares{1} = List.map
             (Pulsar_N1.poly_eval
                (Pulsar_N1.reconstruct quorum{1} shares{1}))
             quorum{1}
        ==> ={res} ].
```

File: `proofs/easycrypt/Pulsar_N1_Extracted.ec`.

## §2 What is proved

| Aspect | Status |
|---|---|
| Implementation refinement | ✅ EasyCrypt proof, 13 files compile, 0 admits |
| Byte-equality with FIPS 204 single-party | ✅ Per the lemma above |
| Class N1 (output-interchangeability) | ✅ Per the lemma above |
| Class N4 (reshare pk-preservation) | ✅ Separate theorem in `Pulsar_N4.ec` |
| Constant-time on threshold layer | ✅ jasmin-ct 3/3 blocking |
| Lean-bridged algebraic identities | ✅ 5 axioms with mechanized Lean proofs (Mathlib polynomial-Lagrange) |
| Bit-level FIPS 204 codec | ⚠ Abstracted via per-type roundtrip axioms (see `proof-axiom-inventory.md` §7) |
| κ-rejection loop acceptance probability | ⚠ Operational bound `mldsa_accept_lower_bound`, not probabilistic Hoare-logic |
| ML-DSA hardness (M-LWE / M-SIS) | ❌ NOT proved — assumed from NIST FIPS 204 analysis |
| Constant-time on libjade sign | ⚠ Advisory under jasmin-ct issue #2 |
| ACVP/CAVP algorithm validation | ❌ External (lab work) |
| FIPS 140-3 module validation | ❌ Out of scope |

## §3 What is NOT proved (and why)

### §3.1 NOT proved: lattice-hardness of ML-DSA

This proof artifact says nothing about the post-quantum hardness of
ML-DSA itself. ML-DSA's security rests on Module-LWE and Module-SIS
hardness assumptions; those are NIST's responsibility (FIPS 204
incorporates the analysis), not ours.

**The defensible PQ-safety claim**:
> Pulsar implements a NIST-standardized post-quantum signature
> algorithm (FIPS 204 ML-DSA-65) and refines that algorithm's
> functional specification with the trust base enumerated in
> proof-axiom-inventory.md.

**NOT defensible**:
> Pulsar is proved post-quantum secure.

### §3.2 NOT proved: implementation-side covert-channel safety

The EC refinement proof says nothing about timing, memory access,
randomness, or power side-channels. Those are addressed separately:

| Side-channel risk | Evidence |
|---|---|
| Timing leakage (threshold layer) | jasmin-ct 3/3 blocking — `round1.jazz`, `round2.jazz`, `combine.jazz` CT-clean |
| Timing leakage (libjade sign) | Advisory (jasmin-ct issue #2 — documented in `ct/jasmin-ct-libjade.md`) |
| Statistical timing (dudect 10⁹ samples) | Nightly gate `scripts/nightly.sh`; harness arm64 + x86_64 clean via `ct/dudect/Makefile`. Submission-grade 10⁹-sample run is the gate that promotes the harness from "wired" to "passed" — see `cryptographer-sign-off.md` §Gates GATE-3 for the dudect-pending disclosure. Per-push smoke runs are informational only. |
| Randomness misuse | Reference impl uses `crypto/rand`; production impl review TBD |
| Zeroization | `ref/go/pkg/pulsar/zeroize.go` (CR-8 closure since v1.0.6): `zeroizeBytes` / `zeroizeSeed` / `zeroizeU16` / `zeroizePrivateKey` best-effort wipes on every Combine/Sign/DKG exit path |
| Fault attacks | Not addressed |

### §3.3 NOT proved: protocol-level adversarial robustness

Class N1 byte-equality is **honest-quorum correctness**. It says:
"when all parties follow the protocol, the output verifies." It
does NOT prove:

- **Unforgeability** under adaptive corruption — separate proof
  obligation, tracked in `Pulsar_M/Unforgeability.lean`.
- **Identifiable abort** under network partition — only synchronous
  network assumptions hold; async abort is out of scope.
- **Robust completion** under f < t/2 Byzantine parties.
- **DKG soundness** under adversarial dealer.

See `pulsar-m/unforgeability.tex` for the unforgeability reduction
(stated, mechanization in flight).

### §3.4 NOT proved: bit-level FIPS 204 codec correctness

The proof abstracts the FIPS 204 §3.5 codec via per-type
encode/decode roundtrip axioms (`encode_decode_signature`,
`encode_decode_sk`, `encode_decode_msg`, etc.). Closing these as
lemmas requires a Barbosa-Barthe-Dupressoir-scale Dilithium
mechanization (CRYPTO 2023, ~6 person-months). Inventoried in
`proof-axiom-inventory.md` §7.

### §3.5 NOT proved: external Lean theorems

5 axioms in the EC dependency cone are Lean-bridged (mechanized in
Lean 4 + Mathlib). The EC side TRUSTS these. Closing requires
either:
(a) Porting Mathlib's polynomial-Lagrange theory to EasyCrypt
    (multi-week), OR
(b) Building a checked Lean ↔ EC translation tool (multi-month —
    no published tool exists).

See `proofs/lean-easycrypt-bridge.md` for the correspondence.

## §4 Refinement chain (what's connected to what)

```
EasyCrypt threshold model
  (Pulsar_N1.ec, Pulsar_N1_Combine_Refinement.ec, Pulsar_N1_Sign_Refinement.ec)
       refines
EasyCrypt centralised functional model
  (Pulsar_N1.mldsa_sign_op = pack_n1_signature ∘ run_signing_components ∘ unpack_sk ∘ compute_mu)
       refines (via per-type codec axioms)
FIPS 204 ML-DSA-65 functional specification
  (MLDSA65_Functional.ec — abstract op surface mirroring FIPS 204 §3 + §6)
       conforms to
FIPS 204 standard text
  (NIST FIPS 204, August 2024)
```

Each "refines" relation is mechanized; each "conforms to" relation
is by inspection.

```
Jasmin threshold layer (round1.jazz, round2.jazz, combine.jazz)
  extracts to EasyCrypt
EasyCrypt extracted procedures
  (proofs/easycrypt/extraction/build/{combine,sign}.ec)
       (byte-walk obligations on output values)
EasyCrypt centralised functional model (above)
```

The byte-walk obligations are the remaining primitive axioms in
`proof-axiom-inventory.md` §1–§4.

## §5 What an auditor verifying this proof should do

1. **Read** the SUBMISSION.md cover sheet for context.
2. **Read** `proof-axiom-inventory.md` for the residual trust base.
3. **Read** this document (`proof-claims.md`) for what's proved vs not.
4. **Read** `tcb.md` for the EC/Jasmin/OCaml TCB.
5. **Run** `scripts/check-high-assurance.sh` — expect 0/0 admits +
   5/5 Lean bridges + 13/13 EC compile.
6. **Cross-check** the residual axioms in `proof-axiom-inventory.md`
   against the raw grep:
   ```bash
   grep -rE "^axiom\s+\w" proofs/easycrypt/ | wc -l
   ```
7. **For each Lean-bridged axiom**, verify the Lean theorem at the
   cited location.
8. **Run** the test vectors in `vectors/` against the reference
   implementation in `ref/go/`.

## §6 The honest one-paragraph version

> Pulsar's EasyCrypt proof artifact establishes that the
> Jasmin-extracted threshold combine procedure produces a byte
> string bit-identical to a single-party FIPS 204 ML-DSA-65
> signature on the Lagrange-reconstructed group secret, modulo
> the trust footprint enumerated in proof-axiom-inventory.md (residual
> byte-walk obligations on extracted Jasmin code, Lean-bridged
> Lagrange algebraic identities, FIPS 204 per-type codec roundtrip
> axioms, and the EasyCrypt/Jasmin/OCaml trusted-computing base).
> The proof is an implementation-correctness result; it does NOT
> prove the post-quantum hardness of ML-DSA, which inheres in
> NIST's FIPS 204 analysis of Module-LWE and Module-SIS.

---

**Document metadata**

- Name: `proof-claims.md`
- Version: v1.0 (post v10)
- Date: 2026-05-18
