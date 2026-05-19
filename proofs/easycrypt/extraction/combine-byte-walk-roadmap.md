# `combine_body_compute_sig_spec` byte-walk roadmap

## Status

`combine_body_compute_sig_spec` is the **last remaining
implementation-refinement axiom** on the combine side (the
separation axiom became a lemma in `c4148a0`). It states:

```ec
axiom combine_body_compute_sig_spec :
  forall mem_pre ptrs full,
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    refine_sig_to_n1 (combine_body_compute_sig mem_pre ptrs)
    = combine_abs_op full.
```

where `combine_abs_op full` unfolds (by definition) to:

```ec
Pulsar_N1.mldsa_sign_op
  (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares)
  full.`full_m full.`full_ctx full.`full_rho_rnd
```

i.e., the centralised FIPS 204 ML-DSA-65 signature on the
Lagrange-reconstructed group secret. Tracked under #4.

This document maps each FIPS 204 §6.2 algorithmic stage to:
1. the corresponding extracted-procedure line(s) in
   `proofs/easycrypt/extraction/build/combine.ec`,
2. the EC functional op in `lemmas/MLDSA65_Functional.ec` it must
   match, and
3. an intermediate sub-claim that lets a future proof attempt
   start at any single stage.

The intent: close the axiom **bottom-up**, one sub-claim at a
time. The first sub-claim (signature packing) is mechanical and
likely closable in a few days of work; the polynomial-aggregation
sub-claims are progressively harder.

## Extracted procedure shape

`M.pulsar_combine` lives in `combine.ec:3245-3617`. Its signature:

```ec
proc pulsar_combine (c_tilde_ptr : W64.t, t0_ptr : W64.t,
                     round2_msgs_ptr : W64.t, threshold : W32.t,
                     sig_out_ptr : W64.t) : W64.t
```

Returns a status word (`0` for success, non-zero `fail_bits` for
rejection-condition failures). On success, writes 3293 bytes of
packed signature at `sig_out_ptr`.

## Stage map

| Stage | Extracted lines | Functional op | Sub-claim |
|---|---|---|---|
| 1. Read c_tilde from input pointer | `combine.ec:3413-3416` | (identity — c_tilde is wire input) | **(S1)** read_c_tilde(mem, c_tilde_ptr) = full.full_wire.c_tilde_abs |
| 2. Read t0 from t0 pointer | `combine.ec:3417-3426` | (identity — t0 is wire input from group pk) | **(S2)** read_t0_vec(mem, t0_ptr) = full.full_wire.t0_abs |
| 3. Read & aggregate Round-2 messages | `combine.ec:3430-3505` | `vec_l_add`, `vec_k_add` | **(S3)** aggregated z, ct0, cs2, w_low equal Lagrange-sum over Round-2 messages = Lagrange-sum over per-party (y_i + c·s1_i), (c·t0_i), (c·s2_i), (w_low_i) |
| 4. SampleInBall on c_tilde | `combine.ec:3506` (call to `sampleInBall`) | `sample_in_ball` | **(S4)** pc_rsp (NTT-domain c poly) = NTT(sample_in_ball(c_tilde)) |
| 5. Compute w_prime = w_agg + ct0_agg | `combine.ec:3530-3545` | `vec_k_add` + decompose math | **(S5)** w_prime (mod q) equals the FIPS 204 §6.2 w' = A·z - c·t1·2^d |
| 6. Decompose w_prime | `combine.ec:3560` (call to `decompose_vec`) | `decompose_vec_k` | **(S6)** (w_low, w_high) = decompose_vec_k(GAMMA2, w_prime) |
| 7. MakeHint(v0, v1) | `combine.ec:3550` (call to `polyveck_make_hint`) | `vec_k_make_hint` | **(S7)** (hint_weight, hint_0) = vec_k_make_hint(GAMMA2, v0_rsp, v1_rsp) |
| 8. Rejection checks R1-R4 | `combine.ec:3562-3594` | norm bounds in MLDSA65_Functional | **(S8)** norm_z, norm_w_low, norm_ct0, hint_count all match FIPS 204 §6.2 conditions; r{1..4}_fail = 0 ↔ all conditions met |
| 9. Pack signature | `combine.ec:3604` (call to `pack_signature`) | `pack_signature` | **(S9)** sig_packed = pack_signature(c_tilde, z_agg, hint_0) on success |
| 10. Write sig_packed at sig_out_ptr | `combine.ec:3606-3611` | `write_signature_at` (already a definition in layout) | **(S10)** Combine_Layout.read_signature_at (memory after the write loop) sig_out_ptr = decode_signature(sig_packed). |

## How the sub-claims compose

```
S1 ∧ S2 ∧ S3 ∧ S4 ∧ S5 ∧ S6 ∧ S7 ∧ S8 ∧ S9 ∧ S10
       ⇒ combine_body_compute_sig_spec
```

Specifically:
* S1, S2 give the byte-level inputs match the abstract wire args.
* S3 gives the aggregated polynomial values match the Lagrange-
  reconstructed FIPS 204 z, w, etc.
* S4-S7 give each FIPS 204 sub-computation matches its functional
  spec.
* S8 gives the rejection branch matches FIPS 204 §6.2 R1-R4.
* S9 gives the signature byte-pack matches FIPS 204 §3.5.5.
* S10 gives the memory write places those bytes at sig_out_ptr.

The "reconstruct under Lagrange equals FIPS 204 single-party
sign" identity (the load-bearing algebraic step inside S3) is
already proved on the Lean side as
`Crypto.Threshold.Lagrange.threshold_partial_response_identity`
(`lean/Crypto/Threshold_Lagrange.lean:121`) and bridged into EC
via `Pulsar_N4.reconstruct_linear` + `Pulsar_N4.shamir_correct`
(see `lean-easycrypt-bridge.md`).

## Suggested attack order

1. **S10 first** (signature memory write). This is the easiest:
   the extracted code is a single-byte storeW8 loop bounded by
   the signature length constant. The proof is induction on the
   loop counter showing every byte of `sig_packed` ends up at
   `sig_out_ptr + i`. The supporting layout lemmas
   (`write_signature_at`, `store_bytes_load_bytes`) already
   exist in `Pulsar_N1_Combine_Layout.ec`. Estimated: 1-2 days.

2. **S9 second** (pack_signature). The extracted `pack_signature`
   procedure (`combine.ec:2243`) lays out c_tilde, z, h
   contiguously. The functional spec
   `MLDSA65_Functional.pack_signature` is the matching abstract
   op. The proof is structural induction on the three pack stages.
   Estimated: 3-5 days.

3. **S1, S2** (input echoes). Mechanical — direct corollary of
   the `Pulsar_N1_Combine_Layout` layout lemmas. Estimated:
   1 day combined.

4. **S4, S6, S7** (SampleInBall, Decompose, MakeHint). Each is a
   small extracted procedure with a clean functional spec. The
   hard part is connecting BArray byte-vector views to R_q
   polynomial views — needs a "BArray ↔ R_q decode" relational
   lemma per type. Estimated: 1-2 weeks combined.

5. **S8** (rejection checks). Each check is a polyvec norm
   comparison; the functional spec is a `≤` on `inf_norm_vec_*`.
   Translating the byte-level comparison to the functional
   inequality requires the BArray ↔ R_q decode bridge from step
   4. Estimated: 3-5 days.

6. **S5** (w_prime computation). This is the hardest stage. The
   extracted code is a sequence of `vec_k_add` / `vec_k_sub` /
   matrix-vector products via NTT; the proof needs the NTT-domain
   ↔ standard-domain equivalence, which Mathlib does not have
   off-the-shelf. Estimated: 2-3 weeks.

7. **S3** (Lagrange aggregation across Round-2 messages). The
   trickiest part — it's the protocol-level identity that
   threshold Round-2 messages, when Lagrange-combined, equal the
   centralized FIPS 204 z. The bridge to Lean's
   `threshold_partial_response_identity` is the right path; the
   EC-side proof composes S3 with `reconstruct_linear` +
   `shamir_correct`. Estimated: 1 week (assuming the bridge
   theorem is already pinned).

**Total honest estimate**: 6-9 weeks of focused EC work.

## What this roadmap does NOT do

It does not produce any actual closure — `combine_body_compute_sig_spec`
remains an axiom in this commit. The value is:

* Every sub-step is named, located, and individually attackable.
* A future closure attempt starts at the smallest tractable
  piece (S10) and works upward.
* The integration story between the byte-walk and the Lean-
  bridged algebraic identities is explicit.

## Cross-references

* The wider trust accounting: `proofs/easycrypt/Pulsar_N1_Extracted.ec`
  (composition theorem) and the per-file `ACCOUNTING` blocks at the
  end of each refinement / wrapper / layout file. See
  `proofs/easycrypt/README.md` for the per-file dashboard.
* Algebraic bridge: `proofs/lean-easycrypt-bridge.md`.
* Sign-side counterpart: `proofs/easycrypt/extraction/sign-byte-walk-roadmap.md`.
* Linear-issue tracker: #4.
