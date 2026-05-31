# Combine-side byte-walk roadmap

## Status — current

`combine_body_compute_sig_spec` is **no longer an axiom**. It is
proved as a lemma at
`proofs/easycrypt/Pulsar_N1_Combine_Refinement.ec:893`,
composing the per-stage component-level lemmas
(`combine_body_compute_components_spec`) with the structural pack
identity (`Pulsar_N1.pack_n1_signature` shared on both extracted
and centralised sides). The 10-step sub-claim decomposition that
the original version of this roadmap sketched (S1..S10) has been
landed implicitly via the v3 → v12 refactor — the per-stage
axioms named below sit at strictly narrower granularity than the
original `combine_body_compute_sig_spec`.

The active byte-walk + codec-layout axiom family on the combine
side (post-v12, all in `Pulsar_N1_Combine_Refinement.ec`):

| Axiom | Line | Category | Replaces |
|---|---|---|---|
| `combine_body_mu_input_prefix_spec` | 504 | codec layout (first 2 bytes of FIPS 204 §5.4.1 ExternalMu) | half of v8 `combine_body_mu_input_spec` |
| `combine_body_mu_input_ctx_bytes_spec` | 517 | codec layout (ctx-bytes slice) | half of v8 `combine_body_mu_input_spec` |
| `combine_body_mu_input_m_bytes_spec` | 531 | codec layout (M-bytes suffix) | half of v8 `combine_body_mu_input_spec` |
| `combine_body_matrix_a_spec` | 616 | w-stage sub-axiom (extracted matrix A = `central_matrix_a`) | half of v11 `combine_body_w_spec` |
| `combine_body_mask_y_spec` | 629 | w-stage sub-axiom (extracted mask y at accepting kappa) | half of v11 `combine_body_w_spec` |
| `combine_body_z_via_aggregation_spec` | 725 | z-stage structural (extracted z = Lagrange aggregation of partial responses) | structural half of v7 `combine_body_z_spec` |
| `combine_body_partial_responses_spec` | 745 | z-stage byte-walk (per-party partial responses = `per_party_partial_response`) | byte-walk half of v7 `combine_body_z_spec` |
| `combine_body_w_low_spec` | 810 | h-stage sub-axiom (extracted w_low = `central_w_low`) | v9 `combine_body_h_spec` (after MakeHint structural split, v10) |
| `combine_no_reject_on_accepted_honest_layout` | 950 | accepted-path companion: layout + accept event ⇒ status = 0 | new in followup B; pairs with `combine_body_compute_sig_spec` |

Plus the Lean-bridged identity
`Pulsar_N1.threshold_partial_response_identity` (`Pulsar_N1.ec:789`)
discharged by
`Crypto/Threshold_Lagrange.lean::threshold_partial_response_identity` —
required for the v8 z-stage lemma (composes the two narrow
z-stage axioms above).

This document is retained for **historical context**: the
S1..S10 stage map below corresponds to FIPS 204 §6.2 inner-loop
stages and matches the granularity originally targeted for the
single bundled axiom. The S-map is still a useful reading guide
to `combine.ec:3245-3617`.

## Historical: original axiom statement

The pre-v3 shape of the obligation:

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
Lagrange-reconstructed group secret. The current shape (now a
lemma) adds three preconditions — `protocol_consistency`,
`threshold_protocol_invariants`, `combine_body_compute_status
mem_pre ptrs = 0` — which thread through the wrapper bridge into
`pulsar_n1_byte_equality_extracted`.

## Historical: extracted procedure shape

`M.pulsar_combine` lives in `combine.ec:3245-3617`. Its signature:

```ec
proc pulsar_combine (c_tilde_ptr : W64.t, t0_ptr : W64.t,
                     round2_msgs_ptr : W64.t, threshold : W32.t,
                     sig_out_ptr : W64.t) : W64.t
```

Returns a status word (`0` for success, non-zero `fail_bits` for
rejection-condition failures). On success, writes 3293 bytes of
packed signature at `sig_out_ptr`.

## Historical: stage map (FIPS 204 §6.2)

| Stage | Extracted lines | Functional op | Sub-claim (now landed as a lemma) |
|---|---|---|---|
| 1. Read c_tilde from input pointer | `combine.ec:3413-3416` | (identity — c_tilde is wire input) | folded into `layout_combine_args` |
| 2. Read t0 from t0 pointer | `combine.ec:3417-3426` | (identity — t0 is wire input from group pk) | folded into `layout_combine_args` |
| 3. Read & aggregate Round-2 messages | `combine.ec:3430-3505` | `vec_l_add`, `vec_k_add` | `combine_body_z_via_aggregation_spec` + `combine_body_partial_responses_spec` + `threshold_partial_response_identity` ⇒ `combine_body_z_spec` (lemma) |
| 4. SampleInBall on c_tilde | `combine.ec:3506` | `sample_in_ball` | folded into the structural `central_c_from_c_tilde` op shared by both sides |
| 5. Compute w_prime = w_agg + ct0_agg | `combine.ec:3530-3545` | `vec_k_add` + decompose math | `combine_body_matrix_a_spec` + `combine_body_mask_y_spec` ⇒ `combine_body_w_spec` (lemma) |
| 6. Decompose w_prime | `combine.ec:3560` | `decompose_vec_k` | factored through structural `high_bits_of_w` ⇒ `combine_body_w1_spec` (lemma) |
| 7. MakeHint(v0, v1) | `combine.ec:3550` | `vec_k_make_hint` | `combine_body_w_spec` + `combine_body_w_low_spec` ⇒ `combine_body_h_spec` (lemma) via structural `make_hint_of_w` |
| 8. Rejection checks R1-R4 | `combine.ec:3562-3594` | norm bounds | `combine_no_reject_on_accepted_honest_layout` (axiom) — conditioned on the protocol-level accept event |
| 9. Pack signature | `combine.ec:3604` | `pack_signature` | folded into structural `pack_n1_signature` shared by both sides + `pack_unpack_n1_signature_roundtrip` (axiom in `Pulsar_N1.ec:817`) |
| 10. Write sig_packed at sig_out_ptr | `combine.ec:3606-3611` | `write_signature_at` | proved in `Pulsar_N1_Combine_Layout.ec` |

## Composition

The lemma chain that closes `combine_body_compute_sig_spec`:

```
combine_body_mu_input_{prefix,ctx_bytes,m_bytes}_spec
  ⇒ combine_body_mu_input_spec
  ⇒ combine_body_mu_spec                                (via shake256_to_mu)
combine_body_{matrix_a,mask_y}_spec
  ⇒ combine_body_w_spec                                 (via central_w)
  ⇒ combine_body_w1_spec                                (via high_bits_of_w)
combine_body_mu_spec ∧ combine_body_w1_spec
  ⇒ combine_body_c_tilde_spec                           (via shake_mu_w1)
combine_body_z_via_aggregation_spec
  ∧ combine_body_partial_responses_spec
  ∧ threshold_partial_response_identity                 (Lean bridge)
  ⇒ combine_body_z_spec
combine_body_w_spec ∧ combine_body_w_low_spec
  ⇒ combine_body_h_spec                                 (via make_hint_of_w)
combine_body_c_tilde_spec ∧ combine_body_z_spec ∧ combine_body_h_spec
  ⇒ combine_body_compute_components_spec
combine_body_compute_components_spec
  ⇒ combine_body_compute_sig_spec                       (via pack_n1_signature congruence)
```

The composition is fully landed in `Pulsar_N1_Combine_Refinement.ec`
through versions v3 → v12. See the per-version delta in the
ACCOUNTING block at the end of that file.

## Concrete attack surface (post-v12)

What remains to mechanically close on the combine side, in
suggested attack order:

1. **`combine_body_mu_input_{prefix,ctx_bytes,m_bytes}_spec`**
   (codec). Strictly narrower than v8 `combine_body_mu_input_spec`;
   each per-range claim is about a fixed-length byte slice of the
   protocol-witness ExternalMu buffer. The combine side cannot
   collapse to `load_bytes` because `combine_ptrs_t` has no
   `m_ptr` / `ctx_ptr` (combine reads c_tilde, not mu). Per-range
   shape lets the proof attempt start at the prefix (2 bytes, the
   easiest) and proceed slice by slice.
2. **`combine_body_partial_responses_spec`** (z-stage byte-walk).
   Per-party partial-response extraction from Round-2 messages.
   Mechanical: the extracted body's read of `round2_msgs_ptr +
   i·response_bytes` lays out one party's partial response per
   wire-encoded message. The functional op
   `Pulsar_N1.per_party_partial_response` defines the same shape.
3. **`combine_body_z_via_aggregation_spec`** (z-stage structural).
   That the extracted body computes z as a Lagrange aggregation
   of the per-party partial responses over the quorum. The
   `combine.ec` body's loop reduces to `vec_l_add` over the
   per-party z components — structural identity through
   `Pulsar_N1.lagrange_aggregate_responses`.
4. **`combine_body_w_low_spec`** (h-stage sub-axiom). Low-bits
   side of the decompose at the accepting kappa. The matching
   axiom on the sign side (`sign_body_w_low_spec`) is a direct
   mirror. Shared proof effort.
5. **`combine_body_{matrix_a,mask_y}_spec`** (w-stage). Each is
   one extracted procedure (`combine_body_compute_matrix_a` /
   `combine_body_compute_mask_y`) reducing through the libjade
   `expand_a` / `expand_mask` functional ops. The hard part is
   bridging the BArray byte-vector view to the R_q polynomial
   view — needs a relational lemma per type.
6. **`combine_no_reject_on_accepted_honest_layout`** (companion).
   Conditional status-bit claim: layout-conforming inputs +
   `accept_signing_attempt` ⇒ `combine_body_compute_status = 0`.
   Deterministic given the accept-path precondition; the
   probability bound `Pulsar_N1.mldsa_accept_lower_bound` is
   tracked operationally rather than via probabilistic Hoare
   logic.

## What this roadmap does NOT do

It does not produce mechanical closure of any of the axioms
above. The historical S-map (S1..S10) is now landed implicitly
via the per-stage axiom family; the residual obligations sit at
the narrower granularity in the table above. Each axiom is
independently attackable; the suggested order moves from the
most mechanical (codec slices) to the most algebraic
(`matrix_a` / `mask_y`).

## Cross-references

- `Pulsar_N1_Combine_Refinement.ec:1100-1412` — the per-file
  ACCOUNTING block (per-version axiom delta v1 → v12)
- `Pulsar_N1_Extracted.ec:34-92` — authoritative trust-boundary
  accounting
- `../README.md` — current axiom enumeration with file:line refs
- `../../lean-easycrypt-bridge.md` — Lean↔EC bridge correspondence
- `sign-byte-walk-roadmap.md` — sign-side counterpart
- Linear issue tracker: #4
