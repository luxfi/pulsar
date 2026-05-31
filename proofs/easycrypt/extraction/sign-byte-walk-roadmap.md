# Sign-side byte-walk roadmap

## Status — current

`sign_body_compute_sig_spec` is **no longer an axiom**. It is
proved as a lemma at
`proofs/easycrypt/Pulsar_N1_Sign_Refinement.ec:776`, composing
the per-stage component-level lemmas
(`sign_body_compute_components_spec`) with the structural pack
identity (`Pulsar_N1.pack_n1_signature` shared on both extracted
and centralised sides). The 7-step sub-claim decomposition that
the original version of this roadmap sketched (S1..S7) has been
landed implicitly via the v3 → v12 refactor — the per-stage
axioms named below sit at strictly narrower granularity than the
original `sign_body_compute_sig_spec`.

The active byte-walk + codec-layout axiom family on the sign
side (post-v12, all in `Pulsar_N1_Sign_Refinement.ec`):

| Axiom | Line | Category | Replaces |
|---|---|---|---|
| `sign_layout_m_buffer_external_mu` | 510 | wrapper byte-layout (load_bytes ↔ external_mu) | v8 `sign_body_mu_input_spec` (narrowed in v9 to drop the abstract `sign_body_mu_input` op) |
| `sign_body_matrix_a_spec` | 560 | w-stage sub-axiom (extracted matrix A = `central_matrix_a`) | half of v11 `sign_body_w_spec` |
| `sign_body_mask_y_spec` | 570 | w-stage sub-axiom (extracted mask y at accepting kappa) | half of v11 `sign_body_w_spec` |
| `sign_body_y_spec` | 649 | z-stage sub-axiom (extracted y = `central_y_at_accepted_kappa`) | half of v10 `sign_body_z_spec` |
| `sign_body_cs1_spec` | 662 | z-stage sub-axiom (extracted cs1 = `apply_c_to_s1`) | half of v10 `sign_body_z_spec` |
| `sign_body_w_low_spec` | 704 | h-stage sub-axiom (extracted w_low = `central_w_low`) | v9 `sign_body_h_spec` (after MakeHint structural split, v10) |
| `sign_no_reject_on_accepted_honest_layout` | 826 | accepted-path companion: layout + accept event ⇒ status = 0 | landed in the v10 no-reject decomposition; pairs with `sign_body_compute_sig_spec` |

The sign side does NOT consume `threshold_partial_response_identity` —
that bridge is only required on the combine side (Lagrange
aggregation across the quorum). The sign-side z-stage uses the
structural `add_response_vec` composition shared with
`Pulsar_N1.mldsa_compute_z`.

This document is retained for **historical context**: the
S1..S7 stage map below corresponds to FIPS 204 §6.2 stages and
the kappa rejection-sampling loop, and it remains a useful
reading guide to `sign.ec:3603-3641` and `sign_inner` at
`sign.ec:3469`. The previous high-level framing — "the sign-side
proof is harder because of the kappa loop" — has been
side-stepped in the current source by introducing
`combine_body_compute_status` / `sign_body_compute_status` and
conditioning each per-stage lemma on `status = 0` (the
accepted-path precondition), with the no-reject companion axiom
discharging the status bit from the protocol-level
`accept_signing_attempt` event.

## Historical: original axiom statement

The pre-v3 shape of the obligation:

```ec
axiom sign_body_compute_sig_spec :
  forall mem_pre ptrs full,
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    refine_sig_to_n1_sign (sign_body_compute_sig mem_pre ptrs)
    = sign_abs_op full.
```

where `sign_abs_op full` unfolds (by definition) to:

```ec
Pulsar_N1.mldsa_sign_op
  full.`sgn_sk_n1 full.`sgn_m_n1
  full.`sgn_ctx_n1 full.`sgn_rnd_n1
```

i.e., the centralised FIPS 204 ML-DSA-65 signature on the four
protocol-level ghost fields. The current shape (now a lemma)
adds one precondition — `sign_body_compute_status mem_pre ptrs
= 0` — which threads through `sign_no_reject_on_accepted_honest_layout`
into the wrapper bridge.

**Ghost contract**: ctx and rho_rnd are not direct libjade
parameters. The wrapper carries them as ghost fields; the
obligation includes the claim that the wrapper's mu derivation
(`SHAKE256(0x00 || ctxlen || ctx || M)` per FIPS 204 §5.4.1
ExternalMu) and K-derived randomness correspond to FIPS 204
`Sign_internal` on the four-tuple. See the named ghost contract
block in `Pulsar_N1_Sign_Refinement.ec` and
`../../lean-easycrypt-bridge.md`. In v9 the prior bundled
`sign_body_mu_input_spec` axiom was narrowed to
`sign_layout_m_buffer_external_mu` (a pure byte-layout claim
about the wrapper-assembled `ptr_m` buffer; no libjade-body read
appears in the statement).

## Historical: extracted procedure shape

`M.sign` lives in `sign.ec:3603-3641`. Its signature:

```ec
proc sign (ptr_signature : W64.t, ptr_m : W64.t,
           m_len : W64.t, ptr_sk : W64.t) : W32.t
```

The body is thin: it reads 4000 bytes of secret-key bytes from
`ptr_sk`, delegates to `sign_inner` for the actual signature
computation, and writes 3293 bytes of packed signature at
`ptr_signature`.

The real work is in `sign_inner` (`sign.ec:3469`). The kappa
rejection loop, the SHAKE-based mu computation, the
expandA + expandMask + matrix-vector multiplication + decompose
+ rejection-check + pack flow — all of it lives in `sign_inner`.

## Historical: stage map (FIPS 204 §6.2)

| Stage | Extracted location | Functional op | Sub-claim (now landed as a lemma) |
|---|---|---|---|
| 1. Read sk bytes from input pointer | `sign.ec:3625-3630` | `decode_sk` (Sign_Layout) | folded into `layout_sign_args` |
| 2. sign_inner: sk unpacking | `sign_inner` body | `Pulsar_N1.unpack_sk` | folded into the structural unpack on both sides; `pack_unpack_sk_roundtrip` (axiom in `Pulsar_N1.ec:950`) pins the realisation |
| 3. sign_inner: mu = SHAKE256(tr ‖ M) | `sign_inner`, SHAKE call | `Pulsar_N1.compute_mu` | `sign_layout_m_buffer_external_mu` (axiom) ⇒ `sign_body_mu_input_spec` (lemma) ⇒ `sign_body_mu_spec` (lemma) via structural `shake256_to_mu`; `compute_mu_injective` (axiom in `Pulsar_N1.ec:953`) pins the realisation |
| 4. sign_inner: rho_prime derivation | deterministic / hedged | (folded into `sign_abs_op`'s `sgn_rnd_n1`) | wrapper ghost-contract obligation; not separately mechanized |
| 5. sign_inner: kappa rejection loop | `sign_inner` body | composition of expand_mask, mat_vec_mul, decompose, sample_in_ball, mul, sub, make_hint | `sign_body_{matrix_a,mask_y}_spec` ⇒ `sign_body_w_spec` (lemma); `sign_body_{y,cs1}_spec` ⇒ `sign_body_z_spec` (lemma) via `mldsa_compute_z` structural; `sign_body_w_low_spec` ⇒ h-stage; `sign_no_reject_on_accepted_honest_layout` (axiom) discharges the status bit |
| 6. sign_inner: pack_signature(c_tilde*, z*, h*) | `pack_signature` call | `Pulsar_N1.pack_n1_signature` | folded into structural `pack_n1_signature`; `pack_unpack_n1_signature_roundtrip` (axiom in `Pulsar_N1.ec:817`) pins the realisation |
| 7. M.sign: write sig_packed at ptr_signature | `sign.ec:3634-3640` | `write_sig_sign` (Sign_Layout) | proved in `Pulsar_N1_Sign_Layout.ec` |

## Composition

The lemma chain that closes `sign_body_compute_sig_spec`:

```
sign_layout_m_buffer_external_mu
  ⇒ sign_body_mu_input_spec
  ⇒ sign_body_mu_spec                                (via shake256_to_mu)
sign_body_{matrix_a,mask_y}_spec
  ⇒ sign_body_w_spec                                 (via central_w)
  ⇒ sign_body_w1_spec                                (via high_bits_of_w)
sign_body_mu_spec ∧ sign_body_w1_spec
  ⇒ sign_body_c_tilde_spec                           (via shake_mu_w1)
sign_body_{y,cs1}_spec ∧ sign_body_c_tilde_spec
  ⇒ sign_body_z_spec                                 (via mldsa_compute_z = add_response_vec)
sign_body_w_spec ∧ sign_body_w_low_spec
  ⇒ sign_body_h_spec                                 (via make_hint_of_w)
sign_body_c_tilde_spec ∧ sign_body_z_spec ∧ sign_body_h_spec
  ⇒ sign_body_compute_components_spec
sign_body_compute_components_spec
  ⇒ sign_body_compute_sig_spec                       (via pack_n1_signature congruence)
```

The composition is fully landed in `Pulsar_N1_Sign_Refinement.ec`
through versions v3 → v12. See the per-version delta in the
ACCOUNTING block at the end of that file.

## Concrete attack surface (post-v12)

What remains to mechanically close on the sign side, in suggested
attack order:

1. **`sign_layout_m_buffer_external_mu`** (wrapper byte-layout).
   The narrowest remaining mu obligation: the bytes the wrapper
   writes at `ptr_m` form the FIPS 204 §5.4.1 ExternalMu layout.
   Single `load_bytes` claim; the wrapper-side writer is a
   straight `store_bytes` of `[0; |ctx|] ++ ctx ++ M`. Mechanical.
2. **`sign_body_w_low_spec`** (h-stage sub-axiom). Low-bits side
   of the decompose at the accepting kappa. Direct mirror of
   `combine_body_w_low_spec` — shared proof effort with the
   combine side.
3. **`sign_body_y_spec`** (z-stage). Extracted mask y at the
   accepting kappa equals `central_y_at_accepted_kappa`.
   Effectively `central_y_at_accepted_kappa` IS the mask-y stage
   conditioned on `status = 0` — the obligation reduces to a
   structural identity once the accepted-path is fixed.
4. **`sign_body_cs1_spec`** (z-stage). Extracted c·s1 mixed
   product equals `apply_c_to_s1`. The c value comes from
   `central_c_from_c_tilde` applied to the extracted c_tilde
   intermediate — composes with the c_tilde lemma chain.
5. **`sign_body_{matrix_a,mask_y}_spec`** (w-stage). Mirrors of
   the combine-side axioms; same BArray ↔ R_q polynomial-view
   bridge required.
6. **`sign_no_reject_on_accepted_honest_layout`** (companion).
   Conditional status-bit claim: layout-conforming inputs +
   `accept_signing_attempt` ⇒ `sign_body_compute_status = 0`.
   Same shape as the combine-side companion. The kappa-loop
   convergence (~ 1 − (3/4)^256 per attempt) is tracked
   operationally via `Pulsar_N1.mldsa_accept_lower_bound`;
   probabilistic Hoare logic for the loop is NOT in scope.

## Why the kappa loop is no longer the bottleneck

The original framing in the pre-v3 version of this roadmap
treated the kappa rejection-sampling loop in `sign_inner` as the
load-bearing obstacle — "proving termination + correctness of an
unbounded rejection loop in EC is significantly harder than
proving a fixed-length aggregation".

The current structure side-steps that obstacle by reducing each
per-stage obligation to its accepted-path form (conditioned on
`sign_body_compute_status mem_pre ptrs = 0`). The deterministic
content of `sign_inner` at the accepting kappa is what
`sign_body_{y,cs1,matrix_a,mask_y,w_low}_spec` capture; the
probabilistic content of the kappa loop is what
`sign_no_reject_on_accepted_honest_layout` discharges from the
protocol-level `accept_signing_attempt` event.

The probability bound on `accept_signing_attempt` is operational
(`Pulsar_N1.mldsa_accept_lower_bound`), not probabilistic-Hoare.
That choice is the same one BBDFGHHLW (CRYPTO 2023) makes for
single-party Dilithium and matches FIPS 204's standard treatment
of the rejection sampler.

## What this roadmap does NOT do

It does not produce mechanical closure of any of the axioms
above. The historical S-map (S1..S7) is now landed implicitly
via the per-stage axiom family; the residual obligations sit at
the narrower granularity in the table above. Each axiom is
independently attackable; the suggested order mirrors the
combine-side ordering where shared.

## Cross-references

- `Pulsar_N1_Sign_Refinement.ec:830-1120` — the per-file
  ACCOUNTING block (per-version axiom delta v1 → v12)
- `Pulsar_N1_Extracted.ec:34-92` — authoritative trust-boundary
  accounting
- `../README.md` — current axiom enumeration with file:line refs
- `../../lean-easycrypt-bridge.md` — Lean↔EC bridge correspondence
- `combine-byte-walk-roadmap.md` — combine-side counterpart
- Ghost contract: named block in `Pulsar_N1_Sign_Refinement.ec`
- Libjade jasmin-ct dependency: `../../../ct/jasmin-ct-libjade.md`
  (separately blocking issue #2)
- Linear issue tracker: #3
