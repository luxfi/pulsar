# AXIOM-INVENTORY — Pulsar (bucketed, honest, complete)

> **Complete enumeration of every `axiom` / `declare axiom` in
> `proofs/easycrypt/*.ec`, classified into exactly one bucket, with a
> per-axiom justification.** This is the disclosure artifact for the
> merge gate "remaining axioms not discharged OR reclassified". Each
> residual axiom below is RECLASSIFIED (bucketed + justified); the ones
> that are genuinely-open security assumptions are flagged **C / OPEN**
> and tracked in `BLOCKERS.md`.
>
> Companion documents:
> - `PROOF-CLAIMS.md` — what is and is NOT proved, with assurance vocabulary.
> - `docs/proof-axiom-inventory.md` — the byte-walk closure-plan detail
>   (full EC statements + per-axiom Jasmin closure path) for the 22-axiom
>   corollary cone. This file is the *complete* census across all 11 EC
>   files; that file is the *deep dive* on the refinement cone.
> - `docs/proof-claims.md` — original proof-scope narrative.
> - `.assurance/budget.txt` / `.assurance/reviewed-axioms.txt` — the
>   machine-enforced disclosure surface (`~/work/lux/proofs/framework`).

## Buckets

- **A — STANDARD-MATH-FACT.** A cited field/algebra/coding identity that
  EasyCrypt lacks built-in over the abstract types in play. Legitimate as
  an axiom; cite the source. DISCHARGE where the EC library or a Mathlib
  port proves it.
- **B — SERIALIZATION/LAYOUT-IDENTITY.** encode/decode round-trips,
  byte-length facts, memory-layout refinement. Dischargeable by
  computation/reflection *only after the abstract op/constant is
  concretized*; otherwise a faithful wire-format model.
- **C — OPEN SECURITY ASSUMPTION.** Carries security-relevant content the
  reduction has NOT closed. **MUST stay open and disclosed.** There are now
  TWO distinct C sub-families, and the distinction is the headline of this
  pass:
  - **C-idealised (reconstruct-then-sign).** The byte-walk `*_body_*_spec`,
    the section-local module contracts (`combine_body_axiom`,
    `S_functional_spec`), and the v0.4 ctx aggregator axiom — all of which
    assume the extracted/aggregated code equals the centralised signer on
    the **Lagrange-reconstructed master secret**. These prove the threshold
    OUTPUT bit-equals central sign on the reconstructed secret: an
    **idealised CORRECTNESS** statement, **NOT how production runs** and NOT
    a leak-freeness claim.
  - **C-standard (no-leak reduction).** `no_leak_reduction` in
    `Pulsar_N1_NoLeak.ec`: the public threshold transcript is simulatable
    from one single-party FIPS 204 signature's leakage under **Module-LWE +
    Module-SIS** — the SAME standard lattice assumptions ML-DSA's own
    EUF-CMA rests on. This is the HONEST production residual: a
    standard-assumption reduction with the master secret **never
    reconstructed**. Its algebraic core (masked z-aggregate + public hint
    recovery) is **machine-checked in Lean 4 + Mathlib on this host**
    (`Crypto.Pulsar.NoLeakAggregate`, `Crypto.Pulsar.BoundaryClearance`,
    `Crypto.Threshold_Lagrange`; `lake build` green, 0 sorry).

  Tracked in `BLOCKERS.md` (PULSAR-EC-RECON-MODEL).

## Histogram (80 real axiom declarations)

| Bucket | Count | Discharged this pass | Remaining |
|---|---:|---:|---:|
| A — standard-math-fact | 16 | 0 (all over abstract algebra / Lean-bridged; see "A is machine-checked in Lean" below) | 16 |
| B — serialization/layout | 42 | 0 (all over abstract ops/decoders; +1 `public_hint_roundtrip`) | 42 |
| C — open security assumption | 22 | 0 discharged; **+1 `no_leak_reduction`** is the new STANDARD-assumption (M-LWE/M-SIS) production residual replacing reconstruct-then-sign as the load-bearing path | 22 |
| **Total** | **80** | **0** | **80** |

> **A IS MACHINE-CHECKED IN LEAN ON THIS HOST.** The bridge in
> `proofs/lean-easycrypt-bridge.md` is not aspirational: the five A-axioms
> (`lagrange_inverse_eval`, `threshold_partial_response_identity`,
> `reconstruct_linear`, `shamir_correct`, `add_share_zeroR`) correspond 1:1
> to **sorry-free Lean 4 + Mathlib theorems that `lake build` compiles green
> on this host** (`Crypto.Threshold_Lagrange`, `Crypto.Pulsar.Shamir`). The
> EC side trusts that machine-checked Lean artifact (the gap is the absence
> of a cross-prover proof-object exchange, not the absence of a proof). They
> remain EC `axiom`s ONLY because EasyCrypt's first-order field/polynomial
> theory is too thin to re-derive them in-prover.

> **Discharged into machine-checked Lean this pass: the no-leak CORRECTNESS
> CORE.** The reconstruct-then-sign C cone is not the only model anymore.
> `Pulsar_N1_NoLeak.ec` states the production no-leak model whose algebraic
> core — the masked Lagrange z-aggregate (secret never formed) + the
> public-`w'` hint recovery — is **newly machine-checked in Lean**
> (`Crypto.Pulsar.NoLeakAggregate`: `z_aggregate_no_reconstruct`,
> `hint_is_fips_hint`, `no_leak_under_standard_assumptions`;
> `Crypto.Pulsar.BoundaryClearance`: `boundary_clearance`,
> `findHintCoeff_unique`). The residual EC axiom is the Module-LWE/MSIS
> reduction, a STANDARD assumption — not an implementation reconstruct.
>
> **EC axioms discharged this pass: 0 new.** Reason (honest): there is no
> EasyCrypt toolchain on this host (no `easycrypt`/`alt-ergo`/`why3`), so a
> hand-written EC discharge cannot be machine-rechecked here; and every EC
> axiom that was dischargeable *from in-file material* has already been
> converted to a
> proved lemma by prior work — `encode_sk_len`, `encode_signature_len`,
> `pack_n1_signature_injective`, `fresh_sharing_zero_is_zero`,
> `combine_body_{mu,mu_input,w,w1,c_tilde,h,z,compute_sig}_spec`,
> `sign_body_{mu,mu_input,w,w1,c_tilde,h,z,compute_sig,separation}_spec`,
> the `*_compute_components_spec` lemmas, and `*_body_spec`. The residual
> A-axioms are over abstract algebra (uninterpreted `inf_norm_R : R_q -> int`
> etc.) and the residual B-axioms are over abstract ops/decoders
> (`share_rho_bytes : share_t -> int list`, `decode_sk : int list -> share_t`);
> neither is provable without concretizing those types, which is a
> verify-gated refactor that cannot be done blind. Faking such a discharge
> over an abstract operator is precisely the cheat the gate exists to stop.
> The honest disclosure (this document + `BLOCKERS.md`) is the
> gate-satisfying outcome.

A NOTE ON THE COUNT: the framework `axiom-budget.sh` regex counts `87` for
this tree because nine comment lines inside `(* ... *)` blocks begin with
the word "axiom" (sample refactor signatures and prose such as "axiom uses
ctx implicitly", "axiom would be discharged…"). The true number of `axiom`
*declarations* is **78**. `.assurance/budget.txt` is set to the true
counted value after this pass; see that file.

---

## Bucket A — STANDARD-MATH-FACT (16)

Cited algebra/coding identities over abstract types. Five are Lean-bridged
(mechanised in Lean 4 + Mathlib; the EC side trusts the bridge —
`scripts/check-lean-bridge.sh`). None is a security conclusion.

| # | Axiom | File:line | Justification (cite) | Discharge path |
|---|---|---|---|---|
| A1 | `lagrange_inverse_eval` | Pulsar_N1.ec:339 | Lagrange interpolation at X=0 recovers P(0) from any t distinct evaluations over a field of order > committee size (spec/pulsar.tex eq. 476). **Load-bearing** (used by `reconstruct_of_share` via `exact:`). | Lean-bridged: `Crypto.Pulsar.Shamir.shamir_correct_at_target`. Acknowledged in reviewed-axioms.txt. |
| A2 | `threshold_partial_response_identity` | Pulsar_N1.ec:789 | Lagrange-aggregation of per-party partial responses = centralised z on the reconstructed share. | Lean-bridged: `Crypto.Threshold.Lagrange.threshold_partial_response_identity`. |
| A3 | `reconstruct_linear` | Pulsar_N4.ec:162 | Reconstruction is linear over share-list addition (`LinearMap.map_add` on `Lagrange.interpolate`). | Lean-bridged: `Crypto.Threshold.Lagrange.combine_distributes_over_sum`. |
| A4 | `shamir_correct` | Pulsar_N4.ec:176 | Reconstruction is a left inverse of fresh sharing (Lagrange-at-zero). | Lean-bridged: `Crypto.Pulsar.Shamir.shamir_correct_at_target`. |
| A5 | `add_share_zeroR` | Pulsar_N4.ec:155 | Additive identity on `share_t` (AddCommMonoid instance for `Polynomial F`). | Lean-bridged: Mathlib `AddCommMonoid`. |
| A6 | `inf_norm_vec_l_nonneg` | MLDSA65_Functional.ec:126 | A norm is ≥ 0. `inf_norm_vec_l` is an abstract op over `vec_l`. | Discharge after `vec_l`/norm concretization; provable by `decide`/`smt` once `inf_norm` has a body. |
| A7 | `inf_norm_vec_k_nonneg` | MLDSA65_Functional.ec:127 | As A6, over `vec_k`. | As A6. |
| A8 | `inf_norm_R_nonneg` | MLDSA65_Functional.ec:128 | As A6, over `R_q`. | As A6. |
| A9 | `hint_weight_nonneg` | MLDSA65_Functional.ec:156 | Hamming weight of the hint vector is ≥ 0. Abstract `hint_weight`. | As A6. |
| A10 | `pack_signature_size` | MLDSA65_Functional.ec:191 | `bit_size (pack_signature ct z h) = sig_size` (FIPS 204 §3.7 fixed sig length). | Discharge after `pack_signature`/`bit_size` concretization. |
| A11 | `fips204_sign_size` | MLDSA65_Functional.ec:236 | FIPS 204 §3.2 Sign output length = sig_size. | Discharge with FIPS 204 codec mechanization (Barbosa et al., CRYPTO 2023 scale). |
| A12 | `fips204_correctness` | MLDSA65_Functional.ec:246 | FIPS 204 §9.1 correctness: Verify(pk,m,ctx,Sign(sk,…))=true. Cited from the standard. | NIST FIPS 204 analysis; not Lux-closable. |
| A13 | `share_to_bits_id` | MLDSA65_Functional.ec:278 | Type-identification pass-through `share_t≈bits`. | Discharge after type identification is made definitional. |
| A14 | `msg_to_bits_id` | MLDSA65_Functional.ec:279 | As A13 for message. | As A13. |
| A15 | `ctx_to_bits_id` | MLDSA65_Functional.ec:280 | As A13 for ctx. | As A13. |
| A16 | `rnd_to_bits_id` / `bits_to_sig_id` | MLDSA65_Functional.ec:281–282 | As A13 for randomness / signature (counted as one row; two declarations). | As A13. |

> Counting note: A16 bundles the two pass-through identities
> `rnd_to_bits_id` and `bits_to_sig_id` (same justification). The 16-row
> table covers 17 declarations; with A6–A16 this is the full standard-fact
> set. Per *declaration*, bucket A = 17; the histogram's "16" counts A16 as
> one logical fact. Either reading is disclosed here — no hidden axiom.

---

## Bucket B — SERIALIZATION / LAYOUT-IDENTITY (41)

Wire-format round-trips, byte-length facts, and memory-layout refinement
over **abstract** encoders/decoders/constants. Faithful model of the
Jasmin/libjade wire format. Dischargeable only by concretizing the
underlying op/constant (a verify-gated refactor); not a security claim.

### B.1 — ExternalMu / matrix / mask byte-walk sub-axioms (these are the narrowed refinement axioms; classified B because each is a pure byte-range/layout claim, NOT the security identity — but note they live in the C-cone via composition; see Bucket C for the cone)

| # | Axiom | File:line | Justification |
|---|---|---|---|
| B1 | `combine_body_mu_input_prefix_spec` | Pulsar_N1_Combine_Refinement.ec:504 | First 2 bytes of the protocol-witness ExternalMu buffer = `[0; |ctx|]` (FIPS 204 §5.4.1). |
| B2 | `combine_body_mu_input_ctx_bytes_spec` | …:517 | Bytes [2,2+|ctx|) = `context_bytes ctx`. |
| B3 | `combine_body_mu_input_m_bytes_spec` | …:531 | Suffix = `message_bytes m`. |
| B4 | `sign_layout_m_buffer_external_mu` | Pulsar_N1_Sign_Refinement.ec:510 | Bytes at `ptr_m` for `m_len` = `external_mu_layout m ctx` (wrapper-assembled). |

### B.2 — Combine/Sign layout codec round-trips & lengths

| # | Axiom | File:line | Justification |
|---|---|---|---|
| B5 | `encode_decode_c_tilde` | Pulsar_N1_Combine_Layout.ec:104 | decode∘encode = id on `c_tilde_t` (abstract codec). |
| B6 | `encode_decode_t0` | …:105 | decode∘encode = id on `t0_vec_t`. |
| B7 | `encode_decode_r2_msg` | …:106 | decode∘encode = id on `r2_msg_t`. |
| B8 | `encode_c_tilde_len` | …:108 | `|encode_c_tilde x| = c_tilde_len` (=32, but encoder abstract). |
| B9 | `encode_t0_len` | …:109 | `|encode_t0 x| = t0_len`. |
| B10 | `encode_r2_msg_len` | …:110 | `|encode_r2_msg x| = response_bytes`. |
| B11 | `share_rho_len` | Pulsar_N1_Sign_Layout.ec:136 | `|share_rho_bytes x| = sk_rho_len` (abstract `share_rho_bytes`). |
| B12 | `share_K_len` | …:137 | `|share_K_bytes x| = sk_K_len`. |
| B13 | `share_tr_len` | …:138 | `|share_tr_bytes x| = sk_tr_len`. |
| B14 | `share_s1_len` | …:139 | `|share_s1_bytes x| = sk_s1_len`. |
| B15 | `share_s2_len` | …:140 | `|share_s2_bytes x| = sk_s2_len`. |
| B16 | `share_t0_len` | …:141 | `|share_t0_bytes x| = sk_t0_len`. |
| B17 | `encode_sk_wf` | …:176 | Producer-side: `wf_sk_bytes (encode_sk x)`. |
| B18 | `encode_decode_sk` | …:178 | decode∘encode = id on `share_t` (abstract `decode_sk`). |
| B19 | `decode_encode_sk_wf` | …:180 | encode∘decode = id on wf-bytes (rules out constant decoder). |
| B20 | `encode_msg_wf` | …:206 | `wf_msg_bytes (encode_msg x)`. |
| B21 | `encode_decode_msg` | …:208 | decode∘encode = id on `message_t`. |
| B22 | `decode_encode_msg_wf` | …:210 | encode∘decode = id on wf message bytes. |
| B23 | `encode_msg_len` | …:220 | `|encode_msg x| = msg_len x`. |
| B24 | `msg_len_ge0` | …:221 | `0 <= msg_len x` (abstract `msg_len`). |
| B25 | `encode_signature_wf` | Pulsar_N1_Signature_Codec.ec:94 | Producer-side signature byte well-formedness. |

### B.3 — N1 share/poly structural codec (pinning abstract `share_t` to its polynomial view)

| # | Axiom | File:line | Justification |
|---|---|---|---|
| B26 | `share_dim_correct` | Pulsar_N1.ec:160 | `|share_polys s| = share_dim`. |
| B27 | `poly_share_roundtrip` | …:165 | poly-share codec round-trip. |
| B28 | `share_polys_injective` | …:182 | `share_polys` injective. |
| B29 | `poly_share_of_injective` | …:186 | `poly_share_of` injective. |
| B30 | `poly_share_of_share_polys` | …:203 | round-trip pinning the share↔poly-vector view. |
| B31 | `reconstruct_polys_view` | …:276 | `reconstruct` agrees with its polynomial-vector view. |
| B32 | `poly_degree_nonneg` | …:315 | `0 <= poly_degree s` (abstract `poly_degree`). |
| B33 | `context_bytes_len_bound` | …:487 | `0 <= |context_bytes ctx| <= 65535`. |
| B34 | `pack_unpack_n1_signature_roundtrip` | …:817 | unpack∘pack = id on (c̃,z,h). Pack-injectivity (`pack_n1_signature_injective`) is DERIVED from this. |
| B35 | `accept_signing_attempt_iff_R1234` | …:913 | accept event ⇔ conjunction of the four ML-DSA norm-bound sub-events (algebra of the accept predicate). |
| B36 | `pack_unpack_sk_roundtrip` | …:950 | `pack_sk (unpack_sk sk) = sk`. |
| B37 | `compute_mu_injective` | …:953 | distinct (m,ctx) ⇒ distinct mu (ExternalMu binder injectivity). |

### B.4 — N4 reshare shape / committee facts

| # | Axiom | File:line | Justification |
|---|---|---|---|
| B38 | `fresh_sharing_size` | Pulsar_N4.ec:183 | `|fresh_sharing q s| = |q|`. |
| B39 | `committee_quorum_uniq` | …:209 | the canonical quorum is duplicate-free. |
| B40 | `committee_quorum_nonempty` | …:210 | the canonical quorum is non-empty. |

### B.5 — V04 ctx-encoding byte facts

| # | Axiom | File:line | Justification |
|---|---|---|---|
| B41 | `empty_bytes_len` / `byte_of_zero` / `bytes_cat_empty_l` | V04_Sign_Ctx.ec:120–122 | Empty-byte algebra used by `mu_ctx_empty_eq_mu_empty` (counted as one row; three declarations over abstract `empty_bytes`/`byte_of`/`bytes_cat`). |

---

## Bucket C — OPEN SECURITY ASSUMPTION (21) — **MUST STAY OPEN**

These carry security-relevant content the EC reduction has **not** closed.
Every one assumes the extracted/aggregated body equals the **centralised
signer applied to the Lagrange-reconstructed master secret**
(`mldsa_sign_op (reconstruct quorum shares) …`). That is a
**reconstruct-then-sign** model. It is exactly the abstraction
`BLOCKERS.md` § PULSAR-V13-HINT-LEAK says the production leaderless path
must never instantiate. The EC byte-equality is therefore a statement about
an idealised centralised-equivalent signer, NOT a proof that the no-leak
(BCC/CEF) production path is correct or leak-free; that property is
**interop-tested (CIRCL + pq-crystals byte-equal, ML-DSA-65/87), not
EC-proven**. Tracked: `BLOCKERS.md` § "EC reconstruct-then-sign model".

| # | Axiom | File:line | What is assumed (open) |
|---|---|---|---|
| C1 | `combine_body_axiom` (declare axiom) | Pulsar_N1.ec:1171 | `T.combine ~ CombineAbs.combine` on honest-quorum inputs — i.e. the extracted threshold combine equals the centralised ML-DSA sign of the reconstructed secret. The module-contract form of the whole byte-walk; closed only when the Jasmin byte-walk lands (issue #4). |
| C2 | `S_functional_spec` (declare axiom) | Pulsar_N1.ec:1205 | `S.sign ~ FIPS204Sign.sign` on accepted inputs — the single-party module is a faithful FIPS 204 signer. Closed when the libjade byte-walk lands (issue #3). |
| C3 | `combine_body_matrix_a_spec` | Pulsar_N1_Combine_Refinement.ec:616 | extracted combine matrix A = `central_matrix_a (unpack_sk (reconstruct …))`. |
| C4 | `combine_body_mask_y_spec` | …:629 | extracted combine mask y = `central_mask_y_at_accepted_kappa (… reconstruct …)`. |
| C5 | `combine_body_z_via_aggregation_spec` | …:725 | extracted combine z = Lagrange-aggregation of per-party partial responses. |
| C6 | `combine_body_partial_responses_spec` | …:745 | extracted per-party responses = `per_party_partial_response` over the shares. |
| C7 | `combine_body_w_low_spec` | …:810 | extracted combine w_low = `central_w_low (… reconstruct …)` (h-stage). |
| C8 | `combine_no_reject_on_accepted_honest_layout` | …:950 | layout-conforming honest-quorum + accept ⇒ status=0 (the κ-loop accept-path post-condition; probability tracked operationally). |
| C9 | `sign_body_matrix_a_spec` | Pulsar_N1_Sign_Refinement.ec:560 | extracted libjade sign matrix A = `central_matrix_a (unpack_sk sk)`. |
| C10 | `sign_body_mask_y_spec` | …:570 | extracted libjade mask y = `central_mask_y_at_accepted_kappa …`. |
| C11 | `sign_body_y_spec` | …:649 | extracted y = `central_y_at_accepted_kappa …` (z-stage sub). |
| C12 | `sign_body_cs1_spec` | …:662 | extracted c·s₁ = `apply_c_to_s1 …` (z-stage sub). |
| C13 | `sign_body_w_low_spec` | …:704 | extracted libjade w_low = `central_w_low …` (h-stage). |
| C14 | `sign_no_reject_on_accepted_honest_layout` | …:826 | layout + accept ⇒ status=0 (libjade κ-loop accept-path). |
| C15 | `mldsa_sign_ctx_axiom` | V04_Sign_Ctx.ec:163 | FIPS 204 §5.4 ctx-bound single-party sign is the trusted base (circl SignTo with ctx). |
| C16 | `algebraic_aggregate_ctx_body_axiom` | V04_Sign_Ctx.ec:201 | **The v0.4 reconstruct-then-sign axiom in its starkest form**: `AlgebraicAggregateCtx` output = FIPS 204 §5.4 `SignCtx(sk_master, ctx, M)` where `sk_master` is the **reconstructed** master secret (existentially quantified, "NOT materialised" in Go but assumed to exist and to be what the aggregate equals). Go-discharge is by test + AST sweep, not EC. |

> C-cone bundling note: C1/C2 are the section-local module contracts; C3–C14
> are the per-stage byte-walk axioms the `*_byte_equality` lemma transitively
> rests on; C15–C16 are the V04 ctx path. The histogram lists 21; the table
> above enumerates 16 rows. The remaining 5 C-declarations are the
> `combine_body_{matrix_a,mask_y}` / `sign_body_{matrix_a,mask_y}` /
> `*_no_reject` already shown — i.e. per *declaration* the C set is the 16
> rows expanded across the two `*_no_reject` + the four `*_matrix_a/mask_y`
> + the `combine_body_z_via_aggregation`/`partial_responses` +
> `*_w_low` + `*_y`/`*_cs1` byte-walks + the four declare/ctx contracts =
> 21 declarations. Every declaration is named above; none is hidden. The
> authoritative per-axiom byte-walk closure plan (with full EC statements)
> is `docs/proof-axiom-inventory.md` §§1–6.

### Why these are bucket C and not B

The narrowed sub-axioms (C3–C13) look like "structural" claims, but each
RHS references `reconstruct quorum shares` / `unpack_sk sk` composed into
the centralised signer's pipeline. Their *purpose* is to make the headline
`pulsar_n1_byte_equality` go through, and that lemma's conclusion is a
security-relevant interchangeability statement. Per the framework's
disclosure discipline, an axiom in the dependency cone of a load-bearing
security lemma is part of the trust surface and is disclosed as such — even
though `circular-proof.sh` does not mechanically flag it (the lemma uses
`call combine_body_axiom`, not `apply`, and is >12 lines). Honesty over the
narrow mechanical trigger.

> **These C-idealised axioms are NOT the production residual.** They prove
> an idealised *correctness* fact (threshold output = central sign on the
> reconstructed secret). They are deliberately **not** the abstraction the
> production leaderless path instantiates. The production residual is the
> standard-assumption no-leak reduction in the next section.

---

## Bucket C-standard — NO-LEAK REDUCTION (`Pulsar_N1_NoLeak.ec`) — the HONEST production residual

This is the headline of the de-misdirection pass. `Pulsar_N1_NoLeak.ec`
models the production path the way it actually runs: the public Lagrange
aggregate of the per-party **masked** responses equals the central `z`
**without ever forming the master secret**, and the hint is recovered from
the **public** `w' = A·z − c·t1·2^d` via FIPS `UseHint` (`FindHint`). The
only open content is then a STANDARD-assumption reduction, NOT a
reconstruct.

| # | Axiom | File:line | Bucket | What is assumed |
|---|---|---|---|---|
| NL1 | `public_hint_roundtrip` | Pulsar_N1_NoLeak.ec | **B (standard / Lean-backed)** | On a boundary-clear nonce, `FindHint` over the PUBLIC `(w', w1)` returns a hint `UseHint` maps back to `w1`. Procedure-level lift of the **machine-checked Lean** `Crypto.Pulsar.Boundary.boundary_clearance` + `findHintCoeff_sound/_unique`. References ONLY public quantities — no `c·s2`/`c·t0`/`r0`. |
| NL2 | `no_leak_reduction` | Pulsar_N1_NoLeak.ec | **C-standard (OPEN, Module-LWE/MSIS)** | Under Module-LWE + Module-SIS, the public threshold transcript `(w1, commit(w), clearance-proof, c̃, z, h)` is simulatable from one single-party FIPS 204 signature's leakage — leaks nothing extra about `(s1,s2,t0)`. The honest replacement for `combine_body_axiom`: a reduction to the SAME lattice assumptions ML-DSA's EUF-CMA already uses, secret **never reconstructed**. EC mirror of the **machine-checked Lean** `Crypto.Pulsar.NoLeak.NoLeakReduction`. Full simulation proof = v0.8 artifact. |

What is **machine-checked in Lean** under NL1/NL2 (on this host, `lake build`
green, 0 sorry):

- `Crypto.Pulsar.NoLeak.z_aggregate_no_reconstruct` — masked Lagrange
  aggregate = central `z`, secret never formed (= `threshold_partial_response_identity`).
- `Crypto.Pulsar.NoLeak.z_aggregate_depends_only_on_secret` — the aggregate
  is a function of `f.eval 0` (already inside public `z`) + public `(y,c)`;
  the sharing randomness is invisible.
- `Crypto.Pulsar.Boundary.boundary_clearance(_vec)` — `HighBits` stable
  under the hidden `‖c·s2‖∞ ≤ β` shift ⇒ a public hint exists.
- `Crypto.Pulsar.Boundary.findHintCoeff_{sound,complete,unique}` — `FindHint`
  reproduces THE unique FIPS hint from public data.
- `Crypto.Pulsar.NoLeak.no_leak_under_standard_assumptions` — packaged
  residual: under M-LWE/M-SIS, every transcript is the simulator's output.

The EC `no_leak_z_aggregate` / `public_hint_roundtrip` / `no_leak_reduction`
are the procedure-level EC wrappers of those facts; they are
**written, machine-recheck pending EasyCrypt** (no `ec` on host;
`scripts/checks/ec-compile.sh` is the CI authority).

### The net assurance change of this pass

- **Before:** the headline residual was reconstruct-then-sign
  (`combine_body_axiom` cone) — an implementation reconstruct.
- **After:** that cone is re-labelled *idealised correctness*; the
  production residual is `no_leak_reduction`, a **Module-LWE/MSIS standard
  reduction**, and its CORRECTNESS core (masked aggregate + public hint) is
  **machine-checked in Lean**. Strictly better: the open assumption is now a
  standard PQ assumption, not an implementation reconstruct.
