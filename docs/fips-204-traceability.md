# FIPS-TRACEABILITY — Pulsar EasyCrypt ↔ FIPS 204 §-map

> **Op-by-op and lemma-by-lemma traceability to the FIPS 204 ML-DSA
> standard.** Required for ACVP/CAVP validation and for reviewers
> wanting to follow a specific FIPS section to its EC counterpart.

## How to read this document

Each section maps a FIPS 204 region to the corresponding EC types,
ops, and lemmas. The "Status" column reads:
- `ABSTRACT` — declared with no body; trusted via axioms.
- `DEFINED` — constructive body; structural identity.
- `PROVED` — derived lemma, no axiom.

## §1 FIPS 204 §3 — Parameters and primitives

### §1.1 Parameter set ML-DSA-65 (FIPS 204 §4 Table 1)

| FIPS 204 | EC op (in `lemmas/MLDSA65_Functional.ec`) | Value | Status |
|---|---|---|---|
| q (prime modulus) | `op q : int = 8380417.` | 2^23 − 2^13 + 1 | DEFINED |
| n (polynomial degree) | `op n_poly : int = 256.` | 256 | DEFINED |
| d (Power2Round drop bits) | `op d : int = 13.` | 13 | DEFINED |
| τ (SampleInBall weight) | `op tau : int = 49.` | 49 | DEFINED |
| λ (security level bits) | `op lambda_sec : int = 192.` | 192 | DEFINED |
| γ1 (y coeff range) | `op gamma1 : int = 524288.` | 2^19 | DEFINED |
| γ2 (Decompose cutoff) | `op gamma2 : int = 261888.` | (q−1)/32 | DEFINED |
| k (vec_k dim) | `op k_dim : int = 6.` | 6 | DEFINED |
| ℓ (vec_l dim) | `op l_dim : int = 5.` | 5 | DEFINED |
| η (s1/s2 coeff range) | `op eta_p : int = 4.` | 4 | DEFINED |
| β (= τ · η) | `op beta_sec : int = 196.` | 196 | DEFINED |
| ω (hint weight max) | `op omega_h : int = 55.` | 55 | DEFINED |
| `beta_sec = tau * eta_p` | `lemma beta_sec_eq` | — | PROVED |
| `(q−1) mod (2·γ2) = 0` | `lemma q_minus_1_mod_2gamma2` | — | PROVED |

### §1.2 Algebraic types (FIPS 204 §3.1)

| FIPS 204 | EC type | Status |
|---|---|---|
| R_q = Z_q[X]/(X^n + 1) | `type R_q.` | ABSTRACT |
| R_q^k | `type vec_k.` | ABSTRACT |
| R_q^l | `type vec_l.` | ABSTRACT |
| R_q^{k×l} | `type matrix_kl.` | ABSTRACT |
| Byte streams | `type bits.` | ABSTRACT |

Concretization path: `vec_k`, `vec_l` to be aliased to lists of
`R_q`; `R_q` to a polynomial-coefficient representation (e.g.,
`int list of length n_poly mod q`).

## §2 FIPS 204 §3.4 — Auxiliary algorithms

| FIPS 204 algorithm | EC op | Where | Status |
|---|---|---|---|
| Power2Round | `op power2round : R_q -> R_q * R_q.` | `MLDSA65_Functional.ec` | ABSTRACT |
| Power2Round on vec_k | `op vec_k_power2round` | same | ABSTRACT |
| Decompose | `op decompose_R : int -> R_q -> R_q * R_q.` | same | ABSTRACT |
| Decompose on vec_k | `op decompose_vec_k` | same | ABSTRACT |
| MakeHint | `op make_hint` | same | ABSTRACT |
| MakeHint on vec_k | `op vec_k_make_hint` | same | ABSTRACT |
| UseHint | `op use_hint` | same | ABSTRACT |
| HintWeight | `op hint_weight` | same | ABSTRACT |

## §3 FIPS 204 §3.5 — Sampling

| FIPS 204 | EC op | Status |
|---|---|---|
| SampleInBall (§3.5.1) | `op sample_in_ball : bits -> R_q.` | ABSTRACT |
| ExpandA (§3.5.2) | `op expand_a : bits -> matrix_kl.` | ABSTRACT |
| ExpandS (§3.5.3) | `op expand_s : bits -> vec_l * vec_k.` | ABSTRACT |
| ExpandMask (§3.5.4) | `op expand_mask : bits -> int -> vec_l.` | ABSTRACT |

## §4 FIPS 204 §3.5.4 — Secret-key encoding (sk packing)

| FIPS 204 sk-component | EC op (in `Pulsar_N1_Sign_Layout.ec`) | Length | Status |
|---|---|---|---|
| ρ (32 bytes, ExpandA seed) | `op share_rho_bytes : share_t -> int list.` | `sk_rho_len = 32` | ABSTRACT |
| K (32 bytes, sk randomness seed) | `op share_K_bytes` | `sk_K_len = 32` | ABSTRACT |
| tr (32 bytes, pk hash) | `op share_tr_bytes` | `sk_tr_len = 32` | ABSTRACT |
| s1 (l-coord vec, bit-packed) | `op share_s1_bytes` | `sk_s1_len = 480` (ML-DSA-65) | ABSTRACT |
| s2 (k-coord vec, bit-packed) | `op share_s2_bytes` | `sk_s2_len = 576` | ABSTRACT |
| t0 (k-coord vec, bit-packed) | `op share_t0_bytes` | `sk_t0_len = 2304` | ABSTRACT |
| Concatenation = encode_sk | `op encode_sk` | `sk_len = 4032` | DEFINED |
| Encode/decode roundtrip | `axiom encode_decode_sk` | — | ABSTRACT (axiom) |
| Length identity | `lemma encode_sk_len` | — | PROVED |
| Well-formedness | `op wf_sk_bytes` | — | ABSTRACT |
| wf round-trip | `axiom decode_encode_sk_wf` | — | ABSTRACT (axiom) |

## §5 FIPS 204 §3.5.5 — Signature encoding

| FIPS 204 sig-component | EC op | Length | Status |
|---|---|---|---|
| c̃ (challenge digest) | `op encode_c_tilde` | `c_tilde_len = 32` | ABSTRACT |
| z (response, bit-packed) | `op encode_z` (in `MLDSA65_Functional`) | — | ABSTRACT |
| h (hint, bit-packed) | `op encode_h` | — | ABSTRACT |
| Concatenation = pack_signature | `op pack_signature` | `sig_size = 3309` (ML-DSA-65) | ABSTRACT |
| Signature codec roundtrip | `axiom encode_decode_signature` | — | ABSTRACT (axiom) |
| Pulsar N1 sig codec | `op pack_n1_signature` (in `Pulsar_N1.ec`) | — | ABSTRACT (with v4 roundtrip axiom) |
| Pack injectivity (derived) | `lemma pack_n1_signature_injective` | — | PROVED |

## §6 FIPS 204 §5.4.1 — ExternalMu derivation

| FIPS 204 | EC representation | Status |
|---|---|---|
| ExternalMu = `0x00 || \|ctx\| || ctx || M` | `op external_mu_layout m ctx = [0; size (context_bytes ctx)] ++ context_bytes ctx ++ message_bytes m.` (in `Pulsar_N1.ec`, v9) | DEFINED |
| Context-length byte (≤ 255) | `axiom context_bytes_len_bound : forall ctx, 0 <= size (context_bytes ctx) <= 255.` | ABSTRACT |
| SHAKE256(ExternalMu, 64) = μ | `op shake256_to_mu : mu_shake_input_t -> mu_t.` | ABSTRACT |
| μ derivation (full pipeline) | `op compute_mu m ctx = shake256_to_mu (external_mu_layout m ctx).` | DEFINED (v6+v9) |
| compute_mu injectivity | `axiom compute_mu_injective` | ABSTRACT (axiom) |

## §7 FIPS 204 §6.1 / §6.2 — Sign and Sign_internal

The full FIPS 204 §6.2 kappa rejection loop:
```
A ← ExpandA(ρ)
(s1, s2, t0) ← ExpandS(ρ′)
μ ← H(tr || M', 512)
ρ' ← H(K || rnd || μ, ...)
κ ← 0
while (z, h) = ⊥:
  y ← ExpandMask(ρ', κ)
  w ← A·y
  w1 ← HighBits(w)
  c̃ ← H(μ || w1Encode(w1))
  c ← SampleInBall(c̃)
  z ← y + c·s1
  r0 ← LowBits(w − c·s2)
  ct0 ← c·t0
  h ← MakeHint(−ct0, w − c·s2 + ct0)
  reject if ||z||∞ ≥ γ1−β or ||r0||∞ ≥ γ2−β or ||ct0||∞ ≥ γ2 or weight(h) > ω
```

EC counterpart (in `Pulsar_N1.ec`, post v10):
```ec
op sign_internal_loop (usk : unpacked_sk_t) (mu_val : mu_t)
                       (rho_rnd : randomness_t) : signature_t =
  let cz_h = run_signing_components usk mu_val rho_rnd in
  pack_n1_signature cz_h.`1 cz_h.`2 cz_h.`3.

op run_signing_components usk mu_val rho_rnd =
  (mldsa_compute_c_tilde usk mu_val rho_rnd,
   mldsa_compute_z usk mu_val rho_rnd,
   mldsa_compute_h usk mu_val rho_rnd).
```

Per-stage breakdown:

| FIPS 204 stage | EC op | Status |
|---|---|---|
| c̃ = H(μ \|\| w1Encode(w1)) (c_tilde) | `op mldsa_compute_c_tilde usk mu rnd = shake_mu_w1 mu (central_w1 usk mu rnd).` | DEFINED (v5+v6+v7) |
| w1 = HighBits(A·y) | `op central_w1 usk mu rnd = high_bits_of_w (central_w usk mu rnd).` | DEFINED (v7) |
| w = A·y at accepted κ | `op central_w` | ABSTRACT |
| HighBits structural | `op high_bits_of_w` | ABSTRACT |
| z = y + c·s1 | `op mldsa_compute_z` | ABSTRACT (sign-side, see §1.2 above) |
| h = MakeHint(...) | `op mldsa_compute_h usk mu rnd = make_hint_of_w (central_w ...) (central_w_low ...).` | DEFINED (v10) |
| w_low for MakeHint | `op central_w_low` | ABSTRACT (v10) |
| MakeHint structural | `op make_hint_of_w` | ABSTRACT (v10) |
| Rejection conditions R1–R4 | folded into `accept_signing_attempt` predicate | ABSTRACT |
| Acceptance probability | `op mldsa_accept_lower_bound : real` | ABSTRACT (operational bound) |

## §8 FROST-style threshold aggregation (FIPS 204 + threshold extension)

| Pulsar/FROST concept | EC op | Lean bridge | Status |
|---|---|---|---|
| Per-party partial response z_i = y_i + c·s_i | `op per_party_partial_response : c_tilde_n1_t -> randomness_t -> mu_t -> share_t -> partial_response_t.` | — | ABSTRACT (v8) |
| Lagrange aggregation at zero | `op lagrange_aggregate_responses : int list -> partial_response_t list -> z_n1_t.` | — | ABSTRACT (v8) |
| Threshold partial-response identity | `axiom threshold_partial_response_identity` | `Crypto.Threshold.Lagrange.threshold_partial_response_identity` (lean/Crypto/Threshold_Lagrange.lean:121) | Lean-bridged (v8) |
| Lagrange inverse at zero | `axiom lagrange_inverse_eval` | `Crypto.Pulsar.Shamir.shamir_correct_at_target` | Lean-bridged |
| Reconstruct (additive-linearity) | `axiom reconstruct_linear` (in Pulsar_N4) | `Crypto.Threshold.Lagrange.combine_distributes_over_sum` | Lean-bridged |
| Shamir correctness | `axiom shamir_correct` (in Pulsar_N4) | `Crypto.Pulsar.Shamir.shamir_correct_at_target` | Lean-bridged |
| Additive zero-right | `axiom add_share_zeroR` (in Pulsar_N4) | Mathlib `AddCommMonoid` | Lean-bridged |

## §9 Wire / layout — combine

| Layout component | EC op (in `Pulsar_N1_Combine_Layout.ec`) | Bytes | Status |
|---|---|---|---|
| c_tilde input pointer (read) | `op read_c_tilde` | `c_tilde_len = 32` | DEFINED |
| t0 vector pointer (read) | `op read_t0_vec` | `t0_len = 6144` | DEFINED |
| Round-2 messages | `op read_r2_msgs` | `response_bytes * n_parties` | DEFINED |
| Signature output pointer (write) | `op write_signature_at` | `sig_len = 3293` | DEFINED |
| Layout invariant | `op layout_combine_args` | — | DEFINED |
| Encode round-trip | `lemma encode_combine_args_layout` | — | PROVED |
| Pointer disjointness | `op pointers_well_separated` | — | DEFINED |

## §10 Wire / layout — sign

| Layout component | EC op (in `Pulsar_N1_Sign_Layout.ec`) | Status |
|---|---|---|
| ptr_sk (read sk) | `op read_sk` | DEFINED |
| ptr_m + m_len (read message) | `op read_msg` | DEFINED |
| ptr_signature (write sig) | `op write_sig_sign` | DEFINED |
| Layout invariant | `op layout_sign_args` | DEFINED |
| Encode round-trip | `lemma encode_sign_args_layout` | PROVED |
| Pointer disjointness | `op sign_pointers_well_separated` | DEFINED |

## §11 Verification (FIPS 204 §6.3)

| FIPS 204 | EC counterpart |
|---|---|
| ML-DSA.Verify | `op fips204_verify : bits -> bits -> bits -> bits -> bool.` in `MLDSA65_Functional.ec` — ABSTRACT |
| Pulsar verifier (Go) | `ref/go/pkg/pulsar/verify.go` — direct call to circl's `mldsa65.SignTo` verifier |

The Pulsar verifier is the FIPS 204 §6.3 verifier verbatim — no
Pulsar-specific envelope. This is the load-bearing claim of the
output-interchangeability theorem: any FIPS-validated ML-DSA
verifier accepts Pulsar signatures.

## §12 Per-axiom FIPS § citation

For each remaining primitive EC axiom, the corresponding FIPS 204 §:

| Axiom | FIPS 204 § | Notes |
|---|---|---|
| `combine_body_w_spec` | §6.2 (A·y at accepted κ) | extracted w match centralised |
| `sign_body_w_spec` | §6.2 | same, single-party |
| `combine_body_w_low_spec` | §3.4.2 (Decompose low bits) | new v10 |
| `sign_body_w_low_spec` | §3.4.2 | same |
| `sign_body_z_spec` | §6.2 (z = y + c·s1) | single-party |
| `combine_body_z_via_aggregation_spec` | §6.2 (threshold variant) | v8 |
| `combine_body_partial_responses_spec` | per-party FROST | v8 |
| `combine_body_mu_input_prefix_spec` | §5.4.1 (ExternalMu prefix) | v9 |
| `combine_body_mu_input_ctx_bytes_spec` | §5.4.1 (ctx bytes) | v9 |
| `combine_body_mu_input_m_bytes_spec` | §5.4.1 (M bytes) | v9 |
| `sign_layout_m_buffer_external_mu` | §5.4.1 | v9 |
| `*_no_reject_on_accepted_honest_layout` | §6.2 (acceptance probabilistic) | operational |
| `threshold_partial_response_identity` | §6.2 + FROST | Lean-bridged |
| `pack_unpack_n1_signature_roundtrip` | §3.5.5 (sigEncode roundtrip) | codec |
| Per-type codec axioms (~21) | §3.5.4, §3.5.5, §5.4.1 | codec layer |

## §13 ACVP/CAVP traceability

ACVP ML-DSA test categories (per NIST ACVP draft):

| ACVP category | Pulsar test vector file | EC theorem |
|---|---|---|
| ML-DSA.KeyGen | `vectors/keygen.json` | `Pulsar_N4.reshare_preserves_secret_honest` (extended to KeyGen) |
| ML-DSA.SigGen (deterministic) | `vectors/sign.json`, `vectors/threshold-sign.json` | `pulsar_n1_byte_equality_extracted` |
| ML-DSA.SigGen (randomized) | `vectors/sign.json` with rnd field | same theorem |
| ML-DSA.SigVer | `vectors/verify.json` | direct verifier call (no theorem needed) |
| Context boundary (0, 1, 255 bytes) | `test/negative/` | `context_bytes_len_bound` axiom |

External validation by an accredited ACVP-CAVP lab is required for
formal certification; this document supports the lab's test
selection.

---

**Document metadata**

- Name: `fips-204-traceability.md`
- Version: v1.0 (post v10)
- Date: 2026-05-18
- FIPS 204 version: NIST FIPS 204 (August 2024, final)
