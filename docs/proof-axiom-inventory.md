# AXIOM-INVENTORY — Pulsar EasyCrypt residual trust base

> **Standalone trust accounting** for the EasyCrypt N1 byte-equality
> theorem. Pairs with `proof-claims.md` (proof scope), `fips-204-traceability.md`
> (op→FIPS § map), and `tcb.md` (EC/Jasmin/OCaml TCB).
>
> Auditors should read this document first. Every axiom in the
> dependency cone of `Pulsar_N1_Extracted.pulsar_n1_byte_equality_extracted`
> is enumerated here with its full statement, location, closure
> plan, and current status.

## Trust footprint summary (after v8)

| Category | Count | Status |
|---|---|---|
| Stage-level byte-walk axioms | 3 | primitive — `sign_body_z_spec`, `combine_body_h_spec`, `sign_body_h_spec` |
| Narrow combine z extraction | 2 | primitive (v8) — `combine_body_z_via_aggregation_spec`, `combine_body_partial_responses_spec` |
| c_tilde dependency sub-stage | 2 | primitive — `combine_body_w_spec`, `sign_body_w_spec` |
| Codec layout (mu_input) | 2 | primitive — `combine_body_mu_input_spec`, `sign_body_mu_input_spec` (sign-side conversion to derived lemma underway in v9) |
| Accepted-path no-reject | 2 | primitive — `*_no_reject_on_accepted_honest_layout` |
| Lean-bridged algebraic | 5 | primitive in EC; mechanized in Lean Mathlib |
| Codec roundtrip (pack_n1) | 1 | primitive — `pack_unpack_n1_signature_roundtrip` |
| Per-type FIPS 204 codec roundtrips | ~21 | primitive — see §6 below |
| Derived lemmas (no longer primitive) | 7+ | derived via decomposition: `*_body_{c_tilde,mu,w1}_spec` × 2 sides + `combine_body_z_spec` |
| EC admit budget | **0 / 0** | hard-pinned by `scripts/checks/ec-admits.sh` |
| Lean ↔ EC bridge guards | **5 / 5** | hard-pinned by `scripts/check-lean-bridge.sh` |

**Counted ONE WAY** (which is the relevant audit framing): the
extracted N1 byte-equality theorem's dependency cone trusts ~36
named axioms across the categories above, plus the EC/Jasmin/OCaml
TCB. Each axiom is independently attackable; the next narrowing
step is named in the "closure plan" column.

## §1 Stage-level byte-walk axioms (3)

These are obligations on the extracted Jasmin / libjade procedures.
Each says "the extracted body's per-stage output value equals the
centralized FIPS 204 op's output on the corresponding inputs."

### §1.1 `sign_body_z_spec`

**File**: `proofs/easycrypt/Pulsar_N1_Sign_Refinement.ec`

**Statement**:
```ec
axiom sign_body_z_spec :
  forall mem_pre ptrs full,
    layout_sign_args mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_compute_z mem_pre ptrs
    = Pulsar_N1.mldsa_compute_z
        (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
        (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
        full.`sgn_rnd_n1.
```

**FIPS 204 §**: §6.2 (Sign_internal — kappa rejection loop output z)

**Closure plan**:
- Step 1: decompose into `sign_body_y_spec` + `sign_body_cs1_spec` +
  structural addition (matches v7 HighBits pattern).
- Step 2: bridge `sign_body_y_spec` to `expand_mask` + accepted-kappa
  selection.
- Step 3: bridge `sign_body_cs1_spec` to `sample_in_ball` + `vec_l_scale`.
- Total estimated effort: 2-3 weeks.

### §1.2 `combine_body_h_spec`

**File**: `proofs/easycrypt/Pulsar_N1_Combine_Refinement.ec`

**Statement**: extracted h-vector equals `mldsa_compute_h` on the
reconstructed share's inputs.

**FIPS 204 §**: §6.2 + §3.4.3 (MakeHint)

**Closure plan**:
- Decompose via `make_hint_of_w` structural split (`w_low` + `w_high`
  inputs to MakeHint as separate sub-axioms). Pattern from v7
  HighBits. Estimated: 1-2 weeks.

### §1.3 `sign_body_h_spec`

Symmetric to `combine_body_h_spec`; libjade single-party version.
Same closure plan.

## §2 Narrow combine z extraction (2 — v8 split)

### §2.1 `combine_body_z_via_aggregation_spec`

**File**: `proofs/easycrypt/Pulsar_N1_Combine_Refinement.ec`

**Statement**: the extracted combine's z output equals the Lagrange
aggregation of `combine_body_compute_partial_responses` over
`full.`full_quorum`.

**FIPS 204 §**: §6.2 (combine z-aggregation stage)

**Closure plan**: byte-walk through `combine.ec` lines 3460-3490
(round-2 aggregation loop) showing the extracted aggregation
matches the abstract `lagrange_aggregate_responses` op. Estimated:
3-5 days.

### §2.2 `combine_body_partial_responses_spec`

**File**: `proofs/easycrypt/Pulsar_N1_Combine_Refinement.ec`

**Statement**: per-party partial responses extracted from round-2
messages equal `per_party_partial_response` on the per-party share.

**FIPS 204 §**: per-party FROST-style `z_i = y_i + c · s_i`

**Closure plan**: byte-walk through round-2 message parsing in
extraction. Estimated: 1-2 weeks.

## §3 c_tilde dependency sub-stage axioms (2)

### §3.1 `combine_body_w_spec`

**Statement**: extracted w polynomial vector (BEFORE HighBits
decomposition) matches the centralized `central_w` on inputs.

**FIPS 204 §**: §6.2 (A·y at accepting kappa)

**Closure plan**: split into `expand_a` + `expand_mask` + `mat_vec_mul`
sub-axioms + accepted-kappa selection. Hardest remaining target.
Estimated: 3-4 weeks.

### §3.2 `sign_body_w_spec`

Symmetric. Same closure plan but no aggregation step.

## §4 Codec layout axioms (2)

### §4.1 `combine_body_mu_input_spec`

**File**: `proofs/easycrypt/Pulsar_N1_Combine_Refinement.ec`

**Statement**: protocol-witness mu_input bytes equal
`external_mu_layout(m, ctx)` (now a constructive byte-list per v9).

**FIPS 204 §**: §5.4.1 (ExternalMu layout)

**Closure plan**: cannot be fully closed without adding `m_ptr` /
`ctx_ptr` to combine layout (protocol-witness limitation). v9
decomposed into byte-range sub-axioms (prefix / ctx / m). Further
closure requires the threshold-protocol model that defines how the
witness ctx/m relate to memory contents.

### §4.2 `sign_body_mu_input_spec`

**File**: `proofs/easycrypt/Pulsar_N1_Sign_Refinement.ec`

**Status**: v9 — converted to DERIVED LEMMA. Replaced by narrower
byte-layout axiom `sign_layout_m_buffer_external_mu`. The
`sign_body_mu_input` op is now constructively defined via
`load_bytes mem ptrs.`ptr_m ptrs.`m_len`.

## §5 Accepted-path no-reject axioms (2)

### §5.1 `combine_no_reject_on_accepted_honest_layout`

**Statement**: under layout invariants + `accept_signing_attempt`
holds, `combine_body_compute_status = 0`.

**FIPS 204 §**: §6.2 (kappa rejection-loop convergence)

**Closure plan**: requires probabilistic Hoare-logic chain on the
kappa loop. Operationally bounded by `mldsa_accept_lower_bound`
(≈ 1 − 2^-128). Closure requires a kappa-loop model in EC.
Estimated: 4-6 weeks.

### §5.2 `sign_no_reject_on_accepted_honest_layout`

Symmetric. Same closure plan.

## §6 Lean-bridged algebraic axioms (5)

These are mechanized on the Lean side; the EC axioms are
hand-bridged via `proofs/lean-easycrypt-bridge.md` + the CI guard
`scripts/check-lean-bridge.sh`.

### §6.1 `lagrange_inverse_eval` (Pulsar_N1.ec)

**Lean**: `Crypto.Pulsar.Shamir.shamir_correct_at_target`
(`lean/Crypto/Pulsar/Shamir.lean`)

### §6.2 `add_share_zeroR` (Pulsar_N4.ec)

**Lean**: implicit in Mathlib's `AddCommMonoid` instance.

### §6.3 `reconstruct_linear` (Pulsar_N4.ec)

**Lean**: `Crypto.Threshold.Lagrange.combine_distributes_over_sum`

### §6.4 `shamir_correct` (Pulsar_N4.ec)

**Lean**: `Crypto.Pulsar.Shamir.shamir_correct_at_target`

### §6.5 `threshold_partial_response_identity` (Pulsar_N1.ec, v8)

**Lean**: `Crypto.Threshold.Lagrange.threshold_partial_response_identity`
(`lean/Crypto/Threshold_Lagrange.lean:121`)

**Closure plan for all 5**: either
- (a) port the relevant Mathlib polynomial-Lagrange theory into EC
  (multi-week), OR
- (b) build a checked Lean ↔ EC translation tool (multi-month
  research project — currently no such tool exists in published
  literature).

## §7 Codec axioms

### §7.1 `pack_unpack_n1_signature_roundtrip`

**File**: `proofs/easycrypt/Pulsar_N1.ec` (v4)

**Statement**: `unpack_n1_signature (pack_n1_signature c z h) = (c, z, h)`.

**FIPS 204 §**: §3.5.5 (sigEncode roundtrip)

**Closure plan**: concretize `pack_n1_signature` and `unpack_n1_signature`
to bit-level codecs matching `MLDSA65_Functional.pack_signature`
when that's mechanized.

### §7.2 Per-type FIPS 204 codec roundtrips (~21)

Across `Pulsar_N1_Signature_Codec.ec`, `Pulsar_N1_Sign_Layout.ec`,
`Pulsar_N1_Combine_Layout.ec`:

- `encode_decode_signature` + `encode_signature_len` + `encode_signature_wf`
- `encode_decode_sk` + `encode_sk_len` + `encode_sk_wf` + `decode_encode_sk_wf`
- `encode_decode_msg` + `encode_msg_len` + `encode_msg_wf`
- `encode_decode_c_tilde` + `encode_c_tilde_len`
- `encode_decode_t0` + `encode_t0_len`
- `encode_decode_r2_msg` + `encode_r2_msg_len`
- (and a handful of share-structure axioms: `share_polys_injective`,
  `poly_share_of_injective`, `poly_share_roundtrip`, etc.)

**Closure plan**: Barbosa-Barthe-Dupressoir-scale Dilithium codec
mechanization (CRYPTO 2023 paper template, ~6 person-months).

## §8 Counterpart concretization opportunities

For each abstract op currently held inside an axiom, the
concretization that would enable closure:

| Abstract op | Concretization needed |
|---|---|
| `message_t`, `ctx_t` | `= int list` (byte sequence) — adds `message_bytes` / `context_bytes` as proper byte serializers |
| `share_t` | `= R_q^l × R_q × bits × bits` per FIPS 204 §3.5.4 sk-structure |
| `signature_t` | already aliased to `Pulsar_N1_Signature_Codec.signature_t` — needs concrete byte-codec body |
| `unpacked_sk_t` | 6-tuple `(rho, K, tr, s1, s2, t0)` per FIPS 204 §3.5.4 |
| `mu_t`, `mu_shake_input_t` | `mu_t = int list` (64 bytes); `mu_shake_input_t = int list` (v9) ✓ done |
| `c_tilde_n1_t`, `z_n1_t`, `h_n1_t` | bit-level FIPS 204 §3.5.5 sig-component encodings |
| `w_value_t`, `w_low_value_t`, `w1_value_t` | `= vec_k` per `MLDSA65_Functional` |
| `partial_response_t` | `= (vec_l × ...)` per protocol-level partial response shape |
| `unpacked_sk_t`, `randomness_t` | concrete byte forms |

Once these are concretized, the structural identities can be proved
mechanically and the corresponding axioms collapse to lemmas.

## §9 What this trust footprint EXCLUDES

The audit cone of `pulsar_n1_byte_equality_extracted` does NOT
include:

- `MLDSA65_Functional.ec`'s internal abstract ops (`fips204_sign`,
  `sample_in_ball`, etc.) — those are abstracted at the bits-level
  but the corollary doesn't reach into them.
- The `combine_body_axiom` / `S_functional_spec` SECTION-LOCAL
  axioms inside `section ClassN1` in `Pulsar_N1.ec`. The extracted
  corollary instantiates the generic theorem with concrete wrapper
  modules + bridge lemmas, NOT via the section's declare-axiom
  hypotheses. The CI guard `scripts/checks/ec-refinement-scaffold.sh`
  reports these as warnings (informational) — they're not on the
  audit path.
- The EC / Jasmin / OCaml compiler trusted-computing base. See
  `tcb.md`.

## §10 Verification commands

```bash
# Full high-assurance gate (admit budget + Lean bridge + compile)
scripts/check-high-assurance.sh

# Admit budget enforcement (hard-pin 0/0)
scripts/checks/ec-admits.sh

# Lean bridge guard (5/5)
scripts/check-lean-bridge.sh

# Per-file EC compile (all 13)
scripts/checks/ec-compile.sh

# Refinement scaffold (declare-axiom hygiene)
scripts/checks/ec-refinement-scaffold.sh

# Retired-axiom regression guard
scripts/checks/ec-regressions.sh
```

All five must exit 0 for a clean trust accounting. Per-push CI
runs all five.

## §11 What an auditor should do

1. **Read** this document end-to-end.
2. **Verify** each axiom's statement matches the file:line it cites.
3. **Run** `scripts/check-high-assurance.sh` and confirm 0/0
   admits + 5/5 bridges + 13/13 compile.
4. **For each Lean-bridged axiom**, read the Lean theorem at the
   cited location and verify the correspondence in
   `proofs/lean-easycrypt-bridge.md`.
5. **For each byte-walk axiom**, read the extraction roadmap at
   `proofs/easycrypt/extraction/{combine,sign}-byte-walk-roadmap.md`
   to confirm the closure plan is concrete.
6. **Cross-check** the axiom count in this document against the
   raw count returned by:
   ```bash
   grep -rE "^axiom\s+\w" proofs/easycrypt/ | wc -l
   ```
   The numbers should match modulo internal sub-axioms not on the
   corollary cone (e.g., `MLDSA65_Functional`-internal axioms).

---

**Document metadata**

- Name: `proof-axiom-inventory.md`
- Version: v1.0 (post v8)
- Date: 2026-05-18
- Companion documents:
  - `proof-claims.md` (proof scope)
  - `fips-204-traceability.md` (op → FIPS §)
  - `tcb.md` (TCB)
  - `proofs/lean-easycrypt-bridge.md` (bridge correspondence)
  - `SUBMISSION.md` (cover sheet with same accounting)
