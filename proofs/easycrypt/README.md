# Pulsar — EasyCrypt theories

This directory holds the **EasyCrypt** theories for Pulsar's
high-assurance track. EasyCrypt
(https://github.com/EasyCrypt/easycrypt) is the machine-checked
proof assistant for cryptographic protocols paired with Jasmin
(`../../jasmin/`). The libjade single-party ML-DSA-65 EasyCrypt
theories are imported from `../../jasmin/ml-dsa-65/libjade/`
(fetched on demand); the Pulsar-specific theories live here.

## Headline

The high-assurance stack is structurally ready for final
mechanized closure. All local EasyCrypt theorem bodies are
admit-free, per-push gates are green, threshold Jasmin CT is
blocking, fuzz / KAT / interop / dudect gates are wired at
documented budgets, and the extracted N1 theorem has no
section-local module-contract axioms in scope. The remaining
trust is split into narrow per-stage byte-walks, per-range
codec-layout axioms, two no-reject companions, one codec
round-trip, and the Lean↔EC algebraic bridge.

The composition theorem `combine_body_compute_sig_spec` (combine)
and `sign_body_compute_sig_spec` (sign) are themselves
**proved lemmas** (`Pulsar_N1_Combine_Refinement.ec:893`,
`Pulsar_N1_Sign_Refinement.ec:776`); the earlier per-side
headline "one byte-walk axiom per side" no longer holds. Both
have been decomposed into the narrower stage-level family below
through versions v4 (per-stage) → v12 (matrix_a + mask_y).

## Status — current trust boundary

| Item | Count |
|---|---|
| Section-local module-contract axioms in extracted N1 corollary | **0** |
| Implementation-refinement axioms in dependency cone (combine + sign + Pulsar_N1 codec) | **17** |
| Lean-bridged algebraic axioms (Lagrange / Shamir / linearity / threshold partial response) | **5** |
| EasyCrypt `admit` budget | **0 / 0** |
| EC files in the per-push gate | **13** |
| `declare axiom` in refinement scaffolds | **0** |

Authoritative source: the accounting block at
`Pulsar_N1_Extracted.ec:34-92` and the per-file accounting
blocks at the end of each `*_Refinement.ec`.

### Implementation-refinement axioms — combine side

`Pulsar_N1_Combine_Refinement.ec`:

| Axiom | Line | Category |
|---|---|---|
| `combine_body_mu_input_prefix_spec` | 504 | codec layout (FIPS 204 §5.4.1 prefix bytes) |
| `combine_body_mu_input_ctx_bytes_spec` | 517 | codec layout (ctx-bytes slice) |
| `combine_body_mu_input_m_bytes_spec` | 531 | codec layout (M-bytes suffix) |
| `combine_body_matrix_a_spec` | 616 | w-stage sub-axiom (matrix A) |
| `combine_body_mask_y_spec` | 629 | w-stage sub-axiom (mask y at accepting kappa) |
| `combine_body_z_via_aggregation_spec` | 725 | z-stage structural (Lagrange aggregation shape) |
| `combine_body_partial_responses_spec` | 745 | z-stage byte-walk (per-party PR extraction) |
| `combine_body_w_low_spec` | 810 | h-stage sub-axiom (w_low decompose output) |
| `combine_no_reject_on_accepted_honest_layout` | 950 | accepted-path status = 0 companion |

### Implementation-refinement axioms — sign side

`Pulsar_N1_Sign_Refinement.ec`:

| Axiom | Line | Category |
|---|---|---|
| `sign_layout_m_buffer_external_mu` | 510 | wrapper byte-layout (load_bytes ↔ external_mu) |
| `sign_body_matrix_a_spec` | 560 | w-stage sub-axiom (matrix A) |
| `sign_body_mask_y_spec` | 570 | w-stage sub-axiom (mask y at accepting kappa) |
| `sign_body_y_spec` | 649 | z-stage sub-axiom (central y at accepting kappa) |
| `sign_body_cs1_spec` | 662 | z-stage sub-axiom (c · s1 mixed product) |
| `sign_body_w_low_spec` | 704 | h-stage sub-axiom (w_low decompose output) |
| `sign_no_reject_on_accepted_honest_layout` | 826 | accepted-path status = 0 companion |

### Implementation-refinement axiom — Pulsar_N1 codec round-trip

`Pulsar_N1.ec`:

| Axiom | Line | Category |
|---|---|---|
| `pack_unpack_n1_signature_roundtrip` | 817 | FIPS 204 §3.5.5 packed-signature codec round-trip |

### Lean-bridged algebraic axioms

Each axiom below is stated in EasyCrypt and discharged by a
proved Lean theorem in `~/work/lux/proofs/lean/Crypto/`. The
correspondence is pinned in `../lean-easycrypt-bridge.md` and
operationally guarded by `../../scripts/check-lean-bridge.sh`.

| EC axiom | EC file:line | Lean theorem |
|---|---|---|
| `lagrange_inverse_eval` | `Pulsar_N1.ec:339` | `Crypto/Pulsar/Shamir.lean::shamir_correct_at_target` |
| `add_share_zeroR` | `Pulsar_N4.ec:155` | structural (Mathlib `AddCommMonoid`) |
| `reconstruct_linear` | `Pulsar_N4.ec:162` | `Crypto/Threshold_Lagrange.lean::combine_distributes_over_sum` |
| `shamir_correct` | `Pulsar_N4.ec:176` | `Crypto/Pulsar/Shamir.lean::shamir_correct_at_target` (different specialization) |
| `threshold_partial_response_identity` | `Pulsar_N1.ec:789` | `Crypto/Threshold_Lagrange.lean::threshold_partial_response_identity` |

The composite-stage axioms `*_body_{c_tilde,mu_input,mu,w,w1,z,h}_spec`,
`combine_body_compute_components_spec`, `combine_body_compute_sig_spec`,
`combine_body_spec`, `combine_body_separation` (and the sign-side
mirrors) are **derived lemmas** in the current source — see each
file's accounting block for the version where the decomposition
landed (v3 → v12).

Strict closure is not reached. Every other obligation —
module contracts, wrapper bridges, memory-frame separations,
layout-correctness conjuncts, ABI bridge identities — has been
collapsed to a lemma or eliminated by the structural decomplect.

## Files

Layered structure (each file owns one concern; the dependency
graph is acyclic and explicit):

| File | Concern |
|---|---|
| `Pulsar_N1.ec` | Class N1 protocol-level spec: abstract types, Pulsar_Threshold + MLDSA65_Sign module types, FIPS204Sign + CombineAbs modules, generic `pulsar_n1_byte_equality` theorem (inside `section ClassN1`) |
| `Pulsar_N4.ec` | Class N4: public-key preservation across proactive resharing (committee rotation) |
| `Pulsar_N1_Memory.ec` | Byte-memory model: `mem_t`, load/store primitives + proved frame laws. No axioms |
| `Pulsar_N1_Signature_Codec.ec` | FIPS 204 §3.5.5 signature codec: `signature_t`, encode/decode/length, memory read/write + proved frame lemmas |
| `Pulsar_N1_Combine_Layout.ec` | Combine ABI: c_tilde / t0 / r2_msg wire types + encoders, `combine_ptrs_t`, `layout_combine_args`, proved `encode_combine_args_layout` |
| `Pulsar_N1_Sign_Layout.ec` | libjade Sign ABI: sk + message wire types + encoders, `sign_ptrs_t`, `layout_sign_args`, proved `encode_sign_args_layout` |
| `Pulsar_N1_Combine_Refinement.ec` | Combine refinement scaffold: `combine_full_args_t` ghost args, `combine_abs_op` definition, the narrow byte-walk + codec-layout axiom family enumerated above, derived `combine_body_{c_tilde,mu_input,mu,w,w1,z,h,compute_components,compute_sig,spec,separation}` lemmas |
| `Pulsar_N1_Sign_Refinement.ec` | Sign refinement scaffold: `sign_full_args_t` (ghost ctx/rho_rnd contract block), `sign_abs_op` definition, the narrow byte-walk + codec-layout axiom family enumerated above, derived `sign_body_{c_tilde,mu_input,mu,w,w1,z,h,compute_components,compute_sig,spec,separation}` lemmas |
| `Pulsar_N1_Combine_Wrapper.ec` | Combine wrapper module + bridge lemma + procedure-level equiv against `CombineAbs` |
| `Pulsar_N1_Sign_Wrapper.ec` | Sign wrapper module + bridge lemma + procedure-level equiv against `FIPS204Sign` |
| `Pulsar_N1_Extracted.ec` | Composition: the concrete extracted N1 byte-equality corollary (applies `Pulsar_N1.pulsar_n1_byte_equality` with the two wrapper-bridge equivs) |
| `lemmas/MLDSA65_Functional.ec` | FIPS 204 ML-DSA-65 functional ops (pack_signature, sample_in_ball, expand_a, etc.) |
| `lemmas/Pulsar_CT.ec` | Constant-time obligations under the Barthe–Grégoire–Laporte leakage model |

Dependency layering:

```
Pulsar_N1 ──┐
            │
Memory ── Signature_Codec
   │              │
   ├── Combine_Layout      Sign_Layout
   │      │                    │
   │      Combine_Refinement   Sign_Refinement
   │          │                    │
   │      Combine_Wrapper       Sign_Wrapper
   │          │_________ Extracted ____│
   │
   └── (Pulsar_N1: protocol types + module types + generic theorem)
```

`Sign_Layout` no longer transitively depends on combine-specific
encoders. The two layouts are siblings sharing Memory +
Signature_Codec.

## Conventions

- `admit` is banned (budget 0/0; enforced by
  `../../scripts/checks/ec-admits.sh`).
- `declare axiom` is banned in refinement scaffolds (enforced by
  `../../scripts/checks/ec-refinement-scaffold.sh`).
- Lean-bridged axioms carry an inline citation comment naming the
  Lean theorem and file (enforced by
  `../../scripts/check-lean-bridge.sh`).
- Per-push gate is real-budget: `../../scripts/check-high-assurance.sh`
  runs every check at the budget that matters (jasmin-ct, EC
  admit budget, EC regression guards, refinement-scaffold guard,
  Lean bridge guard, Jasmin→EC extraction, EC compile). No smoke
  gates.
- Real-budget dudect (10⁹ samples per target) + 1h-per-target
  fuzz run from the nightly gate: `../../scripts/nightly.sh`.

## How to check

Per-push:

```bash
../../scripts/check-high-assurance.sh    # proof gate
../../scripts/test.sh                    # Go test gate
```

Nightly (multi-hour, cron-scheduled):

```bash
../../scripts/nightly.sh
```

Per-check (independently runnable):

```bash
bash ../../scripts/checks/ec-compile.sh
bash ../../scripts/checks/jasmin.sh
bash ../../scripts/checks/ec-admits.sh
bash ../../scripts/check-lean-bridge.sh
# ... etc, see scripts/checks/
```

## Citations

- Barthe, Grégoire, Laporte. *Secure compilation of side-channel
  countermeasures: The case of cryptographic constant-time.* CSF 2018.
- Barbosa, Barthe, Doczkal, Don, Fehr, Grégoire, Huang, Hülsing,
  Lee, Wu. *Fixing and Mechanizing the Security Proof of
  Fiat–Shamir with Aborts and Dilithium.* CRYPTO 2023.
- Almeida et al. *Formally verifying Kyber.* CRYPTO 2024.
- libjade ML-DSA EasyCrypt theories —
  https://github.com/formosa-crypto/libjade/tree/main/proof

## Cross-references

- `../lean-easycrypt-bridge.md` — Lean↔EC axiom correspondence
  table
- `extraction/combine-byte-walk-roadmap.md` — historical
  combine-side sub-step decomposition (the original
  `combine_body_compute_sig_spec` axiom; closed at
  `Pulsar_N1_Combine_Refinement.ec:893`)
- `extraction/sign-byte-walk-roadmap.md` — historical sign-side
  sub-step decomposition (the original
  `sign_body_compute_sig_spec` axiom; closed at
  `Pulsar_N1_Sign_Refinement.ec:776`)
- `../../ct/jasmin-ct-libjade.md` — libjade jasmin-ct issue
  write-up (tracked #2)
