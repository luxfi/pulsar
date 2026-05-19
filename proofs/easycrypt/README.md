# Pulsar — EasyCrypt theories

This directory holds the **EasyCrypt** theories for Pulsar's
high-assurance track. EasyCrypt
(https://github.com/EasyCrypt/easycrypt) is the machine-checked
proof assistant for cryptographic protocols paired with Jasmin
(`../../jasmin/`). The libjade single-party ML-DSA-65 EasyCrypt
theories are imported from `../../jasmin/ml-dsa-65/libjade/`
(fetched on demand); the Pulsar-specific theories live here.

## Headline

The high-assurance stack is now structurally ready for final
mechanized closure. All local EasyCrypt theorem bodies are
admit-free, per-push gates are green, threshold Jasmin CT is
blocking, fuzz / KAT / interop / dudect gates are wired at
documented budgets, and the extracted N1 theorem has no
section-local module-contract axioms. The only remaining
implementation-refinement assumptions are **two localized
byte-walk axioms** over pure signature output, each with a
committed proof roadmap. The Lean↔EC algebraic bridge is named,
cited, and CI-guarded.

The next proof-count milestone is `combine_body_compute_sig_spec`:
closing it reduces the implementation-refinement cone from 2 to 1.

## Status — current trust boundary

| Item | Count |
|---|---|
| Section-local module-contract axioms in extracted N1 corollary | **0** |
| Localized implementation-refinement axioms in dependency cone | **2** |
| Lean-bridged algebraic axioms (Lagrange/Shamir) | **4** |
| EasyCrypt `admit` budget | **0 / 0** |
| EC files in the per-push gate | **13** |
| `declare axiom` in refinement scaffolds | **0** |

The 2 remaining implementation-refinement axioms are byte-walks
over the pure signature output of the extracted Jasmin
procedures:

- `Pulsar_N1_Combine_Refinement.combine_body_compute_sig_spec`
  (tracked #4; roadmap in
  `extraction/combine-byte-walk-roadmap.md`)
- `Pulsar_N1_Sign_Refinement.sign_body_compute_sig_spec`
  (tracked #3; roadmap in `extraction/sign-byte-walk-roadmap.md`;
  ghost contract for ctx/rho_rnd documented in the named block
  inside `Pulsar_N1_Sign_Refinement.ec`)

The 4 Lean-bridged axioms are the Shamir / Lagrange algebraic
identities that EasyCrypt's first-order theory does not natively
cover. Each corresponds 1:1 to a proved Lean theorem in
`~/work/lux/proofs/lean/Crypto/`; the correspondence is named
inline (see comments preceding the axioms in `Pulsar_N1.ec` and
`Pulsar_N4.ec`) and operationally guarded by
`../../scripts/check-lean-bridge.sh`. See
`../lean-easycrypt-bridge.md` for the full correspondence table.

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
| `Pulsar_N1_Combine_Refinement.ec` | Combine refinement scaffold: `combine_full_args_t` ghost args, `combine_abs_op` definition, the one remaining byte-walk axiom (combine_body_compute_sig_spec), derived lemmas |
| `Pulsar_N1_Sign_Refinement.ec` | Sign refinement scaffold: `sign_full_args_t` (ghost ctx/rho_rnd contract block), `sign_abs_op` definition, the one remaining byte-walk axiom, derived lemmas |
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
- `extraction/combine-byte-walk-roadmap.md` — combine byte-walk
  sub-step decomposition (10 sub-claims)
- `extraction/sign-byte-walk-roadmap.md` — sign byte-walk
  sub-step decomposition (7 sub-claims)
- `../../ct/jasmin-ct-libjade.md` — libjade jasmin-ct issue
  write-up (tracked #2)
