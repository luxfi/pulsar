# CHANGELOG — Pulsar threshold ML-DSA

This file tracks substantive changes to the EasyCrypt proof
artifact, the spec, and the residual trust footprint. For
implementation-level changes see `git log`.

## v0.1.0 (target tag: `submission-2026-11-16`)

### Proof artifact progression (v4 → v11)

| Version | SHA | Change | Trust-footprint effect |
|---|---|---|---|
| v4 | `2eae979` | byte-walk: factor through pack_n1_signature | Component-triple axioms with codec roundtrip in `Pulsar_N1.ec` |
| v4b | `564a330` | per-stage split | 2 component-triple → 6 stage-level axioms; broader surface but per-FIPS-stage |
| v5 | `58af7b4` | c_tilde stage decomposition | `*_body_c_tilde_spec` → derived lemmas via mu + w1 sub-axioms |
| v5a | `01025bc` | docs: c_tilde refactor is decomposition not closure | wording correction |
| v6 | `18d01af` | mu sub-stage decomposed via SHAKE/byte-layout | `*_body_mu_spec` → derived lemmas |
| v7 | `76eae80` | w1 sub-stage via HighBits structural split | `*_body_w1_spec` → derived lemmas |
| v7b | `1bcb1eb` | PQ security validation framework (6 evidence layers) | docs framing |
| v8 | `835c176` | combine z-stage via Lean Lagrange bridge | `combine_body_z_spec` → derived lemma; new Lean-bridged `threshold_partial_response_identity` |
| v9 base | `01bdbc3` | mu_shake_input_t = int list concretization | constructive prep |
| v9 + v10 | `83e3c38` | 3-agent parallel: sign mu_input close + combine mu_input decomp + h-stage MakeHint bridge | `*_body_{mu_input,h}_spec` → derived lemmas |
| v10 docs | `ec14c79` | full submission package: PATENTS + AXIOM-INVENTORY + PROOF-CLAIMS + FIPS-TRACEABILITY + TRUSTED-COMPUTING-BASE + NIST-SUBMISSION + docs/evaluation + docs/patent-claims | submission-grade documentation |
| v11 sign z | `02c29f2` | sign z-stage via z = y + c·s1 structural split | `sign_body_z_spec` → derived lemma; 2 new sub-axioms `sign_body_y_spec` + `sign_body_cs1_spec` |
| v11 codec | `81da17b` | signature_t concretization as record wrapping int list | **3 codec axioms ELIMINATED** (real closure, not decomposition) |
| v12 w_spec | `02798c7` | w-stage via ExpandA + ExpandMask + mat_vec_mul structural split | `*_body_w_spec` × 2 → derived lemmas; 4 new sub-axioms (matrix_a + mask_y on each side) |
| v13 accept | `02798c7` | per-R1/R2/R3/R4 accept bridge axiom (no-reject decomposition prep) | +1 bridge axiom (`accept_signing_attempt_iff_R1234`) connects bundled predicate to 4 per-R conditions without breaking downstream tactics |

### Derived lemmas added (previously primitive axioms)

After v10, the following primitive axioms have been converted to
derived lemmas (the original obligation now follows from narrower
sub-axioms + structural composition):

- `combine_body_c_tilde_spec`, `sign_body_c_tilde_spec` (v5)
- `combine_body_mu_spec`, `sign_body_mu_spec` (v6)
- `combine_body_w1_spec`, `sign_body_w1_spec` (v7)
- `combine_body_z_spec` (v8 — Lean-bridged)
- `combine_body_mu_input_spec`, `sign_body_mu_input_spec` (v9)
- `combine_body_h_spec`, `sign_body_h_spec` (v10)
- `sign_body_z_spec` (v11 — z = y + c·s1 structural split)
- `combine_body_w_spec`, `sign_body_w_spec` (v12 — A·y structural split)

Total: 14 axioms re-classified into derived lemmas across v5–v13.

### Actual axiom eliminations (v11 codec, real closure)

In addition to the 12 re-classifications above, v11 also delivered
3 PRIMITIVE AXIOM ELIMINATIONS in `Pulsar_N1_Signature_Codec.ec`
(no replacement axiom on that path — concretized `signature_t` as
a record wrapper):

- `encode_decode_signature` (removed)
- `decode_encode_signature_wf` (removed)
- `encode_signature_wf` (kept, narrowed to a length-only axiom)
- `encode_signature_len` → DERIVED via record-wrap structure

3 axioms eliminated from the codec layer.

### Trust-footprint structure (post v10)

Per `AXIOM-INVENTORY.md`. This is NOT a count-reduction — it is a
re-classification of formerly broad obligations into narrower,
independently-attackable sub-obligations:

- 1 stage-level byte-walk (sign z only — combine z moved to Lean bridge path)
- 2 c_tilde dependency w sub-stage (combine + sign)
- 2 c_tilde dependency w_low sub-stage (combine + sign, v10)
- 2 combine z extraction (v8 — aggregation shape + per-party PR)
- 4 codec mu_input layout (v9 — combine 3 per-range + sign byte-layout)
- 2 accepted-path no-reject (combine + sign)
- 5 Lean-bridged algebraic (v8 added threshold_partial_response_identity)
- 1 + ~21 codec roundtrip
- EC admit budget hard-pinned at 0/0

### Gate properties maintained throughout

- 13/13 EC files compile clean
- jasmin-ct 3/3 blocking on threshold layer (round1, round2, combine)
- Lean ↔ EC bridge guard 5/5
- Admit budget 0/0
- Lean bridge doc + check-script entry per bridged axiom
- Refinement scaffold (no stray `declare axiom`) clean

### Submission documentation added (v10)

- `SUBMISSION.md` — NIST MPTC cover sheet (updated with Tier-1/2/3 labels + patent posture cross-ref)
- `NIST-SUBMISSION.md` — one-page executive summary
- `PATENTS.md` — royalty-free patent grant + defensive termination + claim summary
- `AXIOM-INVENTORY.md` — per-axiom residual trust accounting with closure plans
- `PROOF-CLAIMS.md` — narrow EC/Lean refinement claim with explicit non-claims
- `FIPS-TRACEABILITY.md` — op/lemma → FIPS 204 § map (ACVP/CAVP-ready)
- `TRUSTED-COMPUTING-BASE.md` — EC/Jasmin/OCaml/Lean TCB with per-layer risk
- `docs/patent-claims.md` — 21 numbered claim drafts (5 claim groups) for attorney review
- `docs/evaluation.md` — experimental evaluation report per NIST IR 8214C §6

### Out-of-scope for v0.1 (roadmap, see `NIST-SUBMISSION.md` §Roadmap)

- Full κ-loop probabilistic Hoare model (multi-week)
- Full bit-level FIPS 204 codec mechanization (multi-month, Barbosa-Barthe-Dupressoir scale)
- Lean ↔ EC checked translation tooling (multi-month research)
- ACVP/CAVP algorithm validation certificate (lab work)
- FIPS 140-3 module validation (downstream)
- Threshold SLH-DSA experimental profile (Tier 3, not in v0.1)
- Production Rust / C / WASM implementations (Tier 1 priorities for v0.2+)
- External cryptographic audit (engagement TBD)

### What this submission DOES claim (precise)

> Under the trusted-computing base in `TRUSTED-COMPUTING-BASE.md`
> and the residual axioms enumerated in `AXIOM-INVENTORY.md`, every
> signature byte string produced by the Pulsar Combine procedure on
> inputs satisfying the protocol's threshold-interpolation
> well-formedness invariants is bit-identical to a signature
> produced by single-party FIPS 204 ML-DSA-65 Sign on the
> Lagrange-reconstructed group secret.

This is an implementation-correctness result. It does NOT prove
post-quantum hardness of ML-DSA itself; ML-DSA hardness is inherited
from NIST FIPS 204's analysis. See `PROOF-CLAIMS.md` for the
explicit framing.

### Known limitations (per `BLOCKERS.md`)

- No identifiable abort under network partition (synchronous only)
- No 1-round signing (FIPS 204 rejection sampling precludes)
- DKG bias resistance under collusion requires external randomness beacon
- v0.1 cross-committee reshare without external state binding is not supported

---

## v0.0 (pre-MPTC submission)

Initial reference implementation + spec, prior to the v4 byte-walk
factoring work. See `git log` for early commit history.

---

**Document metadata**

- Name: `CHANGELOG.md`
- Date: 2026-05-18
- Versioning: this file tracks proof-artifact and submission-package
  versions; the production code library will eventually have its own
  semver.
