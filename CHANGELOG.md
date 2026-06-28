# CHANGELOG — Pulsar threshold ML-DSA

This file tracks substantive changes to the EasyCrypt proof
artifact, the spec, and the residual trust footprint. For
implementation-level changes see `git log`.

## v1.2.0 — TALUS threshold ML-DSA (one-round online; W-LEAK closed semi-honest)

TALUS is the threshold ML-DSA scheme on the two-round lattice kernel, adding
**one-round online signing** via three pillars: a dealerless Shamir **nonce
DKG**, the **CEF** (Carry Elimination Framework, distributed `w1`), and **CSCP**
(the CarryCompare secure-comparison protocol). Source:
`ref/go/pkg/pulsar/talus*.go`.

**PULSAR-V13-W-LEAK closed (semi-honest, simulation-proven).** Commit
`530c24e` lands the REAL CSCP secure-comparison circuit (bit-decompose +
carry-save `bitAdd` + prefix `bitLT` over BGW multiplication, validated
coefficient-exact against FIPS Decompose). On the production
`CEFComputeW1` → `cscpSecureHighBitsVec` path NO node forms `w0` or the full
commitment `w` even transiently — only three masked openings
(`{valid, maskC, w1}`) — proven leak-free by `TestCSCP_MultiNode_LeakFree`,
`TestCSCP_LeakFree_Structural`, and `TestCSCP_MaskOpen_HidesW`. HONEST SCOPE:
this is an in-process N-party SIMULATION (the harness holds all parties'
shares); the *algorithm* never reconstructs `w`/`w0`, faithfully proven, but
this is NOT yet a networked/deployed distributed MPC and the malicious-secure
layer is unbuilt.

- **Two profiles.** **Pulsar-TEE** (TEE-backed `w1` source) and **Pulsar-MPC**
  (honest-majority N ≥ 2T−1, enforced by `TalusMinPartiesMPC` / `newCSCPCtx` /
  `cscpSecureHighBitsVec` / `bgwMulShares`). The emitted signature is
  byte-identical across profiles.
- **Stock FIPS-204 verify.** A TALUS signature verifies byte-equal under the
  UNMODIFIED `cloudflare/circl` `mldsa65.Verify` / `mldsa87.Verify`
  (`TestTalus_MPC_EndToEnd_StockVerify`, `TestTalus_MPC_Mode87`).
- **Malicious deviation = liveness-only.** `FindHint` (recovers the FIPS hint
  from public `w' = A·z − c·t1·2^d`) + `TalusReleaseGate` (mandatory stock
  FIPS-204 verify; never releases a failed signature) bound any malicious CSCP
  deviation to abort/retry — never forge or leak
  (`TestCSCP_WrongW1_CaughtByFindHint`). This is the open **Residual A** (the
  CSCP malicious-secure / identifiable-abort layer + a networked,
  non-simulation MPC deployment).
- **KEYGEN is now DEALERLESS (RSS) — the dealer is dead at keygen (v0.6.0+).**
  Superseded the earlier "trusted-dealer / Residual B" status. Only the NAIVE
  additive lift is unreachable: a naive sum/Lagrange of N ≥ 2 `S_η` contributions
  has ℓ∞-support up to `N·η > η`, breaking BCC byte-validity (`‖c·s2‖∞ ≤ N·β > β`)
  — `naive_additive_seta_obstruction.go` returns `ErrDealerlessByteFIPSUnreachable`
  for THAT construction only, **not as a class impossibility**. The published
  escape is **Mithril short replicated secret sharing** (`mithril_rss.go`
  `MithrilRSSKeygen`): committee keygen with no dealer and no centralized
  reconstruction, whose group key signs under **stock unmodified** `mldsa65.Verify`
  (gold-proof at (t=8,n=8), (t=16,n=16), and all small committees `N≤6`;
  `accumulateSubset` per-subset reduction unblocks large committees, v0.6.3). The
  HYPERBALL 3-round signer (`mithril_rss_hyperball.go`) is the Mithril-native
  no-reconstruct signer over that key. **Scope:** standard-verifier-compatible is
  PROVEN; full FIPS-204 KeyGen-distribution-equivalence (simulation/hiding/
  abort-bias) remains a labeled residual. The dealerless **Corona** leg (Pedersen
  DKG over `R_q`) continues to carry permissionless-public safety alongside Pulsar
  in the Quasar AND-mode dual-PQ cert.

## v1.1.0 – v1.1.5 — BCC/CEF byte-equal threshold ML-DSA + honest-status hardening

The Boundary-Clearance-Condition (BCC) + Carry-Elimination (CEF)
no-reconstruct signing path: the hint is recovered from the **public**
`w' = A·z − c·t1·2^d` via `FindHint` (FIPS `UseHint`), no production code forms
`c·s2`/`c·t0`/`r0`, and the single-key BCC signature verifies byte-for-byte
under CIRCL + pq-crystals (ML-DSA-65/87). The leaking v0.3 `AlgebraicAggregate*`
path was deleted forward-only; PULSAR-V04-CTX (FIPS 204 §5.4 ctx-bound sign)
closed; and the proof-claim vocabulary was hardened to an honest two-model
framing (idealised reconstruct-then-sign vs the production no-leak residual
under a standard Module-LWE / Module-SIS reduction).

## v1.0.14 — v0.2 honesty rename (Algebraic → Transitional)

The v0.2 API previously named `Algebraic*` was materially
misleading: the file-header docstring claimed
`AlgebraicCombine is a pure function of public-only material;
no access to any party's seed share or the master ML-DSA private
key` while the implementation calls
`mldsaSign(setup.SkBytes, message, ...)` against the master sk
packed in `AlgebraicSetup.SkBytes`. The aggregator TCB at sign
time is therefore identical to v0.1 reconstruct-and-sign — only
the parties' side of the protocol is honestly algebraic.

v1.0.14 fixes the honesty defect without changing the algorithm:

**API rename (forward-only, no compat aliases):**

- `AlgebraicThresholdSigner` → `TransitionalThresholdSigner`
- `NewAlgebraicThresholdSigner` → `NewTransitionalThresholdSigner`
- `AlgebraicCombine` → `TransitionalAggregate`
- `AlgebraicSetup` → `TransitionalSetup`
- `AlgebraicRound1Message` → `TransitionalRound1Message`
- `AlgebraicRound2Message` → `TransitionalRound2Message`
- `DealAlgebraicShares` → `DealTransitionalShares`
- `ErrAlgRound1MACBad` → `ErrTransitionalRound1MACBad`
- `ErrAlgRound2MACBad` → `ErrTransitionalRound2MACBad`
- `ErrAlgRound2CommitBad` → `ErrTransitionalRound2CommitBad`
- `ErrAlgRestart` → `ErrTransitionalRestart`
- `ErrAlgNoSetup` → `ErrTransitionalNoSetup`
- All `TestV02_*` test functions renamed to `TestTransitional_*`.

**Honesty docstrings rewritten:**

- `threshold_v02.go` file header now opens with HONEST SCOPE
  declaring the aggregator-side SkBytes dependency.
- `TransitionalAggregate` docstring spells out the TCB equivalence
  with v0.1 at sign time.
- `TransitionalSetup` docstring declares SkBytes as the v0.2 TCB
  defect and the v0.3 graduation gate.
- `types.go` Signature docstring rewritten.
- `docs/deployment.md` v0.2 section rewritten with explicit
  "suitable / not suitable" deployment guidance and a v0.3
  milestone section.

**New load-bearing test:**

- `TestTransitional_DependsOnSkBytes` — runs the full Round1/Round2
  cycle then sets `setup.SkBytes = nil` and asserts
  `TransitionalAggregate` returns `ErrTransitionalNoSetup`. The
  test currently PASSES (because v0.2 indeed depends on SkBytes).
  When v0.3 ships and removes the SkBytes dependency, this test
  starts FAILING — that failure is the load-bearing red flag
  documenting the v0.3 graduation.

**Closure record (PULSAR-V03-1):**

- `BLOCKERS.md` entry `PULSAR-V03-1` (closed in v1.0.20, commit
  `023a3ed`) records the v0.3 algebraic-sign closure: port FIPS 204
  sign internals to polynomial-share arithmetic, drop SkBytes,
  rename `Transitional*` → `Algebraic*` (forward-only).

The wire protocol is byte-for-byte unchanged: protocol constants
(`PULSAR-ALG-*` customisation strings) are preserved so any
existing v0.2 test vectors continue to verify.

## v1.0.13

(See git log; v0.2 algebraic threshold wire shape — the rename
above retroactively documents the honesty caveat that should have
shipped with this tag.)

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

Per `docs/proof-axiom-inventory.md`. This is NOT a count-reduction — it is a
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

- `SUBMISSION.md` — NIST MPTC cover sheet (updated with Tier-1/2/3 labels + patent posture cross-ref; absorbed prior one-page executive summary)
- `docs/patents.md` — royalty-free patent grant + defensive termination + claim summary
- `docs/proof-axiom-inventory.md` — per-axiom residual trust accounting with closure plans
- `docs/proof-claims.md` — narrow EC/Lean refinement claim with explicit non-claims
- `docs/fips-204-traceability.md` — op/lemma → FIPS 204 § map (ACVP/CAVP-ready)
- `docs/tcb.md` — EC/Jasmin/OCaml/Lean TCB with per-layer risk
- `docs/patent-claims.md` — 21 numbered claim drafts (5 claim groups) for attorney review
- `docs/evaluation.md` — experimental evaluation report per NIST IR 8214C §6

### Adjacent tracks (each routes through its own work stream)

- κ-loop probabilistic Hoare model — `mldsa_accept_lower_bound` ≈ 1 − 2⁻¹²⁸ tracks the operational bound per the standard FIPS 204 treatment.
- Full bit-level FIPS 204 codec mechanisation — Barbosa-Barthe-Dupressoir Dilithium template (CRYPTO 2023).
- Lean ↔ EC checked translation tooling — research artifact.
- ACVP / CAVP algorithm validation certificate — accredited-lab track.
- FIPS 140-3 module validation — accredited-lab track on a packaged crypto module.
- Threshold SLH-DSA (Tier 3) — Magnetar research track at `docs/magnetar.md`.
- Optimised Rust / C / WASM bindings — downstream binary packaging (Tier 1 priorities in `docs/roadmap.md`).
- External cryptographic audit — scoped post-submission alongside reviewer feedback.

### What this submission DOES claim (precise)

> Under the trusted-computing base in `docs/tcb.md`
> and the residual axioms enumerated in `docs/proof-axiom-inventory.md`, every
> signature byte string produced by the Pulsar Combine procedure on
> inputs satisfying the protocol's threshold-interpolation
> well-formedness invariants is bit-identical to a signature
> produced by single-party FIPS 204 ML-DSA-65 Sign on the
> Lagrange-reconstructed group secret.

This is an implementation-correctness result. It does NOT prove
post-quantum hardness of ML-DSA itself; ML-DSA hardness is inherited
from NIST FIPS 204's analysis. See `docs/proof-claims.md` for the
explicit framing.

### Scope boundary (per `BLOCKERS.md` closed-finding registry)

- Identifiable abort under network partition: synchronous model only; asynchronous attribution routes through the consensus-layer accountability artifact.
- 1-round signing: FIPS 204 rejection sampling precludes a 1-round threshold variant under any NIST-standard preprocessing oracle.
- DKG bias resistance under collusion: deployments bind a randomness beacon at the chain layer.
- Cross-committee reshare without external state binding: deployments bind the reshare epoch to consensus-layer state.

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
