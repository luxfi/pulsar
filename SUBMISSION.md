# NIST MPTC Submission — Pulsar

This document is the cover sheet for the Pulsar submission to the
NIST Multi-Party Threshold Cryptography (MPTC) project. It is written
for NIST reviewers and points at every artifact a reviewer needs.

The `pulsar` repository is the **single canonical home** for the
submission: it carries the Go reference implementation under
`ref/go/pkg/pulsar/`, the cover sheet, the LaTeX spec, the high-
assurance proof artifacts (EasyCrypt, Lean bridge, Jasmin), the
KAT vector format, the constant-time evidence, and the tarball-cut
tooling. There is exactly one canonical implementation, exactly one
canonical spec, and exactly one canonical proof set. A NIST reviewer
gets a self-contained checkout that does not require network access.

The repository is **active** (not frozen). The submission tarball is
cut from a tag on `main` at NIST's deadline via
`scripts/cut-submission.sh`; reviewer feedback and post-submission
patches land in this same repository so the artifact chain stays
auditable.

**Date stamp (this revision): 2026-05-18.**

**Maturity stamp**: v0.1 ready. This submission is **not**
NIST-ratified, **not** FIPS 140-3 validated, **not** ACVP-validated.
It is the algorithm-level reference plus reproducibility tooling
plus high-assurance proof artifacts. ACVP/CAVP/FIPS 140-3 are
downstream of this submission (see §"Layer 4" below).

## At a glance

| Field | Value |
|---|---|
| Submission name | **Pulsar** |
| Submitting organisation | Lux Industries, Inc. |
| Algorithm | Threshold ML-DSA-65 (Module-LWE, FIPS 204-aligned) |
| Target NIST MPTC classes | **N1** (single-party-compatible threshold signing) + **N4** (multi-party key generation with public-key preservation across resharing) |
| Underlying primitive | FIPS 204 ML-DSA-65 |
| Round count | 2 rounds per signature |
| Signature output | **Byte-identical** to single-party FIPS 204 ML-DSA-65 |
| Repository | <https://github.com/luxfi/pulsar> (single canonical home: code, spec, proofs, KAT, cut tool) |
| Algorithm source | Same repository, `ref/go/pkg/pulsar/` (canonical Go reference). Tagged `v1.0.7` (commit `174941a`) is the cited stable release at this revision. |
| Tarball cut tool | `scripts/cut-submission.sh` (tags from `main`, regenerates KATs, snapshots vendor tree, tars) |
| Submission tag | `submission-YYYY-MM-DD` (cut from `main` at deadline) |
| Spec PDF | `spec/pulsar.pdf` (built via `scripts/build.sh`) |
| License | Apache-2.0 (code) — see `LICENSE` |
| Patent posture | **Royalty-free grant** — see `docs/patents.md` (public-facing grant text) and `docs/patent-claims.md` (attorney-prep claim drafts). Lux Industries grants a worldwide, royalty-free, irrevocable patent license to any FIPS 204 ML-DSA-conformant implementation under Apache-2.0 or compatible OSI license, OR any NIST MPTC / PQC / ACVP submission, validation, or interoperability test. Defensive termination mirrors Apache-2.0 §3 and extends to all NIST-standardized PQ signature schemes. |
| Tier | **Tier 1**: Threshold ML-DSA-65 (this submission). **Tier 2**: SLH-DSA (FIPS 205) single-party compatibility — consume the FIPS 205 reference directly. **Tier 3**: Threshold SLH-DSA — research-only track at `docs/magnetar.md`. |

## Headline claim

> Every signature produced by a Pulsar threshold ceremony
> (DKG → Round-1 → Round-2 → Combine) is **bit-identical** to a signature
> produced by single-party FIPS 204 ML-DSA-65 on the same message and
> group public key.

This is the **Class N1** claim. A FIPS-validated ML-DSA verifier
(BoringSSL FIPS, AWS-LC, OpenSSL 3.0 PQ provider) accepts a Pulsar
signature without modification.

> **Two-variant disclosure.** The submission ships **both** the v0.1
> reveal-and-aggregate flow (the runnable Go reference + KAT vectors
> + 19/19 N1 interop subtests) AND the v0.2 FSwA Lagrange-linearity
> flow (the Jasmin sources type-check against this; EasyCrypt N1
> reduction is stated against this). Both variants produce a FIPS 204
> byte-equal `σ = (c̃, z, h)`. v0.1 carries a documented
> reconstruction-aggregator trust caveat (the aggregator briefly
> reassembles the master ML-DSA seed in memory via `KeyFromSeed`,
> zeroized on every exit per `ref/go/pkg/pulsar/zeroize.go`); v0.2
> avoids the reconstruction via Lagrange-linearity but is not yet the
> reference runtime. See `BLOCKERS.md` "Spec ↔ Go-reference protocol
> drift" for full disclosure and the per-deployment guidance in
> `docs/cryptographer-sign-off.md` §Gates GATE-1. The Class N1 byte-equality
> theorem in EasyCrypt is stated and proved against the centralized recovery
> model; both wire variants emit `σ = (c̃, z, h)` byte-equal to single-party
> FIPS 204.

**Theorem framing — accepted-path correctness.** The Class N1
byte-equality theorem is conditional on acceptance: *if* the threshold
combine (and the single-party comparator) accepts — i.e., passes the
ML-DSA norm and rejection checks and the kappa rejection-sampling loop
converged — *then* the produced byte string equals the centralized
ML-DSA-65 signature on the same protocol-level inputs, under the
stated layout, algebraic, and byte-walk assumptions. Acceptance
probability is tracked separately through the `accept_signing_attempt`
predicate and the `mldsa_accept_lower_bound` operational bound; ML-DSA
rejection sampling remains probabilistic per FIPS 204, and the
deterministic EC model captures the accepted-path conditioning via
the predicate rather than via probabilistic Hoare logic.

Cross-validation evidence: every KAT vector in `vectors/` is verified
by three independent ML-DSA implementations
(`test/interoperability/`):

1. The canonical Pulsar reference implementation at
   `github.com/luxfi/pulsar` v1.0.7 (commit `174941a`), pinned via
   `go.mod` and snapshotted into `vendor/` at tarball-cut time
2. The FIPS 204 reference (pq-crystals Dilithium C reference)
3. A third independent implementation (`cloudflare/circl` FIPS 204
   verifier; BoringSSL FIPS or OpenSSL 3.0 PQ provider when available)

## Algorithm scope and audit-response closure

The algorithm being submitted is the merged Pulsar implementation
at `luxfi/pulsar` v1.0.7 (commit `174941a`). v1.0.6 consolidated the
prior submission-grade implementation back into the production
canonical library; v1.0.7 ported the identity-stage uniformity to
the large-committee GF(q) path so a single Go module is both
production and submission across both committee-size paths.

The following audit-response items are **closed on both the
small-committee (≤256, GF(257)) and large-committee (>256, GF(q))
paths** as of v1.0.7:

| ID | Issue | Resolution |
|---|---|---|
| CR-6 | DKG round-1 commit was vacuous | Removed. Each party's coefficient commitment is now bound to the long-term identity public key and to the DKG session identifier. Small path closed in v1.0.6; large path closed in v1.0.7. |
| CR-7 | Threshold-sign session keys were absent | Each (sender, receiver, session-id, transcript) quadruple derives a fresh 32-byte session key from the authenticated ML-KEM-768 + HKDF stage; per-pair `SymmetricSession`. Small path closed in v1.0.6; large path closed in v1.0.7 (`legacyDeriveMACKeyLarge` removed). |
| CR-8 | DKG and reshare envelopes shipped in plaintext | Envelopes are now KEM-wrapped (ML-KEM-768) and authenticated under the long-term ML-DSA-65 identity key. Identity layer at `pulsar.GenerateIdentity` / `IdentityKey` / `IdentityDirectory` is mandatory. Small path closed in v1.0.6; large path closed in v1.0.7 via uniform `sealEnvelope` / `sealOpenEnvelope` slice API. |

**Committee-size coverage**: v1.0.7 makes both paths uniform under
the identity stage. KAT vectors in `vectors/` exercise the
small-committee path (n ≤ 10, t ≤ 7 in the threshold-sign sweep;
n ≤ 7 in the DKG sweep); the large-committee path has its own
test suite (`large_e2e_test.go`, `largeshamir_test.go`) but no
committed KAT vectors in this submission package. KAT vectors are
byte-identical between v1.0.6 and v1.0.7 because the large-path
changes do not touch the small-committee byte stream.

**Proof artifact counts (algorithm v1.0.7)**:

| Artifact | Count | Location |
|---|---|---|
| EasyCrypt files compiling clean, 0/0 admits | 13/13 | `proofs/easycrypt/` (gate: `scripts/checks/ec-compile.sh` + `scripts/checks/ec-admits.sh`) |
| Lean ↔ EC bridge files (algebraic identities) | 5/5 | `~/work/lux/proofs/lean/Crypto/` + `proofs/lean-easycrypt-bridge.md` (gate: `scripts/check-lean-bridge.sh`) |
| jasmin-ct blocking targets on the threshold layer | 3/3 | `jasmin/threshold/{round1,round2,combine}.jazz` (gate: `scripts/checks/jasmin.sh`) |

These artifact counts continue to refer to the merged Pulsar
implementation at v1.0.7; the proof artifacts themselves live in
`./{proofs/easycrypt, jasmin}/` and are unaffected by
the merge or the v1.0.6 → v1.0.7 large-committee identity-stage
port (the algebraic identities the proofs cover are independent
of the envelope-encryption layer).

## What to read first

A reviewer with limited time should read in this order:

1. **`SUBMISSION.md`** (this file) — submission cover sheet, metadata, headline claim
2. **`spec/pulsar.pdf`** — full algorithm specification
   - §1 Introduction + §2 System model
   - §3 Parameters (ML-DSA-44 / 65 / 87)
   - §4 Protocol (DKG, Round-1, Round-2, Combine, Reshare)
   - §5 Security games (EUF-CMA threshold, identifiable abort)
   - §6 Output-interchangeability proof (the Class N1 claim)
   - §7 NIST MPTC category mapping
3. **`docs/proof-claims.md`** — what's proved vs what's not (narrow claim)
4. **`docs/proof-axiom-inventory.md`** — residual EC trust base, per-axiom closure plan
5. **`docs/tcb.md`** — EC/Jasmin/OCaml TCB
6. **`docs/fips-204-traceability.md`** — op/lemma → FIPS 204 § map
7. **`docs/evaluation.md`** — performance + correctness + CT + sec-param evidence
8. **`docs/patents.md`** — royalty-free patent grant text
9. **`README.md`** — repository layout and how to reproduce
10. **`vectors/README.md`** — KAT format + cross-validation gates
11. **`BLOCKERS.md`** — closed-finding registry (Open: none); each
    closure cites commit + tag. Includes the PULSAR-V03-1 v1.0.20
    ExpandA-convention fix and the v0.1 / v0.2 / v0.3 wire-variant
    disclosure
12. **`docs/cryptographer-sign-off.md`** — independent cryptographer
    review (APPROVED WITH GATES) covering construction soundness,
    proof-artifact verification, test surface, and the four
    pre-publish disclosure gates

## What to run

The reproducibility gate is `scripts/build.sh` against the tarball
extract — the entire submission is self-contained, so no network
access is required:

```bash
tar xzf submission-YYYY-MM-DD.tar.gz
cd pulsar
scripts/build.sh          # builds Go ref + spec PDF
scripts/test.sh           # runs unit + KAT + interoperability tests
scripts/bench.sh          # produces signature/verification benchmarks
scripts/gen_vectors.sh    # regenerates KAT vectors (deterministic)
```

`scripts/build.sh` exits non-zero on any failure. CI runs the same
script on every commit; the reproducibility property is the load-
bearing one for the submission.

To cut a fresh tarball (maintainer-side):

```bash
scripts/cut-submission.sh                       # dry-run, no tarball
scripts/cut-submission.sh submission-2026-11-16 # production cut + tag
```

The cut script verifies a clean tree, verifies all proof gates are
green, regenerates the KATs from the in-tree canonical implementation,
re-runs the round-trip replay tests, tars the entire submission
checkout, and prints the SHA-256.

## What's in this package

```
./
├── SUBMISSION.md            # this file
├── README.md                # repository layout + how to use
├── LICENSE                  # Apache-2.0
├── SECURITY.md              # threat model + responsible disclosure
├── CONTRIBUTING.md          # external-contribution policy (post-submission)
├── go.mod                   # module: github.com/luxfi/pulsar
├── spec/                    # LaTeX specification source
│   ├── pulsar.tex           # main spec document
│   ├── parameters.tex       # ML-DSA-44/65/87 parameter sets
│   ├── system-model.tex     # threshold network / adversary model
│   ├── security-games.tex   # EUF-CMA + identifiable-abort games
│   ├── references.bib       # bibliography
│   └── pulsar.pdf           # built PDF (committed for reviewer convenience)
├── ref/go/                  # canonical Go reference implementation
│   ├── pkg/pulsar/          # canonical algorithm sources (this is what
│   │                        #   is being submitted)
│   └── cmd/genkat/          # KAT vector generator (imports ref/go/pkg/pulsar)
├── vectors/                 # KAT test vectors
│   ├── README.md
│   ├── dkg.json             # DKG transcripts
│   ├── keygen.json          # key-generation vectors
│   ├── sign.json            # single-party signing vectors (for cross-validation)
│   ├── threshold-sign.json  # threshold-signing vectors
│   ├── verify.json          # FIPS 204 verification vectors
│   └── transcripts/         # full-protocol KATs per (n, t) sweep
├── test/
│   ├── negative/            # malformed-input + protocol-deviation tests
│   ├── interoperability/    # cross-validation with FIPS 204 verifiers
│   └── fuzz/                # fuzz harnesses (Go native)
├── ct/dudect/               # constant-time analysis (dudect statistical tests)
├── bench/                   # benchmark configurations
├── estimator/               # security-parameter estimator
├── jasmin/                  # high-assurance Jasmin sources (initial track)
│   ├── ml-dsa-65/           #   libjade single-party baseline (fetched on demand)
│   └── threshold/           #   Pulsar threshold layer (stubs)
├── proofs/easycrypt/        # high-assurance EasyCrypt theories (13 files)
│   ├── Pulsar_N1.ec                       # Class N1 protocol spec + generic theorem
│   ├── Pulsar_N4.ec                       # Class N4 reshare pk-preservation
│   ├── Pulsar_N1_Memory.ec                # byte-memory model (0 axioms)
│   ├── Pulsar_N1_Signature_Codec.ec       # FIPS 204 sig codec
│   ├── Pulsar_N1_{Combine,Sign}_Layout.ec # per-side ABI byte layout
│   ├── Pulsar_N1_{Combine,Sign}_Refinement.ec # per-side byte-walk refinement scaffold
│   ├── Pulsar_N1_{Combine,Sign}_Wrapper.ec    # per-side wrapper module + bridge lemma
│   ├── Pulsar_N1_Extracted.ec             # concrete extracted N1 corollary
│   ├── lemmas/MLDSA65_Functional.ec       # FIPS 204 functional ops
│   └── lemmas/Pulsar_CT.ec                # constant-time obligations
├── proofs/lean-easycrypt-bridge.md        # Lean↔EC algebraic-bridge correspondence
├── scripts/                 # per-push + nightly gate orchestrators
│   ├── check-high-assurance.sh, test.sh   # per-push (REAL — under 60s)
│   ├── nightly.sh                         # cron-scheduled REAL-budget gate
│   ├── cut-submission.sh                  # tarball cut
│   ├── checks/                            # per-check independent scripts
│   └── build / bench / gen_vectors / SBOM / extract-jasmin-ec
└── docs/                    # design notes + decision-record archive
```

## Class N1 — Output interchangeability

The N1 claim is asserted at four levels of evidence:

| Evidence | Where |
|---|---|
| Algorithmic argument | `spec/pulsar.tex` §6, Theorem 6.1 |
| Symbolic / Lean proof | `proofs/lean/Crypto/Pulsar/OutputInterchange.lean` (out-of-repo, separate audit artifact) |
| Test harness | `test/interoperability/` runs every KAT through 3 independent verifiers |
| Cross-implementation KATs | `vectors/sign.json` shares vectors with FIPS 204 reference |

## Class N4 — Public-key preservation across resharing

Multi-party proactive resharing preserves the group public key across
committee rotations (epoch boundaries), so a single long-lived public
identity persists while the secret-share custodians rotate.

| Evidence | Where |
|---|---|
| Algorithmic argument | `spec/pulsar.tex` §4.5 (Reshare protocol) |
| Symbolic / Lean proof | `proofs/lean/Crypto/Pulsar/Shamir.lean` (Shamir + ring extension) |
| Test harness | `vectors/transcripts/n*-t*-reshare.jsonl` carry pre/post-reshare public keys + verify both verify under unmodified ML-DSA |

## High-assurance track (Jasmin + EasyCrypt)

Pulsar ships with a Jasmin + EasyCrypt high-assurance track aimed at
the same formal-method footing libjade gives the single-party ML-DSA
implementation: Jasmin sources whose verified compiler produces
bit-identical assembly, and EasyCrypt theories that machine-check
both functional correctness and constant-time against the
Barthe-Grégoire-Laporte leakage model.

The EasyCrypt track is **not theory shells** — every lemma in the
13-file tree is closed (admit budget enforced 0/0; see
`scripts/checks/ec-admits.sh`). What remains in the dependency cone
of the extracted N1 byte-equality theorem is a small, localized
axiom set:

| Artifact | Status | Location |
|---|---|---|
| libjade ML-DSA-65 single-party baseline (Jasmin + EasyCrypt) | Verified upstream; pinned, fetched on demand | `jasmin/ml-dsa-65/fetch.sh` |
| Pulsar Round-1 commit (Jasmin) | Implemented (~400 lines) | `jasmin/threshold/round1.jazz` |
| Pulsar Round-2 response (Jasmin) | Implemented (~600 lines) | `jasmin/threshold/round2.jazz` |
| Pulsar Combine (Jasmin) | Implemented (~400 lines) | `jasmin/threshold/combine.jazz` |
| Jasmin → EC extraction sanity | Per-push gate | `scripts/checks/extraction.sh` |
| jasmin-ct threshold (round1, round2, combine) | **BLOCKING — green** | `scripts/checks/jasmin.sh` |
| jasmin-ct libjade sign | Allowed-failure under #2 (precise write-up: `ct/jasmin-ct-libjade.md`) | same |
| Class N1 byte-equality (concrete extracted corollary) | **Proven as a lemma** (`pulsar_n1_byte_equality_extracted`) — composes the per-side wrapper-bridge equivs | `proofs/easycrypt/Pulsar_N1_Extracted.ec` |
| Class N1 byte-equality (generic, parametric) | **Proven as a theorem** (`pulsar_n1_byte_equality`) inside `section ClassN1` | `proofs/easycrypt/Pulsar_N1.ec` |
| Class N4 public-key preservation | **Proven** (concrete `ReshareHonest` module + `reshare_preserves_secret_honest` lemma) | `proofs/easycrypt/Pulsar_N4.ec` |
| Wrapper bridges (combine + sign) | **Proven as lemmas** (both — neither is an axiom) | `Pulsar_N1_{Combine,Sign}_Wrapper.ec` |
| Body separation (combine + sign) | **Proven as lemmas** | `Pulsar_N1_{Combine,Sign}_Refinement.ec` |
| Memory frame laws | **Proven** (0 axioms) | `Pulsar_N1_Memory.ec` |
| Build wiring | Per-check orchestrator; per-check scripts independently runnable | `scripts/check-high-assurance.sh` |

**Trust footprint of the extracted N1 corollary** — **22 named axioms total**,
each with file:line in EC and Lean. The c_tilde stage has been decomposed and
structurally factored: every top-level c_tilde byte-walk obligation is a
derived lemma; trust localises into strictly narrower sub-axioms aligned
to concrete FIPS 204 computation boundaries.

| Category | Count | Notes |
|---|---|---|
| Stage-level byte-walks (post v12) | 1 | `sign_body_z_spec` (the only stage-level byte-walk that survives the v8 / v11 / v12 splits) |
| w-stage matrix_a / mask_y sub-axioms (v12) | 4 | combine + sign × {matrix_a, mask_y} |
| Combine-side z extraction (v8) | 2 | `combine_body_z_via_aggregation_spec` (aggregation shape) + `combine_body_partial_responses_spec` (per-party byte-walk) |
| w_low sub-axioms (h-stage, v10) | 2 | `{combine,sign}_body_w_low_spec` |
| Codec mu_input layout (v9) | 4 | combine: 3 per-range; sign: 1 collapsed `sign_layout_m_buffer_external_mu` |
| Accepted-path no-reject | 2 | `{combine,sign}_no_reject_on_accepted_honest_layout` |
| Codec roundtrip | 1 | `pack_unpack_n1_signature_roundtrip` |
| Subtotal — implementation refinement | **17** | byte-walk + codec round-trip + honest-execution no-reject |
| Lean-bridged algebraic (v8) | 5 | `lagrange_inverse_eval`, `reconstruct_linear`, `shamir_correct`, `add_share_zeroR`, `threshold_partial_response_identity` |
| **Total named axioms** | **22** | each with file:line in EC and Lean |
| Derived c_tilde / mu / w / w1 / h / combine_z lemmas | 11+ | `*_body_{c_tilde,mu,w,w1,mu_input,h}_spec` × 2 sides + `combine_body_z_spec` |

**v8 — combine z-stage Lean-bridged**: `combine_body_z_spec` is no
longer a primitive axiom; it is a derived lemma composing two
narrower combine-side facts (`combine_body_z_via_aggregation_spec`
on the aggregation shape, `combine_body_partial_responses_spec` on
per-party byte-walk) with the Lean Lagrange theorem
`Crypto.Threshold.Lagrange.threshold_partial_response_identity`
(`lean/Crypto/Threshold_Lagrange.lean:121`). The Lean theorem's
preconditions (uniq quorum, size match, polynomial degree bound,
honest sharing — collectively the **threshold interpolation
well-formedness** bundle) are now propagated as preconditions of
`pulsar_n1_byte_equality` and `pulsar_n1_byte_equality_extracted`.
The first two conjuncts (`uniq quorum`, `size shares = size quorum`)
were already present in the wrapper context; v8 threads the
remaining two (degree bound, honest evaluation) through to the
top-level equivalence statements so the bridge backstops the
derivation.

This is not full mechanized closure of the z stage. Trust has
moved from one stage-level byte-walk axiom (combine z) to one
narrower partial-response extraction axiom (a byte-walk) plus a
proven Lean theorem (the algebra). The next narrow target on this
side is `combine_body_partial_responses_spec` itself — a byte-walk
proving that the round-2 messages decode to per-party
`per_party_partial_response` values.

Detail on the 22 named axioms — the live source for the per-axiom
file:line is `docs/proof-axiom-inventory.md`. Summary by category:

- **Stage-level byte-walk (1)**: `sign_body_z_spec`. Combine's z-stage
  is a derived lemma composing `combine_body_z_via_aggregation_spec`
  + `combine_body_partial_responses_spec` with the Lean Lagrange
  bridge `threshold_partial_response_identity`.
- **w-stage matrix_a / mask_y sub-axioms (4)** at the accepting kappa,
  per FIPS 204 §6.2: `{combine,sign}_body_matrix_a_spec` and
  `{combine,sign}_body_mask_y_spec`. The HighBits step is a structural
  definition on both sides (`Pulsar_N1.high_bits_of_w`), so
  `*_body_w1_spec` is derived, and `*_body_c_tilde_spec` composes via
  `shake256_to_mu` + the v5 SHAKE composition.
- **Combine z extraction (2)**: `combine_body_z_via_aggregation_spec`
  (aggregation shape) + `combine_body_partial_responses_spec` (per-party
  byte-walk). With the Lean bridge, `combine_body_z_spec` is derived.
- **w_low sub-axioms for the h-stage (2)**: `{combine,sign}_body_w_low_spec`.
  Both `*_body_h_spec` are derived via `make_hint_of_w` structural
  composition.
- **ExternalMu codec layout (4)**: combine side carries three per-range
  sub-axioms over the protocol-witness buffer
  (`combine_body_mu_input_{prefix,ctx_bytes,m_bytes}_spec` per FIPS 204
  §5.4.1); sign side carries one collapsed
  `sign_layout_m_buffer_external_mu` because sign owns `m_ptr`/`ctx_ptr`
  in its layout. `*_body_mu_spec` are derived via `shake256_to_mu`.
- **Codec round-trip (1)**: `pack_unpack_n1_signature_roundtrip`
  in `Pulsar_N1.ec` — `unpack_n1_signature (pack_n1_signature c z h) =
  (c, z, h)` per FIPS 204 §3.5.5.
- **Honest-execution no-reject (2)**:
  `combine_no_reject_on_accepted_honest_layout` and
  `sign_no_reject_on_accepted_honest_layout`. Each conditions
  `status = 0` on the protocol-level `accept_signing_attempt`
  predicate; the kappa rejection-sampling probability bound
  `mldsa_accept_lower_bound` (≈ 1 − 2^-128 after the κ-bounded
  loop) is tracked operationally per the standard FIPS 204 treatment.
- **Lean-bridged algebraic (5)**: `lagrange_inverse_eval`
  (`Pulsar_N1.ec`), `add_share_zeroR` / `reconstruct_linear` /
  `shamir_correct` (`Pulsar_N4.ec`), and
  `threshold_partial_response_identity` (`Pulsar_N1.ec`, v8). Each
  carries an inline citation comment naming the Lean theorem and
  file; the bridge correspondence is pinned in
  `proofs/lean-easycrypt-bridge.md` and enforced by
  `scripts/check-lean-bridge.sh`.

Beyond the corollary cone: ~21 per-type FIPS 204 codec round-trip
axioms across `Pulsar_N1_Sign_Layout`, `Pulsar_N1_Combine_Layout`,
`Pulsar_N1_Signature_Codec`, and `Pulsar_N1` — encode/decode pairs
guarded by `wf_*` well-formedness predicates with per-component
length identities (sk: ρ/K/tr/s1/s2/t0 per FIPS 204 §3.5.4) and
share-polynomial-vector views. Each reduces to the corresponding
`MLDSA65_Functional` bit-level pack/unpack identity; the Barbosa-
Barthe-Dupressoir Dilithium mechanization (CRYPTO 2023) is the
template path.

**0 section-local module-contract axioms** in the extracted
corollary's cone — the corollary uses the concrete wrapper modules
plus proved bridge lemmas, never the section's declare-axiom
hypotheses.

What this gives the NIST reviewer at submission time:

1. The libjade single-party verified baseline as the kernel under
   Pulsar's threshold layer — real, machine-checked, citable.
2. Real Jasmin sources for all three threshold-layer routines that
   call into the pinned libjade kernel.
3. The Class N1 byte-equality theorem **proven** in EasyCrypt as
   `pulsar_n1_byte_equality_extracted`, instantiating the generic
   `pulsar_n1_byte_equality` with concrete wrapper modules. Trust
   reduces to **22 named axioms** (17 implementation-refinement: 14
   byte-walk + 1 signature-codec round-trip + 2 honest-execution
   no-reject; plus 5 Lean-bridged algebraic), each with file:line in
   EC and Lean. Per-axiom enumeration: `docs/proof-axiom-inventory.md`.
   The composite `*_body_{c_tilde,mu,w,w1,mu_input,h}_spec` lemmas and
   `combine_body_z_spec` are derived; the structural identity layer
   `Pulsar_N1.high_bits_of_w` is a shared definition, not an axiom.
4. The Class N4 reshare-preservation theorem **proven** as a
   concrete lemma on `ReshareHonest`.
5. jasmin-ct **blocking** on the threshold layer (round1, round2,
   combine all CT-clean); libjade sign advisory with a documented
   fix path.

Each of the 22 axioms is independently attackable through the per-
axiom closure plan in `docs/proof-axiom-inventory.md`. Sub-step
roadmaps with named obligations live under
`proofs/easycrypt/extraction/{combine,sign}-byte-walk-roadmap.md`.

`scripts/check-high-assurance.sh` runs every per-push EC + jasmin-ct
+ extraction-sanity + bridge-guard + admit-budget + regression-guard
check at real budget. `scripts/nightly.sh` runs the heavier 1-hour
fuzz + 10⁹-sample dudect runs; results check into `ct/dudect/results/`.

## Path toward full mechanized closure

The Class N1 byte-equality theorem is **proved as a lemma** in
EasyCrypt. The trust footprint reduces to the 22 named axioms
enumerated in `docs/proof-axiom-inventory.md`, the ~21 per-type
FIPS 204 codec round-trips, and the EasyCrypt / Jasmin / OCaml
TCB in `docs/tcb.md`. Each axiom is independently attackable.

### Per-axiom closure paths

| Axiom | Closure path |
|---|---|
| `combine_body_partial_responses_spec` | Byte-walk through round-2 message parsing in extraction; mirrors `per_party_partial_response`. |
| `combine_body_z_via_aggregation_spec` | Structural identity through `Pulsar_N1.lagrange_aggregate_responses`. |
| `{combine,sign}_body_matrix_a_spec`, `{combine,sign}_body_mask_y_spec` | BArray ↔ R_q polynomial-view bridge through `expand_a` / `expand_mask`. |
| `{combine,sign}_body_w_low_spec` | Mirror lemma through `decompose_vec_k` low-bits. |
| `sign_body_y_spec`, `sign_body_cs1_spec` | `expand_mask` + accepted-κ selection / `sample_in_ball` + `vec_l_scale`. |
| `sign_body_z_spec` | y + c·s1 structural composition through `mldsa_compute_z`. |
| `{combine,sign}_body_mu_input_*_spec`, `sign_layout_m_buffer_external_mu` | FIPS 204 §5.4.1 byte-layout proof; per-range slice arithmetic. |
| `{combine,sign}_no_reject_on_accepted_honest_layout` | κ-rejection-loop model conditioned on `accept_signing_attempt`. The operational bound `mldsa_accept_lower_bound` (≈ 1 − 2⁻¹²⁸) tracks the probability per the standard FIPS 204 treatment. |
| `pack_unpack_n1_signature_roundtrip` | Bridge to `MLDSA65_Functional.pack_signature`. |
| 5 Lean-bridged algebraic | Either port the Mathlib polynomial-Lagrange theory into EC, or build a checked Lean ↔ EC translation artifact. |
| ~21 per-type FIPS 204 codec round-trips | Concretize abstract types against `MLDSA65_Functional` bit-level ops, Barbosa-Barthe-Dupressoir (CRYPTO 2023) template. |

### What full mechanized closure would buy

The Pulsar N1 byte-equality reduces purely to the verified libjade
Jasmin compilation pipeline plus the FIPS 204 standard text — no
hand-bridged identities, no operational probability bounds, no
abstract op surfaces. The trust footprint composes to: **trust the
published FIPS 204 standard and the Jasmin verified compiler, and
you trust every Pulsar signature.**

## PQ security validation — evidence layers

A compiling EasyCrypt proof is **one layer** of PQ security
validation, not the whole story. NIST FIPS 204 standardizes ML-DSA
for digital signatures and states that it is believed secure even
against adversaries with a large-scale quantum computer
(<https://csrc.nist.gov/pubs/fips/204>). A submission claim of
"post-quantum secure threshold ML-DSA" needs evidence across six
layers:

### Layer 1 — Algorithm-level PQ strength (assumed, not proved here)

| Item | This submission |
|---|---|
| Algorithm | ML-DSA (FIPS 204) — not pre-standard Dilithium |
| Parameter set | **ML-DSA-65** (NIST security category 3) |
| Claimed strength | Inherits the NIST ML-DSA-65 hardness analysis (Module-LWE / Module-SIS) |
| Hash/XOF usage | SHAKE128 / SHAKE256 per FIPS 204 |
| Encoding | pk / sk / sig / μ / w1 / z / h match FIPS 204 §3.5–§5.4 |
| Rejection sampling | Distribution and acceptance behavior per FIPS 204 §6.2 |
| Domain separation | Context string + pre-hash mode + message binding per FIPS 204 §5.4.1 ExternalMu |

The claim is: **this implementation targets FIPS 204 ML-DSA-65
semantics, assuming the ML-DSA-65 hardness assumptions and NIST
security-category analysis.** It is **not** a lattice-hardness
proof — the EasyCrypt refinement chain is an *implementation
correctness* result.

### Layer 2 — Implementation correctness (this is where the EC proof lives)

Refinement chain:

```
machine code / Jasmin / extracted implementation
  refines
low-level EasyCrypt model (Pulsar_N1_{Combine,Sign}_Refinement.ec)
  refines
centralized ML-DSA functional model (MLDSA65_Functional.ec)
  conforms to
FIPS 204 ML-DSA algorithm
```

Evidence delivered:

| Area | Evidence |
|---|---|
| EasyCrypt compile | `scripts/checks/ec-compile.sh` — 13/13 files, 0/0 admits |
| Axiom inventory | This document (residual trust base, below) |
| Derived lemmas | `*_body_c_tilde_spec`, `*_body_mu_spec`, `*_body_w1_spec`, `*_body_compute_{components,sig}_spec`, `*_body_{spec,separation}` — all no longer primitive |
| FIPS traceability | Per-axiom mapping below; per-op MLDSA65_Functional bridges |
| Extraction/model gap | Abstract ops `central_w`, `high_bits_of_w`, `shake_mu_w1`, `shake256_to_mu`, `external_mu_layout`, `pack_n1_signature` named with FIPS §-refs |
| Test vectors | `vectors/` directory (KAT format); cross-validated against `cloudflare/circl` FIPS 204 verifier in `test/interoperability/` (19/19 N1 subtests PASS); ACVP/CAVP cross-validation is downstream lab work |
| Differential testing | `test/interoperability/` — 3 independent ML-DSA verifiers |
| Negative tests | `test/negative/` — malformed inputs, boundary cases |

**Primitive EasyCrypt trust base after v7:**

| Axiom | Category | FIPS section | Residual risk | Closure plan |
|---|---|---|---|---|
| `combine_body_w_spec` | byte-walk / polynomial | §6.2 | A·y at accepted κ + threshold aggregation | split into ExpandA, ExpandMask, mat_vec_mul + Lean Lagrange bridge for combine |
| `sign_body_w_spec` | byte-walk / polynomial | §6.2 | A·y at accepted κ | split into ExpandA, ExpandMask, mat_vec_mul |
| `combine_body_z_spec` | **DERIVED LEMMA (v8)** | §6.2 | n/a | replaced by `combine_body_partial_responses_spec` + `threshold_partial_response_identity` Lean bridge |
| `combine_body_z_via_aggregation_spec` | byte-walk / aggregation shape (v8) | §6.2 | extracted z's Lagrange shape | mechanical structural identity |
| `combine_body_partial_responses_spec` | byte-walk / per-party PR (v8) | §6.2 | per-party z_i extraction | narrow byte-walk through round-2 message parsing |
| `threshold_partial_response_identity` | Lean-bridged algebraic (v8) | §6.2 (FROST) | Lagrange-interpolation response identity | discharged in `lean/Crypto/Threshold_Lagrange.lean:121` |
| `sign_body_z_spec` | byte-walk / response | §6.2 | y + c·s1 at accepted κ | reduce via vec ops + accepted-κ model |
| `combine_body_h_spec` | byte-walk / hints | §6.2 | MakeHint over aggregated w_low/w_high | bridge to `MLDSA65_Functional.vec_k_make_hint` |
| `sign_body_h_spec` | byte-walk / hints | §6.2 | same as combine sans aggregation | same bridge |
| `combine_body_mu_input_spec` | codec layout | §5.4.1 | ExternalMu byte serialization | byte-level layout proof (mechanical) |
| `sign_body_mu_input_spec` | codec layout | §5.4.1 | same | same |
| `combine_no_reject_on_accepted_honest_layout` | protocol acceptance | §6.2 | honest accepted path | probabilistic Hoare logic on κ loop |
| `sign_no_reject_on_accepted_honest_layout` | protocol acceptance | §6.2 | same | same |
| `pack_unpack_n1_signature_roundtrip` | codec roundtrip | §3.5.5 | sig packing | bridge to `MLDSA65_Functional.pack_signature` |
| `lagrange_inverse_eval` | Lean-bridged algebraic | §6.2 (FROST) | Lagrange identity at 0 | replace with checked translation artifact |
| `add_share_zeroR`, `reconstruct_linear`, `shamir_correct` | Lean-bridged algebraic | (N4 cone) | Shamir/Lagrange algebra | same |
| ~21 per-type FIPS 204 codec round-trips | codec roundtrip | §3 | encode/decode pairs | Barbosa-Barthe-Dupressoir style bit-level mechanization |
| EasyCrypt / Jasmin / OCaml compiler TCB | trusted base | — | tooling correctness | external (compiler verification project) |

**Proof claim** (narrow): *Under these axioms and trusted
components, the N1 combine/sign implementation produces the same
signature components as the centralized ML-DSA-65 functional
model.*

### Layer 3 — Side-channel and fault security (separate evidence)

PQ implementations are typically broken in the implementation, not
the math. Required evidence:

| Risk | Validation status |
|---|---|
| Timing leakage on secret ops | `scripts/checks/jasmin.sh` — **jasmin-ct blocking** on threshold layer (round1, round2, combine all CT-clean); libjade sign advisory under #2 |
| Memory access leakage | Same (Jasmin-CT analysis) |
| Rejection sampling leakage | Documented in `ct/dudect/README.md` — `pulsar.Sign` is intentionally non-CT per FIPS 204 §3.3 |
| Randomness misuse | `ct/dudect/` — dudect statistical tests at 10⁹ samples (nightly) |
| Fault attacks | Threshold layer is deterministic given per-party randomness; fault-injection at the deployed-binary layer is a separate evaluation track per `docs/evaluation.md` §6 |
| Key erasure | Landed in `luxfi/pulsar` v1.0.7 (`zeroize.go`); fuzz harness and N1 byte-equality test ride alongside it. |
| Encoding malleability | `test/negative/` exercises malformed pk / sk / sig / ctx-length / message-length boundary cases on every per-push gate |

Sensitive regions per FIPS 204: ExpandMask, sampling of y, w = A·y,
HighBits/LowBits, rejection checks, hint generation, secret-key
unpacking, any branch depending on secret or rejection conditions.
The EC functional refinement does NOT by itself prove constant-time
behavior; the jasmin-ct analysis provides that for the threshold layer.

### Layer 4 — Federal/compliance validation (separate tracks)

| Track | Status |
|---|---|
| ACVP / CAVP algorithm validation | Downstream lab work against the NIST ACVP ML-DSA harness (<https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html>); the reference implementation produces ACVP-compatible JSON via `scripts/gen_vectors.sh` |
| FIPS 140-3 module validation | Applies to a packaged crypto module, not to this reference implementation; engagement is a deployed-product concern |

For federal procurement, *"we implement ML-DSA"* is weaker than
*"ACVP/CAVP-validated ML-DSA implementation plus FIPS 140-3
validated module"*. This submission delivers the algorithm-level
reference implementation; module packaging + lab validation are
downstream of this submission.

### Layer 5 — Test evidence (delivered, partial)

Currently delivered (`scripts/test.sh`):
- KAT vectors against pq-crystals reference (Dilithium3) via differential testing
- BoringSSL FIPS / OpenSSL 3.0 PQ provider cross-validation (when available)
- Internal KAT vectors in `vectors/` (deterministic generation)

Required for full validation:
- NIST ACVP-style KATs (ACVP ML-DSA test vector format)
- Randomized signing vectors with seed control
- Malformed pk/sk/sig tests
- Context-string boundary tests (0, 1, 255 bytes)
- Message-length boundary tests
- Cross-implementation differential tests
- Decoder/verifier fuzz testing

### Layer 6 — Standard conformance audit (external)

The EasyCrypt refinement chain says the implementation matches a
functional model that *conforms to* FIPS 204 — but the conformance
itself is by inspection, not machine-checked. A formal conformance
audit by an accredited lab (or NIST-recognized review) is the
external evidence step.

### What this submission delivers vs. what it doesn't

**Delivered**:
- Layer 2 (implementation correctness) at the strongest level
  short of full mechanized closure — EC refinement proof with
  enumerated residual axioms;
- Layer 3 (side-channel) on the threshold layer (Jasmin-CT blocking
  green; libjade sign advisory documented under #2);
- Layer 5 (test evidence) for differential and KAT validation.

**Outside the algorithm-level reference scope**:
- Layer 1 PQ hardness — inherited from NIST FIPS 204's M-LWE / M-SIS analysis;
- Layer 4 ACVP / CAVP / FIPS 140-3 — accredited-lab tracks downstream;
- Layer 6 standard conformance audit — accredited reviewer track downstream;
- Full Layer 2 mechanized closure of the 22 residual axioms — each
  axiom is independently attackable through the per-axiom closure
  plan in `docs/proof-axiom-inventory.md`.

### Recommended next proof work (post-submission)

Per the user's review prioritization (revised after v7):

1. **`*_body_z_spec`** — likely easier than full w_spec with the
   Lean Lagrange bridge already stable. Use
   `Crypto.Threshold.Lagrange.threshold_partial_response_identity`
   for combine; reduce via vec ops + accepted-κ model for sign.
2. **`*_body_mu_input_spec`** — byte-layout proof, mechanical and
   high-confidence once the FIPS 204 §5.4.1 byte serialization
   is concretised.
3. **`*_body_h_spec`** — bridge toward `vec_k_make_hint`.
4. **`*_body_w_spec`** — the hardest target; requires the
   loop/fixed-point accepted-κ model + ExpandA/ExpandMask/mat-vec.

This reverses the earlier ordering (which had w as the natural
next target after w1's HighBits decomposition). The revised
ordering optimizes for fastest residual-trust reduction.

## What this submission does NOT claim

The construction's scope boundary:

- **Identifiable abort on asynchronous networks** — Pulsar identifies
  aborting parties under synchronous network assumptions. Asynchronous
  identifiable-abort attribution routes through a separate consensus-
  layer accountability artifact.
- **1-round signing** — the construction is 2-round by design. FIPS 204
  ML-DSA's rejection-sampling step precludes a 1-round threshold
  variant under any NIST-standard preprocessing oracle.
- **DKG bias resistance under collusion** — Pulsar DKG produces unbiased
  coefficients under honest-majority assumptions. Production
  deployments bind a randomness beacon at the consensus layer
  (chain-level concern, not algorithm-level).

## Comparison to related submissions

| Submission | Round count | Output interchange | Underlying lattice |
|---|---|---|---|
| **Pulsar** (this) | 2 | Byte-equal to FIPS 204 ML-DSA | Module-LWE (M-LWE) |
| Lux Corona (R-LWE sibling) | 2 | Byte-equal to FIPS 204 ML-DSA | Ring-LWE (R-LWE) |
| Raccoon | 3 | Compatible verification | Module-LWE |
| Corona (upstream academic) | 2 | Not interchange-tested at submission time | R-LWE |

The R-LWE sibling library lives at <https://github.com/luxfi/corona>
and is not part of this submission. It is included only in the
comparison because the production Lux Quasar consensus uses both
kernels as parallel options selectable per-chain.

## Contact

- Primary: <z@lux.network> (Lux Industries, Inc.)
- Submission coordination: <mptc@lux.network>
- Security disclosure: see `SECURITY.md`
- Public discussion: <https://github.com/luxfi/pulsar/discussions>

## Reproducibility commitment

The build, test, vector-generation, and benchmark scripts are
deterministic from a 48-byte seed. A reviewer reproducing the
submission tarball from `submission-` should obtain
byte-identical artifacts. Drift is a build bug; please open an issue.
