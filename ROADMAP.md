# ROADMAP — Hanzo / Lux Cryptographic Stack, Q4 2026 → Q4 2029

> **Multi-year engineering plan for the Hanzo / Lux cryptographic stack.**
>
> Audience: NIST reviewers, IETF/CFRG editors, audit-lab partners, FIPS
> 140-3 lab engagement leads, Lux internal cryptography engineering,
> patent counsel. Written as a hard-edged engineering plan — not a
> marketing document.
>
> Maintained by: `crypto-suite@lux.network`
> Last revised: 2026-05-18 (initial draft)

---

## §A Executive Summary

**State today (2026-05-18).** One construction in the Hanzo crypto
inventory — **Pulsar v0.1** (threshold ML-DSA-65, FIPS 204) — is
NIST-MPTC submission-ready: full cover sheet (`SUBMISSION.md`),
formal spec (`spec/pulsar.tex`), IETF draft (`docs/ietf-draft-skeleton.md`),
reference implementation (`ref/go/`), EasyCrypt mechanization (11
files compile, 0 admits, 71 enumerated residual axioms — see
`AXIOM-INVENTORY.md`), 5 Lean-bridged algebraic identities (verified
by `scripts/check-lean-bridge.sh`), Jasmin threshold sources + jasmin-ct
3/3 blocking-green, KAT vectors cross-validated against three independent
ML-DSA implementations, royalty-free patent grant (`PATENTS.md`),
21-claim attorney-prep document (`docs/patent-claims.md`), and 13/13
production go-live blockers closed (`BLOCKERS.md`). Every other
construction listed in `HANZO-CRYPTO-SUITE.md` — Corona, Magnetar,
LSS, FROST/CGGMP21 (Lux profile), BLS aggregate (Lux profile), X-Wing-Sig,
P3Q precompile, C-Chain / X-Chain PQ migration, Z-Chain PQ identity
rollup, threshold TFHE — has varying degrees of LP-level spec
maturity but lacks the matching SUBMISSION-grade packaging.

**Three-year target (Q4 2029).** Pulsar / Corona / Magnetar each have
NIST-submission-shaped packages with mechanized refinement proofs;
FROST and CGGMP21 each have Lux-profile IETF drafts with EasyCrypt
+ Lean proofs and constant-time analyses; X-Wing-Sig is an IETF
RFC-class draft with reference implementation and Lean composition
theorem; the Quasar finality stack provably enforces the strict-PQ
profile end-to-end (and has been independently audited at that
profile); the P3Q precompile is deployed on C-Chain at slot
`0x012205` and exercised in production; C-Chain and X-Chain support
PQ-native account types with X-Wing-Sig as the transition envelope;
Z-Chain PQ identity rollup is live with Groth16 abort-evidence
verification; threshold TFHE bootstrap-key generation is functional
on F-Chain; ACVP/CAVP certificates have been issued by an accredited
lab for ML-DSA-65, ML-KEM-768, and SLH-DSA SHAKE-192s in the Pulsar
reference implementation; one FIPS 140-3 module containing Pulsar
has been submitted to CMVP; and the canonical Rust crate + C library
+ WASM build + no_std embedded target ship under semver discipline
with external constant-time audits.

**Honest caveat.** This roadmap is a plan, not a delivery contract.
Items gated on external bodies — NIST ratification, IETF RFC
publication, FIPS 140-3 lab issuance, CMVP certificate issuance,
USPTO grant — describe **what Lux submits**, not what the external
body decides. Items gated on open research — full bit-level FIPS
204 codec mechanization (Barbosa-Barthe-Dupressoir scale, ~6
person-months for a senior cryptographer-formal-methods specialist
per CRYPTO 2023 precedent), κ-loop probabilistic Hoare model in
EasyCrypt (no published reduction at this scale; multi-month
research project), checked Lean↔EasyCrypt translation tooling (no
such tool exists in the published literature; multi-month research
project) — will slip unless those research items close. Several of
the items in §B are explicitly research, not engineering. The
roadmap names them as such; the engineering work plans around them,
not on top of them.

---

## §B Work Streams

Each stream below is its own section. Effort is in **person-weeks of
senior cryptographer + formal-methods engineer time**, not
calendar-weeks. Calendar slips because senior crypto-FM specialists
are not parallelizable beyond a small team.

### §B.1 Pulsar Tier 1 Post-Submission

**Stream ID**: `PULSAR-POST-SUBMISSION`
**Owner**: Lux crypto-engineering lead + outside formal-methods
collaborator (Cryspen / Galois / Formosa-Crypto consortium contact)
**Current state**:
- Submission package ready (cover, spec, IETF draft, ref impl, EC + Lean
  proofs, KAT vectors, PATENTS, AXIOM-INVENTORY, PROOF-CLAIMS,
  TCB, FIPS-TRACEABILITY, evaluation report).
- 71 enumerated residual EC axioms (`grep -rEn "^axiom\s+\w" proofs/easycrypt/ | wc -l` → 71 on tag `v13`).
- 5 Lean bridges hard-pinned via `scripts/check-lean-bridge.sh`.
- All 13 production go-live blockers closed (BLOCKERS.md, audit dated 2026-05).
- One open advisory: libjade sign CT issue #2 (`ct/jasmin-ct-libjade.md`).
- κ-loop probabilistic Hoare model is OPEN RESEARCH (no closure path).

**Target end state (Q4 2027)**:
- Full κ-loop probabilistic Hoare-logic model in EasyCrypt
  discharging both `*_no_reject_on_accepted_honest_layout` axioms.
- Bit-level FIPS 204 codec mechanization in EasyCrypt (Barbosa-
  Barthe-Dupressoir style) discharging ~21 codec round-trip axioms.
- Stage-level byte-walk axioms `combine_body_{w,h}_spec` and
  `sign_body_{z,w,h}_spec` discharged via narrower sub-axioms
  (ExpandA + ExpandMask + mat_vec_mul; MakeHint) where mechanizable.
- ACVP/CAVP algorithm-validation certificate for the Pulsar
  reference implementation (ML-DSA-65 conformance) issued by an
  accredited lab.
- FIPS 140-3 module submission for one packaged Pulsar consumer
  (e.g. Lux KMS) to CMVP.
- External cryptographic audit (Cryspen / NCC / Trail of Bits / Kudelski)
  report published with all critical / high findings remediated.
- External implementation audit (separate engagement) report
  published with all critical / high findings remediated.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q4 2026 | NIST MPTC submission | Cut `submission-2026-11-16` tag from `main`; deliver the tarball to NIST by 2026-11-16. |
| Q4 2026 | External-audit scoping | Three lab RFPs out (Cryspen, NCC Group, Trail of Bits). Scope: spec + proofs + ref impl. Budget anchor: USD 250-400 k. |
| Q1 2027 | External cryptographic audit kickoff | One lab engaged. 8-12 week engagement. Findings tracked in `audits/<lab>-<year>/`. |
| Q1 2027 | κ-loop EasyCrypt research start | Hire / engage formal-methods specialist for the probabilistic Hoare-logic model. 6-12 person-months. |
| Q2 2027 | Codec mechanization research start | Engage academic collaborator for bit-level FIPS 204 codec mechanization (BBD-scale). 6 person-months. |
| Q2 2027 | Audit report Round 1 | All audit findings classified C/H/M/L. C+H remediation begins immediately. |
| Q3 2027 | NIST MPTC public-analysis response | NIST submission feedback (if any) addressed. Public mailing-list responses to community analysis. |
| Q3 2027 | ACVP/CAVP lab engagement | Engage atsec / Acumen / Leidos / Atsec for ACVP validation of the Pulsar reference implementation. |
| Q4 2027 | κ-loop model first draft | Probabilistic Hoare-logic model compiled in EC; first attempt at discharging `*_no_reject_*` axioms. |
| Q4 2027 | Codec mechanization first draft | First subset of codec round-trip axioms (sk encode/decode) discharged. |
| Q1 2028 | ACVP/CAVP certificate issuance (target) | Certificate from the lab; cert number recorded in `FIPS-TRACEABILITY.md`. (External outcome — Lux controls submission, not issuance.) |
| Q2 2028 | FIPS 140-3 module submission | One Pulsar consumer (e.g., Lux KMS) packaged as a FIPS 140-3 module; submitted to CMVP via lab. |
| Q4 2028 | Codec mechanization complete | All ~21 codec round-trip axioms either discharged or replaced with narrower sub-axioms. |
| Q1 2029 | κ-loop closure | Both `*_no_reject_*` axioms discharged from the axiom inventory. |
| Q3 2029 | Implementation audit | Second external audit on the Rust + C + WASM production targets. |
| Q4 2029 | All Stream B.1 deliverables landed | AXIOM-INVENTORY shrinks to: Lean-bridged algebraic (5), EC/Jasmin/OCaml TCB (out of EC trust). |

**Dependencies**: §B.14 (mechanized closure of residual EC axioms) is
where the κ-loop and codec work formally lives. §B.15 (external
audits) and §B.18 (FIPS 140-3) and §B.19 (ACVP/CAVP) are also called
out as separate streams because their cadence and ownership are
independent.

**Risks**:

- **Research**: κ-loop probabilistic Hoare model is open research
  (no published reduction at this scale in the EasyCrypt literature).
  This may not close in 12 months even with a dedicated specialist.
  **Mitigation**: state operationally that `mldsa_accept_lower_bound`
  is an inherited FIPS 204 acceptance bound; ship submission with
  current packaging even if κ-loop model slips.
- **Research**: bit-level codec mechanization (BBD-scale) is a
  multi-month project even with a single specialist. **Mitigation**:
  prioritize the codec sub-axioms that are highest-leverage (signature
  encode/decode, sk encode/decode); leave low-leverage round-trips
  axiomatic with narrowed statements.
- **Engineering**: opam-pinned EasyCrypt version `909464e` will drift
  off mainline; new EC bug fixes / breaking changes require selective
  cherry-pick or pin migration. **Mitigation**: nightly canary build
  against EC head; quarterly opam refresh cadence.
- **External**: ACVP/CAVP lab availability is constrained (single-digit
  number of US labs accredited for PQ algorithm validation as of 2026).
  **Mitigation**: line up two labs concurrently (atsec + Acumen).
- **External**: FIPS 140-3 module validation timeline is 12-24 months
  end-to-end; first submission may slip to 2029. **Mitigation**:
  manage expectation in roadmap (target Q2 2028 submission, certificate
  issuance is the lab's clock).

**Effort estimate**:

| Sub-task | Person-weeks |
|---|---:|
| External cryptographic audit (Round 1) — Lux side: scoping, fix landings | 30 |
| κ-loop probabilistic Hoare-logic research | 60 |
| Codec mechanization (BBD-scale) | 80 |
| ACVP/CAVP lab engagement (Lux engineering side) | 12 |
| FIPS 140-3 module packaging + submission | 40 |
| Implementation audit (Round 2) | 20 |
| Documentation + axiom-inventory updates | 10 |
| **Total** | **252** |

**Acceptance gate**: AXIOM-INVENTORY.md residual count drops to ≤
10 (only Lean-bridged + irreducible TCB items). External audit report
published. ACVP cert recorded. FIPS 140-3 module submitted (not
necessarily issued).

---

### §B.2 Corona Tier 1b Submission Packaging

**Stream ID**: `CORONA-SUBMISSION`
**Owner**: Lux R-LWE specialist + cross-pollination from PULSAR-POST-SUBMISSION
**Current state**:
- Reference implementation mature at `~/work/lux/corona/` (full Go: `dkg/`,
  `dkg2/`, `cli/`, `cmd/`, `sign/`, `threshold/`, `reshare/`, `keyera/`).
- DESIGN.md and CONSTANT-TIME-REVIEW.md drafts present (`corona/DESIGN.md`,
  `corona/CONSTANT-TIME-REVIEW.md`).
- DKG oracle binary built (`corona/dkg_oracle*`, `corona/dkg2_oracle*`).
- Partial EC proof scaffolding for DKG only; no Lean bridges yet.
- No SUBMISSION.md, no SPEC.md (standalone), no PATENTS.md, no IETF draft,
  no AXIOM-INVENTORY, no PROOF-CLAIMS, no TCB, no FIPS-TRACEABILITY.

**Target end state (Q2 2027)**:
- Corona has the same package shape as Pulsar:
  `corona/SUBMISSION.md`, `corona/SPEC.md`, `corona/PATENTS.md`,
  `corona/AXIOM-INVENTORY.md`, `corona/PROOF-CLAIMS.md`,
  `corona/TRUSTED-COMPUTING-BASE.md`, `corona/FIPS-TRACEABILITY.md`
  (since Corona is byte-compatible with FIPS 204 verifier — same
  underlying ML-DSA semantics, R-LWE sibling),
  `corona/HANZO-CRYPTO-SUITE.md` cross-reference,
  `corona/docs/evaluation.md`, `corona/docs/ietf-draft.md`,
  `corona/docs/patent-claims.md`, `corona/CHANGELOG.md`.
- EC proofs mirror Pulsar's structure: refinement chain + axiom
  inventory + Lean bridges. The R-LWE arithmetic differs from M-LWE
  but the proof-engineering technique transfers (same Lagrange
  identity in Lean, different ring).

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q4 2026 | Corona standalone spec | `corona/SPEC.md` (text spec) + `corona/SUBMISSION.md` (cover sheet) cut from existing DESIGN.md. Patent grant copied + R-LWE-specific. |
| Q1 2027 | Corona EC proof scaffolding | 11-file mirror of Pulsar's EC theories adapted to R-LWE: `Corona_N1.ec`, `Corona_N1_{Sign,Combine}_{Refinement,Layout,Wrapper}.ec`, `Corona_N1_Memory.ec`, etc. Same admit budget 0/0. |
| Q1 2027 | Corona Lean bridges | Same 5 Lean-bridged algebraic identities; reuse `Crypto.Threshold.Lagrange` Lean theory (ring-agnostic). Bridge guard pinned. |
| Q2 2027 | Corona Jasmin threshold layer | Port `jasmin/threshold/{round1,round2,combine}.jazz` to R-LWE arithmetic. jasmin-ct 3/3 blocking. |
| Q2 2027 | Corona IETF draft | `docs/ietf-draft.md` for Corona; submit to CFRG mailing list for review. |
| Q3 2027 | Corona AXIOM-INVENTORY + PROOF-CLAIMS + TCB | Full trust accounting at Pulsar-grade. |
| Q3 2027 | Corona external review-ready | Submit to NIST MPTC public comment (no separate submission slot needed; Corona is a sibling not a parallel competitor). |

**Dependencies**: §B.21 (documentation + governance) for the IA
update; §B.14 (mechanized closure) — Corona will inherit any κ-loop
or codec discharge from Pulsar's work.

**Risks**:

- **Engineering**: R-LWE has different reduction properties from
  M-LWE; some Pulsar proof techniques may not transfer 1:1.
  **Mitigation**: identify per-axiom transfer feasibility at Q1 2027
  scaffolding milestone; budget extra time for non-transferable lemmas.
- **Engineering**: Corona's Jasmin threshold layer needs an R-LWE
  baseline (no libjade equivalent for R-LWE). May require writing a
  Jasmin R-LWE single-party baseline from scratch. **Mitigation**:
  Lux's R-LWE Go reference is mature; transcribing it to Jasmin
  is 2-3 person-weeks with jasmin-ct checks.

**Effort estimate**:

| Sub-task | Person-weeks |
|---|---:|
| Standalone SUBMISSION + SPEC + PATENTS + cover docs | 8 |
| EC proof scaffolding (11 files) | 20 |
| Lean bridge documentation + CI guards | 4 |
| Jasmin threshold layer (R-LWE arithmetic) | 12 |
| IETF draft | 6 |
| AXIOM-INVENTORY + PROOF-CLAIMS + TCB | 6 |
| docs/evaluation.md + benchmarks | 6 |
| **Total** | **62** |

**Acceptance gate**: `corona/check-high-assurance.sh` runs analogous
checks to Pulsar's; all 7 per-push gates green. IETF draft accepted
by CFRG for working-group consideration (or explicit feedback received).

---

### §B.3 Magnetar Tier 3 Research → Spec

**Stream ID**: `MAGNETAR-RESEARCH-TO-SPEC`
**Owner**: Lux + academic collaborator (hash-based-signatures research
group — Andreas Hülsing's group at TU/e, Bernstein–Lange axis, or
Joppe Bos / NXP)
**Current state**:
- `docs/magnetar.md` — research-direction placeholder (~125 lines), no
  spec, no implementation.
- No published threshold-SLH-DSA construction is well-reviewed enough
  to lift directly; this is research-grade.

**Target end state (Q4 2028)**:
- Research paper draft (LaTeX) proposing the Magnetar construction:
  distributed seed generation via Pedersen-VSS on the SHAKE seed;
  per-signature MPC for FORS / W-OTS+ Merkle traversal; identifiable
  abort with TLV evidence; reshare with public-key preservation.
- Initial prototype implementation (Go) demonstrating end-to-end
  threshold signing on SHAKE-192s.
- KAT vectors verified against single-party FIPS 205 SLH-DSA.
- Spec converging on parameter set
  `MAGNETAR-THRESHOLD-SLH-DSA-SHAKE-192s`.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q3 2026 | Literature survey + collaborator engagement | Identify academic collaborator; review prior threshold-hash-sig work (Coretta et al., Roy et al., Boneh-Boyen-Goh threshold-related literature). |
| Q4 2026 | Construction design draft | First-pass construction document under `docs/magnetar-construction.tex`. Open design questions enumerated. |
| Q1 2027 | Construction first review | Internal cryptographer + collaborator review. Open security analysis questions identified. |
| Q2 2027 | Threshold seed-generation prototype (Go) | DKG over the SHAKE seed using Pedersen-VSS. Standalone, not yet wired to FORS. |
| Q3 2027 | FORS-traversal MPC prototype | One Merkle layer of FORS-traversal computed under MPC; per-party time + bandwidth metrics. |
| Q4 2027 | W-OTS+ MPC prototype | One W-OTS+ chain computed under MPC; combined with FORS prototype = end-to-end one-signature ceremony. |
| Q1 2028 | Per-signature ceremony complete | Full per-signature flow producing a FIPS 205 SHAKE-192s signature byte-identical to single-party. KAT vectors written. |
| Q2 2028 | Identifiable-abort + reshare modules | Same TLV-encoded evidence format as Pulsar §10; per-MPC-round per-party state. |
| Q3 2028 | Research paper submitted | Submit to CRYPTO 2029 / EUROCRYPT 2029 / ASIACRYPT 2028. Self-archive on IACR ePrint. |
| Q4 2028 | Initial Magnetar v0.1 package | Same shape as Pulsar (SUBMISSION + SPEC + PATENTS + ref/ + proofs/). **Status: research-grade, not production**. |

**Dependencies**: §B.21 (governance) for an LP-NNN slot; §B.20
(patent prosecution) for any Magnetar-specific filings.

**Risks**:

- **Research**: there is no obviously-correct threshold construction
  for SLH-DSA. The whole stream is research, not engineering. **Mitigation**:
  treat 2027-2028 as a research project, not an implementation
  project; accept that the timeline may slip to 2029-2030.
- **Performance**: per-signature MPC will be 100-1000× the cost of
  single-party SLH-DSA; the prototype may show Magnetar is impractical
  at FIPS 205 SHAKE-192s. **Mitigation**: do the cost analysis early
  (Q1 2027); if untenable, downgrade Magnetar to "research-only
  artifact, no production track" and document accordingly.
- **External**: academic collaboration cadence is unpredictable.
  **Mitigation**: Lux internal cryptographer takes ownership of design
  + prototype; collaborator role is review + co-authorship.

**Effort estimate**:

| Sub-task | Person-weeks |
|---|---:|
| Literature survey + collaborator engagement | 4 |
| Construction design + review | 12 |
| DKG-over-SHAKE prototype | 8 |
| FORS MPC prototype | 12 |
| W-OTS+ MPC prototype | 12 |
| End-to-end signing ceremony | 16 |
| Identifiable-abort + reshare | 8 |
| Research paper drafting + submission | 12 |
| Initial v0.1 package | 8 |
| **Total** | **92** |

**Acceptance gate**: Research paper accepted at CRYPTO/EUROCRYPT/ASIACRYPT
OR self-archived on IACR ePrint with positive peer review. Prototype
demonstrates end-to-end FIPS 205 SHAKE-192s signature production under
MPC with KAT cross-validation.

---

### §B.4 LSS Tier 4 IETF / CFRG Draft

**Stream ID**: `LSS-CFRG-DRAFT`
**Owner**: Lux MPC engineer
**Current state**:
- Specified inside LP-019 (`~/work/lux/lps/LP-019-threshold-mpc.md`)
  + LP-077 (`~/work/lux/lps/LP-077-lss.md`) + LP-141
  (`~/work/lux/lps/LP-141-threshold-vm.md`).
- Implementation present inside `~/work/lux/mpc/` and the Lux KMS.
- No standalone IETF draft.

**Target end state (Q3 2027)**:
- Standalone Internet-Draft `draft-lux-cfrg-linear-shamir-resharing-00`
  submitted to IETF datatracker.
- KAT vectors aligned with the `pulsar-mptc/vectors/` format.
- Reference impl extracted out of `~/work/lux/mpc/` into a standalone
  library `~/work/lux/lss/` (separable from MPC infrastructure).

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q1 2027 | Standalone draft skeleton | Convert LP-019 + LP-077 + LP-141 LSS sections into IETF-draft template (mmark/kramdown-rfc). |
| Q2 2027 | KAT vectors | Generate aligned KATs in `pulsar-mptc/vectors/`-style JSON; deterministic regen via seeded RNG. |
| Q2 2027 | Reference impl extraction | Split `~/work/lux/lss/` out of `~/work/lux/mpc/`. Standalone go module. |
| Q3 2027 | IETF submission | Submit `draft-lux-cfrg-linear-shamir-resharing-00` to CFRG. |

**Dependencies**: §B.21 (governance) for LP cross-refs.

**Risks**:

- **External**: CFRG may not adopt LSS as a working-group document if
  it's perceived as redundant with FROST or upstream Shamir. **Mitigation**:
  position LSS as **proactive secret refresh wrapper for any linear
  threshold scheme** (FROST, CGGMP21, BLS, Pulsar, Corona) — composable
  building block, not a parallel competitor.

**Effort estimate**: 18 person-weeks total.

**Acceptance gate**: Internet-Draft on datatracker (`draft-lux-cfrg-*`).
CFRG mailing-list discussion thread initiated.

---

### §B.5 FROST Profile (Lux) + EC Proofs

**Stream ID**: `FROST-LUX-PROFILE`
**Owner**: Lux crypto-engineering (consumer-side: bridge, custody)
**Current state**:
- Upstream IETF draft `draft-irtf-cfrg-frost` exists.
- Lux implementation under `~/work/lux/mpc/cc/frost/` (DKG, sign).
- No Lux-specific profile draft; no EC proof in Lux; no CT analysis
  beyond ad-hoc review.
- LP-019 + LP-154 (`~/work/lux/lps/LP-154-frost.md`) cover Lux's usage.

**Target end state (Q4 2027)**:
- `~/work/lux/frost/` standalone submission package: SUBMISSION.md,
  SPEC.md (Lux profile: domain separation, transcript binding, deterministic-
  vs-randomized nonce mode, identifiable abort), PATENTS.md (defensive
  grant, since FROST itself is published prior art), IETF draft
  (`draft-lux-frost-profile-00`).
- EC proofs (refinement chain for Lux-profile sign + DKG).
- Lean bridges (Lagrange identity reused from Pulsar — `Crypto.Threshold.Lagrange`).
- Jasmin sources for the sign-share + combine pipeline; jasmin-ct
  blocking.
- KAT vectors aligned with Pulsar's format.
- Constant-time analysis report.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q1 2027 | Lux profile spec | `~/work/lux/frost/SPEC.md` capturing Lux's domain separators, transcript-binding choices, identifiable-abort evidence format. |
| Q1 2027 | Reference impl extraction | Split into `~/work/lux/frost/` (Go) from `~/work/lux/mpc/cc/frost/`. |
| Q2 2027 | EC proof scaffolding | Refinement chain modeled on Pulsar's: FROST_Sign_Layout, FROST_Sign_Refinement, FROST_Sign_Wrapper, FROST_DKG_*, etc. |
| Q2 2027 | KAT vectors | Aligned with upstream draft-irtf-cfrg-frost KATs + Lux-specific transcript-binding vectors. |
| Q3 2027 | Jasmin sources + jasmin-ct | Sign-share + combine in Jasmin; jasmin-ct 2/2 blocking-green. |
| Q3 2027 | Lean bridges | Reuse `Crypto.Threshold.Lagrange.threshold_partial_response_identity`. |
| Q3 2027 | IETF draft (Lux profile) | `draft-lux-frost-profile-00` to datatracker. Convergence with upstream draft author maintained. |
| Q4 2027 | External CT review | jasmin-ct + dudect runs publicly archived. |

**Dependencies**: Lean Lagrange theory (already in Pulsar). §B.14
codec mechanization will help if FROST's Schnorr scheme has bit-level
encoding axioms; Schnorr encoding is much simpler than ML-DSA, so
this is mostly mechanical.

**Risks**:

- **External**: IETF draft-irtf-cfrg-frost is a moving target; Lux
  profile may need realignment. **Mitigation**: track upstream draft
  changes per RFC editor cadence.

**Effort estimate**: 50 person-weeks.

**Acceptance gate**: EC `check-high-assurance.sh` analogue passes;
jasmin-ct 2/2 blocking green; KAT vectors cross-validate against
upstream draft-irtf-cfrg-frost test vectors AND against any other
FROST implementation in the wild (zcash/orchard, FROST.zip).

---

### §B.6 CGGMP21 Submission Package

**Stream ID**: `CGGMP21-SUBMISSION`
**Owner**: Lux crypto-engineering + bridge team
**Current state**:
- LP-019 + LP-155 (`~/work/lux/lps/LP-155-cggmp21.md`) cover Lux's usage.
- Implementation under `~/work/lux/mpc/cc/cggmp21/` (and `~/work/lux/mpc/` infrastructure).
- No Lux-specific spec; no EC proof; partial CT analysis.

**Target end state (Q1 2028)**:
- `~/work/lux/cggmp21/` standalone submission package: SUBMISSION.md,
  SPEC.md (Lux profile: identifiable-abort variant with stronger
  evidence than upstream, transcript-binding, deterministic-presign mode),
  PATENTS.md (defensive grant, since CGGMP21 is published academic
  prior art with no patent claims known), IETF draft
  (`draft-lux-cggmp21-profile-00`).
- EC proofs (refinement chain for Lux-profile ECDSA threshold sign
  + presign).
- Lean bridges for the Paillier-style ZK-proofs (range, log, mul).
- Constant-time analysis on Paillier + ECDSA operations (jasmin-ct
  not directly applicable to Paillier-modular-exp; use BearSSL constant-
  time bignum and document).
- KAT vectors.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q3 2027 | Spec extraction | LP-019 / LP-155 sections + implementation review → `~/work/lux/cggmp21/SPEC.md`. |
| Q3 2027 | Reference impl extraction | `~/work/lux/cggmp21/` standalone. |
| Q4 2027 | EC proof scaffolding | Refinement chain for Lux-profile presign + sign. Identifies which CGGMP21 ZK proofs need Lean mechanization. |
| Q4 2027 | Lean ZK-proof bridges | Mechanize the Paillier-range-proof, log-proof, mul-proof identities in Lean; bridge to EC. |
| Q1 2028 | IETF draft | `draft-lux-cggmp21-profile-00` to datatracker. |
| Q1 2028 | CT analysis + dudect runs | Constant-time analysis of Paillier-bignum operations; dudect at 10⁹ samples. |
| Q1 2028 | Identifiable-abort variant spec + proof | Document Lux's stronger evidence (vs. upstream) and prove the soundness/completeness reduction. |

**Dependencies**: Lean polynomial-ring theory; potentially Mathlib's
Paillier soundness reductions (may need to be ported).

**Risks**:

- **Engineering**: Paillier-bignum constant-time is hard; we may need
  to ship with the same "advisory CT" framing libjade-sign has.
  **Mitigation**: identify a known-CT Paillier implementation (s2n,
  BoringSSL, or our own) at scoping; treat constant-time as a separate
  hardening milestone.
- **Cryptographic**: CGGMP21's full security reduction depends on
  ZK-proof soundness; mechanizing those is more work than Lagrange.
  **Mitigation**: scope ZK-proof bridges before EC scaffolding;
  estimate effort per-proof rather than aggregate.

**Effort estimate**: 70 person-weeks.

**Acceptance gate**: `~/work/lux/cggmp21/check-high-assurance.sh`
analogue green; KAT vectors cross-validate against upstream CGGMP21
reference (Fireblocks open-source, zengo CGGMP21, dfns) AND a
secondary independent implementation.

---

### §B.7 BLS Aggregated Signatures Profile

**Stream ID**: `BLS-LUX-PROFILE`
**Owner**: Lux consensus team
**Current state**:
- BLS12-381 production deployment in `~/work/lux/crypto/`, Quasar
  finality stack consumer.
- LP-075 + LP-110 (`~/work/lux/lps/LP-{075,110}-*.md`) cover usage.
- No standalone submission package; no EC proof.

**Target end state (Q2 2028)**:
- `~/work/lux/bls/` standalone package: SUBMISSION.md, SPEC.md (Lux
  profile: aggregation, proof-of-possession to defend against rogue-key,
  domain separators per IETF `draft-irtf-cfrg-bls-signature`), PATENTS.md.
- EC proofs (aggregation soundness reduction).
- KAT vectors cross-validated against `blst` (which Lux already uses
  as test-time oracle per `lps/CRYPTO-CANONICAL.md`).

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q4 2027 | Spec extraction | Per-LP material → `~/work/lux/bls/SPEC.md`. |
| Q1 2028 | Reference impl extraction | Already factored; just produce SUBMISSION.md + IETF profile draft. |
| Q1 2028 | EC proof scaffolding | Aggregation + verify-aggregate reduction. |
| Q2 2028 | IETF draft | `draft-lux-bls-aggregate-profile-00` (alignment with `draft-irtf-cfrg-bls-signature`). |

**Risks**: Rogue-key attack is the classical pitfall. Lux's profile
MUST mandate proof-of-possession or message-augmentation. Document
the choice and prove the security reduction.

**Effort estimate**: 35 person-weeks.

**Acceptance gate**: Lux profile draft accepted at CFRG for working-group
review (or explicit feedback received). KAT vectors byte-equal against
`blst`.

---

### §B.8 X-Wing-Sig Hybrid Wrapper Specification

**Stream ID**: `X-WING-SIG`
**Owner**: Lux crypto-engineering (driver of `docs/x-wing-sig.md`)
**Current state**:
- `docs/x-wing-sig.md` proposed direction (no LP, no impl, no proof).

**Target end state (Q2 2028)**:
- `~/work/lux/lps/LP-NNN-xwing-sig.md` LP draft (Final status).
- IETF draft `draft-lux-cfrg-xwing-sig-00`.
- Reference implementation in `~/work/lux/crypto/xwing-sig/` (Go) +
  Rust port (`~/work/lux/crypto-rs/xwing-sig/`).
- Lean composition theorem: `HybridSig.secure ⇐ classical.secure ∨ pq.secure`
  (under standard hybrid-signature composition; reference: Bindel-Brendel-
  Fischlin-Goncalves-Stebila "Hybrid Key Encapsulation Mechanisms and
  Authenticated Key Exchange" CT-RSA 2019 and follow-ups for signatures).
- KAT vectors with `(classical, pq)` ciphersuite identifiers.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q3 2026 | LP draft | `~/work/lux/lps/LP-NNN-xwing-sig.md` resolving open design questions in `docs/x-wing-sig.md` §"Open design questions". |
| Q4 2026 | IETF draft 00 | `draft-lux-cfrg-xwing-sig-00` to datatracker. |
| Q4 2026 | Reference impl (Go) | `~/work/lux/crypto/xwing-sig/` with Ed25519+ML-DSA-65 and ECDSA-P256+ML-DSA-65 ciphersuites. |
| Q1 2027 | KAT vectors | Aligned with Pulsar format; ciphersuite-tagged. |
| Q2 2027 | Lean composition theorem | `~/work/lux/proofs/lean/Crypto/XWingSig/Composition.lean`. Compiled, no `sorry`. |
| Q2 2027 | Rust port | `~/work/lux/crypto-rs/xwing-sig/`. No-std capable. |
| Q3 2027 | External review | CFRG mailing-list review; address feedback in `-01` draft. |
| Q1 2028 | Wallet integration | First wallet (Lux KMS HSM) signs with X-Wing-Sig in production. |
| Q2 2028 | Threshold variant spec | "FROST × Pulsar" composition specified as `draft-lux-cfrg-xwing-sig-threshold-00`. |

**Dependencies**: §B.5 FROST (for threshold variant); §B.1 Pulsar (PQ side).

**Risks**:

- **Cryptographic**: composition theorems for hybrid signatures need
  care around malleability, length-extension, and signature-binding.
  Bindel et al's KEM work is the closest analog; signature composition
  is more subtle. **Mitigation**: state the composition theorem
  precisely (which security games compose); mechanize the composition
  argument in Lean.
- **Standardization**: NIST has not committed to a hybrid-signature
  standardization track (unlike hybrid KEM where `xwing` is in CFRG
  flight). X-Wing-Sig is Lux-led. **Mitigation**: pursue IETF/CFRG
  track but do not block production deployment on RFC publication.

**Effort estimate**: 35 person-weeks.

**Acceptance gate**: IETF draft on datatracker; reference impls (Go +
Rust) cross-validate; Lean composition theorem compiles. First wallet
deployment is the production-readiness signal.

---

### §B.9 C-Chain Native PQ Migration

**Stream ID**: `C-CHAIN-PQ-NATIVE`
**Owner**: Lux EVM team + consensus team
**Current state**:
- C-Chain uses ECDSA (secp256k1) for transaction signing.
- LP-172 (`~/work/lux/lps/LP-172-wallet-pq-account-type.md`) + LP-173
  (`~/work/lux/lps/LP-173-tx-auth-envelope.md`) + LP-174
  (`~/work/lux/lps/LP-174-pq-permit.md`) cover wallet-side PQ.
- Strict-PQ profile enforcement landed (CR-1, CR-2 in `BLOCKERS.md`).
- P3Q precompile slot `0x012205` reserved.
- No PQ-native account type live in production.

**Target end state (Q4 2028)**:
- C-Chain supports a new wallet account type (`PQ_ACCOUNT`) where
  authorization is via X-Wing-Sig (Ed25519 + ML-DSA-65) or pure ML-DSA-65.
- Validators verify ML-DSA on every PQ_ACCOUNT transaction (via P3Q
  precompile or native VM op).
- Legacy ECDSA accounts continue working through the transition window.
- Genesis-time `StrictPQTime` activation per-chain controls migration.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q1 2027 | LP-172/173/174 finalization | Resolve open issues in LP-172 (account-type derivation, tx-envelope format, replay protection). |
| Q2 2027 | EVM precompile spec | LP-NNN: P3Q precompile at slot `0x012205` (gas cost analysis, input format, error cases). |
| Q3 2027 | Implementation (devnet) | Devnet C-Chain accepts PQ_ACCOUNT transactions with X-Wing-Sig envelopes. |
| Q4 2027 | Wallet SDK support | Lux JS SDK + Hanzo KMS sign PQ_ACCOUNT transactions. |
| Q1 2028 | Testnet deployment | testnet rolls out PQ_ACCOUNT support with telemetry. |
| Q2 2028 | Mainnet deployment (opt-in) | mainnet allows PQ_ACCOUNT registration; legacy ECDSA accounts unchanged. |
| Q3 2028 | Bridge integration | Lux native bridge (LP-016/017) accepts PQ_ACCOUNT signatures on both sides. |
| Q4 2028 | Migration telemetry | % of accounts migrated; gas-cost trajectory; ML-DSA verifier latency at consensus throughput. |

**Dependencies**: §B.8 X-Wing-Sig; §B.11 P3Q precompile; §B.1 Pulsar
(for threshold-signing C-Chain validators if applicable).

**Risks**:

- **Engineering**: ML-DSA verification gas cost is ~10× ECDSA. C-Chain
  fee economics may need adjustment. **Mitigation**: precompile gas
  pricing review at Q2 2027 milestone; alternative is to batch-verify
  ML-DSA at block-level rather than per-tx.
- **Operational**: wallet upgrade is a long-tail problem. **Mitigation**:
  bridge encourages migration; legacy ECDSA never deprecated absent
  hard-fork vote.

**Effort estimate**: 80 person-weeks.

**Acceptance gate**: PQ_ACCOUNT transactions land on mainnet; first
1000 PQ_ACCOUNT addresses created; one bridge transfer signed PQ-native.

---

### §B.10 X-Chain Native PQ Migration

**Stream ID**: `X-CHAIN-PQ-NATIVE`
**Owner**: Lux X-Chain team
**Current state**:
- X-Chain is UTXO-based; uses ECDSA + Ed25519 hybrid.
- LP-105 + LP-172-179 PQ LPs cover Lux-wide PQ.
- No PQ-native UTXO signing in production.

**Target end state (Q1 2029)**:
- X-Chain UTXOs can be locked under a PQ output type (X-Wing-Sig
  envelope or pure ML-DSA-65).
- Validators verify PQ signatures on PQ-output spending.
- Legacy UTXOs continue working through transition window.

**Per-quarter milestones**: structurally mirror §B.9 (C-Chain), shifted
~1-2 quarters later to leverage C-Chain learnings.

| Quarter | Milestone |
|---|---|
| Q3 2027 | LP-NNN: X-Chain PQ output type spec |
| Q1 2028 | Devnet impl |
| Q2 2028 | Testnet rollout |
| Q3 2028 | Mainnet opt-in |
| Q1 2029 | Bridge integration + migration telemetry |

**Effort estimate**: 60 person-weeks.

**Acceptance gate**: First PQ-output UTXO created and spent on mainnet.

---

### §B.11 EVM Precompile P3Q at Slot `0x012205`

**Stream ID**: `P3Q-PRECOMPILE`
**Owner**: Lux EVM team
**Current state**:
- Slot `0x012205` reserved per CLAUDE.md (P3Q "Post-Quantum Pulsar Proof").
- Partial coverage in LP-078 (`~/work/lux/lps/LP-078-evm-precompiles.md`).
- No dedicated LP for the precompile itself.

**Target end state (Q3 2027)**:
- `~/work/lux/lps/LP-NNN-p3q-precompile.md`: spec for input format
  (group_pk + message + Pulsar/single-party ML-DSA signature), gas
  cost (informed by §B.9 cost model), error cases, conformance vectors.
- Implementation in `~/work/lux/evm/precompiles/` (Go) +
  `~/work/lux/luxcpp/cevm` (C++ via cgo).
- KAT vectors and conformance test suite.
- Decomplexed: P3Q is its own precompile slot, NOT bolted onto BLS or
  ZK precompiles (per CLAUDE.md discipline).

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q1 2027 | P3Q LP draft | `LP-NNN-p3q-precompile.md` with input/output format, gas-cost model, error spec. |
| Q2 2027 | Implementation (Go + C++) | Behind feature flag; devnet only. |
| Q2 2027 | KAT vectors + conformance suite | `~/work/lux/evm/precompiles/p3q/test-vectors/`. |
| Q3 2027 | Testnet rollout | Deployed; metered; observability dashboard. |
| Q4 2027 | Mainnet rollout (gated) | Available on mainnet behind `StrictPQTime`. |

**Dependencies**: §B.1 (Pulsar reference); §B.9 (C-Chain migration consumer).

**Risks**:

- **Gas cost**: ML-DSA verify is computationally heavy; gas pricing
  could undercut the precompile's utility. **Mitigation**: batch-verify
  multiple signatures in one precompile call (saves per-call overhead);
  measure actual gas-vs-time trajectory before mainnet.

**Effort estimate**: 25 person-weeks.

**Acceptance gate**: Mainnet block contains first transaction calling
P3Q. Gas-vs-time stability over 1 month of mainnet traffic.

---

### §B.12 Z-Chain PQ Accountability Layer

**Stream ID**: `Z-CHAIN-PQ-IDENTITY`
**Owner**: Lux Z-Chain team
**Current state**:
- LP-063 + LP-169 + LP-179 cover Z-Chain + PQ identity rollup.
- Z-Chain repo absent from `~/work/lux/zchain/` (verified by `ls`);
  spec exists in LPs only.
- BLOCKERS.md flags `QuasarCert.MLDSAProof` as not currently Groth16
  (per-validator sigs with length prefixes; BN254 quantum exposure
  theoretical only because BN254 not actually in use).

**Target end state (Q4 2028)**:
- `~/work/lux/zchain/` repo with Z-Chain reference implementation.
- Groth16 circuit (`zchain/circuits/pulsar-abort.circom` or equivalent)
  for Pulsar identifiable-abort evidence aggregation.
- L1 verifier accepts Groth16 proofs of Pulsar abort and slashes
  identified malicious parties.
- LP-169 finalized; LP-179 (`contract-auth-via-zchain-proof.md`) wired
  to live Z-Chain.
- BLS12-381 (PQ-vulnerable curve) phased out of the abort-evidence path;
  the post-quantum-secure pairing question is settled or hybridized.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q2 2027 | Z-Chain repo created | `~/work/lux/zchain/` with skeleton + LP-063 + LP-169 cross-refs. |
| Q3 2027 | Pulsar-abort circuit | Groth16 circuit for the abort-evidence aggregation identity. |
| Q4 2027 | L1 verifier | EVM precompile or contract verifying the Groth16 proof. |
| Q1 2028 | Devnet integration | Z-Chain rollup posts abort proofs; L1 slashes. |
| Q2 2028 | Testnet rollout | |
| Q3 2028 | Mainnet rollout | |
| Q4 2028 | LP-169 + LP-179 finalization | "Final" status in `~/work/lux/lps/`. |

**Dependencies**: §B.1 Pulsar (abort-evidence semantics); §B.11
P3Q precompile.

**Risks**:

- **Cryptographic**: Groth16 over BN254 is not PQ-secure. If quantum
  adversary forges Groth16 proof, abort accountability degrades.
  **Mitigation**: PlonK over BLS12-381 (also not PQ-secure but stronger
  classically); long-term plan a PQ ZK system (STARK + FRI). State the
  classical-only assumption clearly in LP-169.
- **Engineering**: Z-Chain rollup is a substantial project orthogonal
  to the crypto-stack roadmap; this stream may need to land downstream
  of Z-Chain core readiness.

**Effort estimate**: 90 person-weeks (Z-Chain rollup work is its own
beast; this is the cryptography subset).

**Acceptance gate**: First slashing event on mainnet driven by a Groth16
proof of Pulsar abort.

---

### §B.13 TFHE / F-Chain Integration

**Stream ID**: `TFHE-F-CHAIN`
**Owner**: Lux FHE team
**Current state**:
- LP-013 + LP-066 + LP-067 + LP-068 + LP-134 + LP-137-FHE-* cover FHE / F-Chain.
- TFHE production reference in `~/work/lux/fhe/` and `~/work/luxcpp/fhe/`
  (CPU + GPU via Metal/CUDA/WGSL).
- M-Chain / F-Chain split per LP-134 in flight.
- Distributed bootstrap-key generation not yet implemented.

**Target end state (Q3 2028)**:
- M-Chain hosts MPC ceremonies for FHE bootstrap-key generation
  (threshold TFHE).
- F-Chain hosts FHE compute on encrypted ciphertexts using the
  threshold-generated bootstrap key.
- LP-066 + LP-134 + LP-141 + LP-167 wired end-to-end.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q1 2027 | Threshold TFHE bootstrap-key DKG spec | Match LP-019 + LP-141 patterns. |
| Q2 2027 | Implementation (devnet) | Threshold bootstrap on devnet. |
| Q3 2027 | F-Chain compute on threshold-keyed ciphertexts | One worked example end-to-end (confidential-ERC-20 transfer). |
| Q1 2028 | Testnet | |
| Q3 2028 | Mainnet | |

**Dependencies**: §B.4 LSS (for the reshare wrapper around TFHE bootstrap
keys); §B.21 governance.

**Risks**:

- **Performance**: distributed TFHE bootstrap is expensive (10²-10³ ms
  per gate in MPC mode). May limit applicability to small circuits.
  **Mitigation**: focus on use cases where threshold bootstrap is a
  one-time setup cost (key custody), not per-operation.

**Effort estimate**: 60 person-weeks (within the FHE team's scope, not
counted in central crypto budget).

**Acceptance gate**: First confidential-ERC-20 transfer on mainnet with
threshold-generated bootstrap key.

---

### §B.14 Mechanized Closure of Residual EC Axioms

**Stream ID**: `EC-AXIOM-CLOSURE`
**Owner**: Lux + formal-methods specialist (subcontractor)
**Current state** (2026-05-18): 71 residual axioms enumerated in
`AXIOM-INVENTORY.md`, distributed roughly as:

| Category | Count | Discharge plan |
|---|---:|---|
| Stage-level byte-walk axioms (z, h on sign and combine sides) | 3 | Decompose via narrower sub-axioms (v8/v11/v12 pattern); some are open research (κ-loop) |
| Combine z extraction (aggregation shape + per-party PR) | 2 | Byte-walk through extraction; mechanical |
| w sub-stage axioms (combine + sign) | 2 | ExpandA + ExpandMask + mat_vec_mul; addressable with codec mechanization |
| w_low sub-stage axioms (combine + sign) | 2 | Decompose structurally |
| matrix_a / mask_y sub-axioms | 4 | Discharge after codec mechanization |
| Codec mu_input layout (3 combine ranges + 1 sign) | 4 | Discharge with byte-layout codec mechanization |
| Accepted-path no-reject axioms | 2 | OPEN RESEARCH — κ-loop probabilistic Hoare model |
| Lean-bridged algebraic axioms | 5 | OPEN RESEARCH — checked Lean↔EC translation, OR port Mathlib polynomial-Lagrange theory to EC |
| Pack/unpack signature roundtrip | 2 | Discharge with codec mechanization |
| Per-type codec round-trips, length axioms, well-formedness | ~21 | BBD-scale codec mechanization (6 person-months) |
| MLDSA65_Functional internals (norms, hint weight, etc.) | ~7 | Concretize types; mechanical |
| Memory / share / N4 structural axioms | ~17 | Decomposable; many already narrow |

**Target end state (Q1 2029)**:
- AXIOM-INVENTORY.md drops from 71 to ≤ 15 (Lean-bridged + irreducible
  TCB-level axioms only).
- κ-loop probabilistic Hoare model published as a paper (CRYPTO /
  CCS / S&P paper) AND mechanized in EC.
- Bit-level FIPS 204 codec mechanization complete (matches BBD CRYPTO
  2023 in scope).
- Checked Lean↔EC translation tool **either** built and applied to
  reduce Lean-bridged axiom count to 0, **OR** documented as out-of-
  scope (Lean bridges remain as 5 informational items, not residual
  axioms on the proof cone).

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q4 2026 | Decompose `combine_body_{w,h}_spec`, `sign_body_{z,w,h}_spec` further | v14-v16: narrower sub-axioms per ExpandA / ExpandMask / mat_vec_mul / MakeHint patterns. Mechanical engineering. |
| Q1 2027 | Codec mechanization start | Engage academic collaborator (Manuel Barbosa or equivalent). 6 person-months work plan. |
| Q1 2027 | κ-loop research kickoff | Engage formal-methods specialist; scoping doc for the probabilistic Hoare model. |
| Q3 2027 | Codec round-1 deliverables | sigEncode / sigDecode mechanized. ~5 axioms discharged. |
| Q4 2027 | κ-loop model first draft | Probabilistic-Hoare compiled in EC; first attempt at no-reject discharge. |
| Q1 2028 | Codec round-2 deliverables | encode_sk / decode_sk + per-type length identities. ~10 axioms discharged. |
| Q3 2028 | κ-loop model published | Paper + EC mechanization; both `*_no_reject_*` discharged. |
| Q4 2028 | Codec round-3 deliverables | All ~21 codec axioms either discharged or replaced with narrower sub-axioms ≤ 5. |
| Q1 2029 | Lean↔EC translation decision | Either build a checked translation artifact and discharge the 5 Lean bridges; OR formalize "Lean bridge as TCB item, not residual axiom" and update PROOF-CLAIMS.md. |
| Q1 2029 | Final AXIOM-INVENTORY count | ≤ 15 residual; AXIOM-INVENTORY.md v2.0 released. |

**Dependencies**: §B.1 Pulsar (this stream's deliverables flow into
Pulsar's submission-package-shaped trust accounting); §B.2 Corona (will
inherit the codec mechanization).

**Risks**:

- **Research risk on κ-loop**: no published mechanization of an ML-DSA
  rejection-sampling loop at this granularity. The work may not close
  cleanly in 12 person-months. **Mitigation**: define a fallback —
  if probabilistic Hoare logic for the κ-loop is intractable, leave
  the two no-reject axioms in the inventory and document them as
  irreducible-without-new-research; the absence of closure does not
  block submission.
- **Research risk on Lean↔EC translation tool**: no published tool
  exists. Building one would itself be a publishable contribution
  (likely CSF / POPL / CPP venue). **Mitigation**: pursue translation
  only if academic collaboration is funded; otherwise treat Lean
  bridges as a TCB item with check-script enforcement and document
  accordingly.
- **Engineering risk on codec**: BBD's Dilithium mechanization (CRYPTO
  2023) is the comparison; their effort was ~6 person-months by a
  specialist team. Lux's codec mechanization could match that. Risk
  is on Lux finding a comparable specialist. **Mitigation**: engage
  academic collaborator (HACSPEC + Cryspen consortium, Charlie Jacomme
  at Inria, or HACL* / fstar team at Microsoft Research).

**Effort estimate**:

| Sub-task | Person-weeks |
|---|---:|
| Decomposition engineering (stage-level + sub-stage) | 30 |
| Codec mechanization (BBD-scale) | 80 |
| κ-loop probabilistic Hoare model | 60 |
| Lean↔EC translation research / port | 40 (if pursued) |
| **Total** | **170-210** depending on translation choice |

**Acceptance gate**: AXIOM-INVENTORY.md count ≤ 15 (residual); first
academic paper on the κ-loop model accepted at a top venue OR
self-archived on IACR ePrint with positive review.

---

### §B.15 External Cryptographic + Implementation + Side-Channel Audits

**Stream ID**: `EXTERNAL-AUDITS`
**Owner**: Lux security lead (engagement) + Lux crypto-engineering (remediation)
**Current state**:
- No external audit completed on Pulsar v0.1 submission package.
- Internal 4-red-agent + 1-scientist audit dated 2026-05 closed 13/13
  blockers (BLOCKERS.md).

**Target end state (Q3 2029)**:
- Three independent external audits completed:
  1. Cryptographic correctness + protocol design (Cryspen / NCC Group /
     Trail of Bits / Kudelski — pick two for redundancy).
  2. Implementation correctness (Rust + C + WASM production targets) —
     same lab pool.
  3. Side-channel / fault-injection (NCC Group hardware team /
     Rambus / Riscure / FortifyIQ).
- All critical / high findings remediated in shipping artifacts.
- Audit reports published with Lux response document.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q4 2026 | Audit Round 1 scoping | RFPs to three labs (cryptographic). |
| Q1 2027 | Audit Round 1 engagement | One lab engaged; 8-12 week engagement. |
| Q2 2027 | Audit Round 1 report | Findings delivered; severity classification; remediation tracker. |
| Q3 2027 | Audit Round 1 remediation | All C / H findings closed in main branch. |
| Q4 2027 | Audit Round 1 publication | Audit report + Lux response published in `audits/cryptographic-round-1/`. |
| Q1 2028 | Audit Round 2 scoping (implementation) | RFPs out for production-target audit. |
| Q2-Q3 2028 | Audit Round 2 engagement + report | |
| Q4 2028 | Audit Round 2 remediation + publication | |
| Q1 2029 | Audit Round 3 scoping (side-channel) | RFPs to hardware-side-channel labs. |
| Q2-Q3 2029 | Audit Round 3 engagement + report + remediation + publication | |

**Dependencies**: §B.1, §B.5, §B.6, §B.8 (production-target readiness
of each construction).

**Risks**:

- **Lab availability**: PQ-specialist labs are limited. **Mitigation**:
  engage in two waves; don't put all audits on one lab.
- **Findings volume**: external audits typically surface findings that
  internal audits missed. **Mitigation**: budget Q3 2027 remediation
  as a real workstream; don't treat audit report as a one-week task.
- **Costs**: USD 250-400 k per cryptographic audit, USD 100-300 k for
  implementation audits, USD 150-300 k for hardware-side-channel.
  Total roadmap audit budget: USD 0.9 M - 1.6 M.

**Effort estimate**: 90 person-weeks (engagement + remediation).

**Acceptance gate**: Three published audit reports; all C/H findings closed.

---

### §B.16 NIST MPTC Standardization Track

**Stream ID**: `NIST-MPTC-TRACK`
**Owner**: Lux MPTC coordinator + outside policy contact (NIST liaison)
**Current state**:
- Pulsar v0.1 packaged for the 2026-11-16 deadline.
- No prior NIST submission contact.

**Target end state (Q4 2029)**:
- Pulsar accepted to whatever NIST process round follows submission.
- Public-comment-response posted to the NIST mailing list addressing
  any community analysis.
- (Lux-controlled actions only — NIST ratification timing is NOT in
  Lux's control.)

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q4 2026 | Submission tarball delivered | `submission-2026-11-16` tag; tarball uploaded to NIST submission portal by 2026-11-16. |
| Q1 2027 | Submission acknowledgment | NIST acknowledges receipt; Lux publishes submission package mirror on `github.com/luxfi/pulsar-mptc` `Releases`. |
| Q2 2027 | Public-analysis monitoring | Track community analysis on the NIST MPTC mailing list and IACR ePrint. |
| Q3 2027 | Public response (round 1) | Lux response to any community-raised analysis. |
| Q4 2027 | Submission revision (if requested) | If NIST asks for clarifications, deliver `submission-2027-XX` package. |
| Q2 2028 | NIST workshop participation | Present Pulsar at NIST MPTC workshop (if held). |
| Q1 2029 | Round-2 submission (if NIST formats a round-2) | Update submission per NIST round-2 framework. |
| Q4 2029 | Standardization process continues | Continue as NIST's process dictates. |

**Dependencies**: §B.1 (post-submission proof work).

**Risks** (mostly out of Lux's control):

- **NIST decision**: NIST may decline to standardize Pulsar (or any
  threshold ML-DSA). Lux cannot control this. **Mitigation**: ensure
  the Pulsar IETF/CFRG track (§B.17) is independent of NIST's
  decision — IETF can publish a Pulsar RFC even if NIST does not
  standardize. The Lux production deployment also does not require
  NIST ratification.
- **Round structure**: NIST has not announced the round structure
  for MPTC (unlike PQC's 4-round process). The roadmap assumes a
  multi-round process by analogy; this could differ.

**Effort estimate**: 25 person-weeks (mostly coordination + response writing).

**Acceptance gate**: Submission delivered; NIST acknowledgment received;
public-comment response published.

---

### §B.17 IETF / CFRG Standardization Track

**Stream ID**: `IETF-CFRG-TRACK`
**Owner**: Lux IETF liaison (engages CFRG mailing list)
**Current state**:
- `docs/ietf-draft-skeleton.md` is a complete Internet-Draft (no longer
  skeleton — covers all required sections through §19 + appendices).

**Target end state (Q4 2029)**:
- `draft-hanzo-pulsar-threshold-mldsa-NN` adopted as CFRG working-group
  document (`draft-irtf-cfrg-pulsar-threshold-mldsa-NN`).
- RFC publication (target — outside Lux's control).
- Parallel CFRG drafts for Corona, FROST (Lux profile), CGGMP21 (Lux
  profile), BLS (Lux profile), X-Wing-Sig.

**Per-quarter milestones**:

| Quarter | Milestone | Scope |
|---|---|---|
| Q4 2026 | Pulsar -00 to datatracker | Submit `draft-hanzo-pulsar-threshold-mldsa-00` to IETF datatracker. |
| Q1 2027 | CFRG mailing-list review | Initial review thread; respond to feedback. |
| Q2 2027 | -01 revision | Per feedback. Submit X-Wing-Sig -00. |
| Q3 2027 | -02 revision | Submit Corona -00. |
| Q4 2027 | CFRG adoption call (Pulsar) | Request adoption as WG document. |
| Q1 2028 | LSS -00 submitted | |
| Q2 2028 | FROST Lux profile -00 submitted | |
| Q4 2028 | CGGMP21 Lux profile -00 + BLS Lux profile -00 submitted | |
| Q2 2029 | Pulsar working-group draft milestones | If adopted, follow WG editor cadence. |
| Q4 2029 | Multiple drafts in WG advancement | |

**Dependencies**: All §B.4-§B.8 streams (each contributes a draft).

**Risks** (out of Lux's control):

- **CFRG adoption**: CFRG may decline to adopt Pulsar; or may prefer
  a different threshold-ML-DSA construction. **Mitigation**: respond
  to comparison-with-alternatives questions in the draft; engage the
  research community via IACR ePrint preprint.
- **WG editor velocity**: IETF WG processes are slow (years). **Mitigation**:
  decouple Lux production deployment from RFC publication.

**Effort estimate**: 30 person-weeks (across all drafts; mostly response
writing + editor cycles).

**Acceptance gate**: At least one Lux-authored draft adopted by CFRG
as a working-group document; multiple drafts in active flight.

---

### §B.18 FIPS 140-3 Module Validation Track

**Stream ID**: `FIPS-140-3-MODULE`
**Owner**: Lux KMS / module-engineering team
**Current state**:
- No Lux module currently submitted to CMVP.
- Pulsar reference implementation is NOT a FIPS module; it's a reference
  algorithm.

**Target end state (Q4 2029)**:
- At least one Lux module packaging Pulsar (e.g., Lux KMS HSM) submitted
  to CMVP and progressing toward CAVP-validated → CMVP-validated.
- (CMVP certificate issuance is outside Lux's control and the queue
  is 12-24 months at current cadence.)

**Per-quarter milestones**:

| Quarter | Milestone |
|---|---|
| Q3 2027 | FIPS 140-3 module scope definition |
| Q4 2027 | Lab engagement (atsec / Acumen / Leidos) |
| Q1 2028 | Module packaging + documentation |
| Q2 2028 | Lab-conducted FIPS 140-3 testing |
| Q3 2028 | Submission to CMVP |
| 2029+ | CMVP queue (cert issuance outside Lux control) |

**Effort estimate**: 60 person-weeks.

**Acceptance gate**: CMVP submission with a tracker number. Cert
issuance is the CMVP's clock.

---

### §B.19 ACVP / CAVP Algorithm Validation Track

**Stream ID**: `ACVP-CAVP-TRACK`
**Owner**: Lux KMS / module-engineering team
**Current state**:
- Reference implementation cross-validated against three independent
  ML-DSA implementations (pq-crystals, circl, BoringSSL FIPS) — see
  `docs/evaluation.md` §4.
- No ACVP/CAVP lab engagement yet.

**Target end state (Q3 2028)**:
- ACVP/CAVP certificate issued for Pulsar reference implementation
  ML-DSA-65 conformance.
- Same for ML-KEM-768 + X-Wing (if applicable to Lux's CAVP scope).
- Same for SLH-DSA SHAKE-192s (if Magnetar / SLH-DSA usage matures
  in time).

**Per-quarter milestones**:

| Quarter | Milestone |
|---|---|
| Q3 2027 | ACVP lab engagement (atsec / Acumen / Leidos) |
| Q4 2027 | ACVP test campaign |
| Q1 2028 | CAVP certificate (target — outside Lux control) |
| Q2 2028 | Cert documented in `FIPS-TRACEABILITY.md` |
| Q3 2028 | ML-KEM + X-Wing campaigns (if in scope) |

**Effort estimate**: 25 person-weeks.

**Acceptance gate**: CAVP certificate number recorded in
`FIPS-TRACEABILITY.md` §13.

---

### §B.20 Patent Prosecution

**Stream ID**: `PATENT-PROSECUTION`
**Owner**: Lux legal counsel + external patent attorney
**Current state**:
- `PATENTS.md` (royalty-free grant) published.
- `docs/patent-claims.md` (21 numbered claims, 5 claim groups) ready
  for attorney prep.
- No provisional filed yet.

**Target end state (Q4 2029)**:
- US provisional application filed BEFORE 2026-11-16 (preserves
  priority before NIST submission becomes public).
- PCT international application filed within 12 months of provisional.
- EPO + national-phase entries at 30-month PCT deadline.
- Continuation / divisional strategy executed.

**Per-quarter milestones**:

| Quarter | Milestone |
|---|---|
| Q3 2026 | Attorney engagement |
| Q3 2026 | US provisional drafted from `docs/patent-claims.md` |
| **Before 2026-11-16** | **US provisional filed (CRITICAL — preserves priority)** |
| Q4 2027 | PCT international filed (within 12 months of provisional) |
| Q3 2029 | National-phase entries (PCT 30-month deadline) |
| Ongoing | Continuations for v8 Lean-bridged aggregation identity, v6 ExternalMu layout, N4 reshare algorithm |

**Dependencies**: `docs/patent-claims.md` (already drafted).

**Risks**:

- **Priority loss**: NIST submission counts as public disclosure
  under 35 USC §102. Filing the provisional AFTER the NIST submission
  loses foreign-filing rights. **Mitigation**: file the US
  provisional BEFORE 2026-11-16 (NIST submission deadline).
- **Cost**: USD 50-150 k for provisional + PCT + 5-7 jurisdiction
  national-phase entries.

**Effort estimate**: 10 person-weeks (Lux side; attorney drives).

**Acceptance gate**: US provisional filed; PCT filed; national-phase
entries on track.

---

### §B.21 Documentation + Governance

**Stream ID**: `DOCS-GOVERNANCE`
**Owner**: Lux crypto-suite maintainer (`crypto-suite@lux.network`)
**Current state**:
- `lps/CRYPTO-CANONICAL.md` is the master crypto wiring doc.
- `pulsar-mptc/INFORMATION-ARCHITECTURE.md` documents three-axis taxonomy.
- LPs 168-179 mirror Hanzo HIPs 0077-0104 for E2E PQ.
- `pulsar-mptc/SUITE.md` + `pulsar-mptc/HANZO-CRYPTO-SUITE.md` are master
  indexes.

**Target end state (Q4 2029)**:
- Every construction in the Lux crypto suite has its own LP-NNN
  (canonical spec), repo (`~/work/lux/<name>/`), and (when production)
  submission-package.
- `lps/CRYPTO-CANONICAL.md` stays in sync with implementation truth.
- Quarterly review cadence: each quarter, the crypto-suite maintainer
  publishes a single LP-NNN status doc updating progress against this
  ROADMAP.

**Per-quarter cadence**: end-of-quarter review and LP updates.

**Effort estimate**: 20 person-weeks across 3 years.

**Acceptance gate**: `lps/CRYPTO-CANONICAL.md` matches grep of repo
state; no orphan crypto code lacking an LP.

---

### §B.22 Production Library Targets

**Stream ID**: `PROD-TARGETS`
**Owner**: Lux production-eng + bindings team
**Current state**:
- Pulsar reference implementation in Go (`ref/go/`).
- Corona reference implementation in Go (`~/work/lux/corona/`).
- LuxCpp + Lux-crypto in C++ + CUDA + Metal + WGSL.
- No Rust crate, no standalone C library + FFI for Pulsar, no WASM
  build, no no_std embedded target.

**Target end state (Q3 2028)**:
- `lux-pulsar` Rust crate (no_std capable, audited).
- `libpulsar.so` C library + `pulsar.h` FFI (audited).
- `pulsar.wasm` WASM build (audited).
- `pulsar-no_std` embedded target (no allocator, fixed-size buffers).
- Language bindings: Python (via cffi), JS/TS (via WASM), Java (via JNI).

**Per-quarter milestones**:

| Quarter | Milestone |
|---|---|
| Q2 2027 | Rust crate v0.1 (alpha) |
| Q3 2027 | C library + FFI |
| Q4 2027 | WASM build |
| Q1 2028 | no_std embedded port |
| Q2 2028 | Python + JS + Java bindings |
| Q3 2028 | All targets audited |

**Dependencies**: §B.15 (external audits).

**Risks**: each language target is a fresh CT analysis. **Mitigation**:
each target ships its own jasmin-ct or dudect verification before
v1.0 tag.

**Effort estimate**: 70 person-weeks.

**Acceptance gate**: All targets have CI-gated CT checks; published
to crates.io / npm / PyPI / Maven Central with semver.

---

### §B.23 Ecosystem Integration

**Stream ID**: `ECOSYSTEM-INTEGRATION`
**Owner**: Lux developer-relations + bridge / consensus consumer teams
**Current state**:
- Pulsar used by Lux Quasar consensus, KMS, MPC.
- Not yet integrated with external ecosystems (Cosmos, Substrate,
  Sigstore, etc.).

**Target end state (Q4 2029)**:
- Solidity verifier contract for Pulsar signatures (gas-cost-tuned).
- Cosmos SDK module for Pulsar threshold validator signing.
- Substrate pallet for Pulsar consensus.
- Tendermint signer plugin for Pulsar.
- Sigstore experiment: Pulsar as a Rekor signing identity.
- Validator-set rotation playbook (Class N4 reshare in production).

**Per-quarter milestones**:

| Quarter | Milestone |
|---|---|
| Q2 2027 | Solidity verifier contract (gas-cost tuned) |
| Q4 2027 | Cosmos SDK module (community contribution welcomed) |
| Q1 2028 | Substrate pallet |
| Q2 2028 | Tendermint signer plugin |
| Q3 2028 | Sigstore experiment |
| Q4 2028 | Validator-set rotation playbook |

**Effort estimate**: 40 person-weeks (mostly community / outreach).

**Acceptance gate**: At least one external project adopts Pulsar in
production (signal: not Lux-internal).

---

## §C Quarterly View

This table cross-references the work streams above. **Effort** is the
sum of person-weeks targeted in that quarter across all active
streams. Streams overlap; effort sums approximate the staffing target.

| Quarter | Active streams | Key deliverable milestones | Dependencies satisfied | Effort (person-weeks) |
|---|---|---|---|---:|
| **Q4 2026** | B.1, B.2, B.8, B.14, B.15, B.16, B.17, B.20 | **NIST MPTC submission delivered (2026-11-16)**; X-Wing-Sig LP + draft -00; US provisional patent **filed before 2026-11-16**; Corona spec extracted; codec decomposition v14 | NIST submission deadline | 35 |
| **Q1 2027** | B.1, B.2, B.4, B.5, B.6, B.13, B.14, B.15, B.16, B.17, B.21, B.22 | External audit Round 1 engagement; κ-loop research kickoff; codec mechanization start; FROST + LSS spec extraction; Z-Chain repo created; Solidity verifier prototype | First external audit lab engaged | 75 |
| **Q2 2027** | B.1, B.2, B.5, B.8, B.11, B.13, B.14, B.21, B.22 | Audit Round 1 report; Pulsar EC sub-stage decomposition v15; FROST Jasmin sources; P3Q precompile impl; threshold TFHE bootstrap DKG; Rust crate v0.1 | Lean composition theorem for X-Wing-Sig drafted | 75 |
| **Q3 2027** | B.1, B.2, B.3, B.4, B.5, B.6, B.7, B.11, B.13, B.14, B.16, B.18 | Audit Round 1 remediation; FROST IETF draft; ACVP lab engagement; FIPS module scoping; P3Q testnet; Z-Chain pulsar-abort circuit; codec round-1 axioms discharged | Corona EC scaffolding done | 80 |
| **Q4 2027** | B.1, B.6, B.8, B.11, B.13, B.14, B.18, B.20 | CGGMP21 EC scaffolding; X-Wing-Sig external review; P3Q mainnet rollout; PCT international filed; κ-loop model first draft | PCT filing deadline | 70 |
| **Q1 2028** | B.1, B.6, B.9, B.10, B.12, B.13, B.14, B.18, B.19, B.20, B.22 | ACVP/CAVP certificate (target); C-Chain testnet PQ-native; X-Chain devnet impl; Z-Chain devnet integration; FIPS module packaging; codec round-2 axioms; Rust no_std port | First ACVP cert target | 80 |
| **Q2 2028** | B.1, B.5, B.7, B.8, B.9, B.10, B.12, B.15, B.18, B.20, B.22 | FIPS module submission to CMVP; C-Chain mainnet PQ-native opt-in; BLS Lux profile IETF draft; Audit Round 2 engagement; bindings released | First mainnet PQ-account live | 80 |
| **Q3 2028** | B.1, B.3, B.6, B.9, B.10, B.13, B.14, B.15, B.18, B.19, B.22, B.23 | κ-loop model paper submitted; F-Chain mainnet threshold-TFHE; X-Chain mainnet PQ; CGGMP21 IETF draft; production targets audited; Sigstore integration | F-Chain TFHE mainnet | 80 |
| **Q4 2028** | B.1, B.3, B.10, B.12, B.14, B.15, B.21, B.23 | Magnetar v0.1 package; Z-Chain mainnet PQ identity; codec round-3 axiom closure; Audit Round 2 remediation; Magnetar paper draft; validator-rotation playbook | Mainnet Z-Chain abort proofs | 75 |
| **Q1 2029** | B.1, B.10, B.14, B.15, B.20 | X-Chain mainnet bridge integration; AXIOM-INVENTORY v2.0 (≤ 15 residual); Audit Round 3 scoping; national-phase patent entries | All PQ-native on mainnet | 65 |
| **Q2 2029** | B.1, B.15, B.16, B.17 | Audit Round 3 engagement; CFRG WG draft milestones; multiple drafts active | | 60 |
| **Q3 2029** | B.1, B.15, B.19 | Audit Round 3 report + remediation; ACVP cert for ML-KEM + SLH-DSA additions | | 50 |
| **Q4 2029** | B.1, B.16, B.17, B.21 | NIST process continuation; multiple CFRG WG drafts in flight; roadmap retrospective | | 40 |

**Total effort across 13 quarters**: ~890 person-weeks (sum of
quarterly columns; some double-counting across streams). Headcount
implication: 6-8 senior crypto-FM engineers at full staffing across
the 3 years.

---

## §D Critical-Path Analysis

### §D.1 Longest dependency chain

The single longest dependency chain in this roadmap is the
**production PQ-native chain**:

```
Pulsar v0.1 NIST submission (2026-11-16)
   ↓
External cryptographic audit Round 1 (Q1 2027 - Q3 2027, ~6 months)
   ↓
ACVP/CAVP engagement (Q3 2027 - Q1 2028, ~6 months, external timing)
   ↓
ACVP cert issuance (Q1-Q2 2028, lab-controlled)
   ↓
FIPS 140-3 module packaging + lab testing (Q2 2028, internal + lab)
   ↓
FIPS 140-3 module CMVP submission (Q3 2028)
   ↓
CMVP certificate issuance (2029+, queue-dependent — outside Lux control)
   ↓
C-Chain PQ-native deployment with FIPS-validated module (2029+)
```

**Wall-clock floor**: ~3 years from submission to FIPS-validated module
running on C-Chain mainnet — and the last leg's timing is controlled
by CMVP queue, not Lux. If CMVP queue is 24 months instead of 12, the
endpoint slips to 2030+.

### §D.2 Cryptographic-research blockers gating everything else

These three open-research items each gate substantial downstream work:

1. **κ-loop probabilistic Hoare model**. Blocks: full discharge of
   the two `*_no_reject_on_accepted_honest_layout` axioms. Without
   closure, AXIOM-INVENTORY.md keeps these two items indefinitely.
   No published reduction at this scale exists in the EasyCrypt
   literature. **Estimate**: 60 person-weeks of dedicated specialist
   work + paper publication.
2. **Bit-level FIPS 204 codec mechanization**. Blocks: full discharge
   of ~21 codec round-trip axioms. Comparable to Barbosa-Barthe-Dupressoir
   CRYPTO 2023 Dilithium mechanization (~6 person-months for a
   specialist team). Lux + academic-collaborator engagement required.
3. **Checked Lean↔EasyCrypt translation tooling**. Blocks: discharge of
   the 5 Lean-bridged algebraic axioms as derived lemmas inside EC.
   No published tool exists. Building one would itself be a publishable
   paper (likely CSF / POPL / CPP venue). **Alternative**: leave Lean
   bridges as TCB items with check-script enforcement; the proof is
   no weaker, but the trust framing differs. **Decision deferred**
   to Q1 2029 in stream B.14.

### §D.3 Engineering-bottleneck items

These are items where engineering work is the rate-limiter, not research:

1. **Rust crate** is required for ecosystem integration (Cosmos SDK,
   Substrate pallet, Sigstore). Blocked on FFI design freeze + audit.
   Rust crate target Q2 2027.
2. **P3Q precompile** mainnet rollout blocks C-Chain native PQ migration.
   Q4 2027 mainnet target (per stream B.11).
3. **Corona EC proof scaffolding** is the bottleneck for Corona
   submission packaging. Q1 2027 milestone in stream B.2.
4. **Pulsar Jasmin threshold sources** are mature; the bottleneck for
   Corona is whether the libjade R-LWE single-party baseline exists
   (no, must be written).
5. **CFRG adoption of Pulsar draft** is outside Lux's engineering
   control but blocks the IETF stream. Q4 2027 adoption-call target.

---

## §E Risk Register

| Risk | Probability | Impact | Mitigation | Owner |
|---|---|---|---|---|
| **NIST does not standardize Pulsar** | Medium | Medium — Lux production deployment does not require NIST ratification, but FIPS 140-3 path is weakened | Pursue IETF/CFRG track independently; ensure Lux mainnet deployment is operational regardless | Lux MPTC coordinator |
| **IETF / CFRG does not adopt Pulsar draft as WG** | Medium | Low — Lux can publish as Independent Stream or via different SDO | Engage CFRG mailing list early; respond to comparison-with-alternatives feedback | Lux IETF liaison |
| **FIPS 140-3 module certificate slips to 2030+** | High | Medium — CMVP queue is slow; this is structural | Treat certificate issuance as outside Lux control; document submission status as the Lux-controlled artifact | Lux KMS team |
| **κ-loop probabilistic Hoare model intractable in 12 months** | Medium | Low — axioms remain in inventory, but the inventory is honest about that; no false claim of closure | Define fallback in stream B.14; ship submission package with operational acceptance bound | Lux + FM specialist |
| **Codec mechanization (BBD-scale) does not complete by Q4 2028** | Medium | Low — partial discharge is still axiom-reduction; full closure can slip | Phase the mechanization (signature encode/decode first; per-type round-trips later); commit to partial-closure deliverables | Lux + academic |
| **External audit surfaces critical / high findings affecting Pulsar correctness** | High | High — could invalidate Class N1 byte-equality claim | Budget Q3 2027 remediation as a real workstream; maintain CI for regression prevention | Lux + audit lab |
| **External audit surfaces architectural design flaw** | Low | Very High — could require protocol redesign | Internal red-team rounds before external engagement (already done 2026-05); maintain `BLOCKERS.md` discipline | Lux crypto-engineering |
| **Patent counsel does not file US provisional before 2026-11-16** | Low | Very High — loses foreign-filing rights; NIST submission becomes 35 USC §102 prior art | Critical-path item; engage counsel Q3 2026 with explicit calendar deadline | Lux legal |
| **Magnetar research direction does not converge into a spec** | Medium | Low — Tier 3 is research; non-convergence is honest framing, not failure | Treat Magnetar as research not engineering; downgrade gracefully if construction is impractical | Lux + academic |
| **Lean Mathlib breaking change invalidates bridges** | Medium | Medium — would force re-pinning Lean toolchain or porting Mathlib version | Pin Lean toolchain at known-good commit; CI canary against Mathlib head | Lux FM |
| **EasyCrypt soundness bug discovered** | Low | Very High — would invalidate the EC proof if the bug is in the relevant tactic | Cross-validate critical theorems via `byphoare` AND `equiv`; track EC bug reports | Lux FM |
| **C-Chain PQ migration breaks legacy wallets** | Medium | High — could brick user accounts during transition | Soft-fork-first migration; legacy ECDSA never deprecated absent hard-fork vote; long transition window | Lux EVM |
| **P3Q precompile gas pricing too expensive for adoption** | Medium | Medium — would limit C-Chain PQ-native usage | Batch-verify multiple signatures per call; revisit pricing post-mainnet | Lux EVM |
| **Z-Chain abort circuit's classical-only ZK is broken by quantum** | Low (5-15 yr horizon) | High when realized | Begin long-term plan for PQ-ZK (STARK + FRI) integration; state classical-only assumption clearly in LP-169 | Lux Z-Chain |
| **Threshold TFHE bootstrap is impractical (performance)** | High | Medium — limits FHE applicability | Focus on use cases where bootstrap is a one-time cost; treat per-operation bootstrap as v0.2+ goal | Lux FHE |
| **Lab availability constrained** (ACVP + FIPS 140-3 + audits all competing for same labs) | High | Medium — slips milestones in B.15, B.18, B.19 | Engage labs in parallel; line up alternates | Lux security lead |
| **Senior crypto-FM specialist hiring difficulty** | High | High — the κ-loop and codec work both require specialists | Engage academic collaborators (HACSPEC + Cryspen consortium, INRIA, MPI-SP) as a fallback to internal hiring | Lux engineering management |
| **Audit budget exceeds USD 1.6 M over 3 years** | Medium | Medium — could force scope reduction | Stage audits in 3 rounds rather than 1 big-bang; prioritize Pulsar Round 1 over rounds 2 + 3 | Lux finance |

---

## §F What This Roadmap Explicitly Does NOT Promise

Per the honest-no-overclaiming discipline:

1. **This roadmap does NOT promise NIST ratification of Pulsar.** NIST
   has its own process and its own analysis; Lux can submit and
   respond, but the standardization decision is NIST's. The roadmap
   describes Lux's submission cadence, not NIST's decision cadence.
2. **This roadmap does NOT promise IETF RFC publication of any draft.**
   IETF working groups have their own adoption and editor cadence; we
   describe Lux's draft-submission and revision activity, not RFC issuance.
3. **This roadmap does NOT promise FIPS 140-3 certificate issuance.**
   CMVP queue timing is external; we promise submission, not issuance.
4. **This roadmap does NOT promise ACVP/CAVP certificate issuance.**
   Lab availability and test campaign duration are external; we
   promise lab engagement, not cert issuance.
5. **This roadmap does NOT promise that ML-DSA's lattice hardness
   assumption is settled.** FIPS 204's analysis is taken at face value
   per `PROOF-CLAIMS.md` §3.1. If a future cryptanalytic break weakens
   M-LWE / M-SIS, Pulsar inherits that risk — the EC proof artifact
   is implementation-correctness, not hardness.
6. **This roadmap does NOT promise that 100% of residual axioms will
   be mechanically closed by Q4 2029.** Some are open research (κ-loop;
   Lean↔EC translation); some are gated on multi-person-month
   specialist work (codec mechanization). The target is ≤ 15 residual
   axioms; reaching 0 is a longer-term goal.
7. **This roadmap does NOT promise that every quarterly milestone
   will hit on time.** Research projects slip, audits surface
   findings that require rework, external dependencies have their
   own clocks, and senior specialist hiring is hard. Plan for slip;
   prioritize Q4 2026 NIST submission, US provisional filing, and
   external-audit engagement as the unconditional commitments.
8. **This roadmap does NOT promise that Magnetar will reach
   production-ready threshold SLH-DSA.** Magnetar is research-track.
   Threshold SLH-DSA may be impractical at FIPS 205's parameter sets;
   if so, the roadmap downgrades Magnetar accordingly.
9. **This roadmap does NOT promise that Z-Chain PQ-identity rollup
   will be quantum-secure.** Groth16 over BN254 is classically secure
   but quantum-vulnerable. A future PQ-ZK migration (STARK + FRI) is
   on the roadmap conceptually but not concretely scheduled within
   3 years.
10. **This roadmap does NOT promise that the C-Chain / X-Chain PQ
    migration will be complete by end of Q4 2029.** It promises that
    PQ-native account types are live; legacy ECDSA accounts may persist
    for years (decades) past the roadmap horizon.
11. **This roadmap does NOT promise zero-incident execution.** Critical
    security findings will be discovered; the discipline is rapid
    remediation and transparent disclosure (per `SECURITY.md`).
12. **This roadmap does NOT promise that audit findings will all be
    "informational".** External audits typically surface critical /
    high findings even on hardened code. The promise is remediation
    cadence, not finding absence.

---

## §G Concrete Next-30-Days Actions (As Of 2026-05-18)

Regardless of the multi-year plan, these items must complete in the
next 30 days:

### G.1 Patent priority preservation

1. **Engage patent counsel within 7 days.** Recommended firm: Cooley LLP
   or Knobbe Martens (PQ patent experience) — alternates: Wilson Sonsini,
   Fenwick & West. Brief them on `docs/patent-claims.md` and PATENTS.md.
2. **File US provisional within 14 days** (so anchor date is well
   before 2026-11-16 NIST submission). Draft from `docs/patent-claims.md`
   Claim Groups A, B, C, D, E. Filing fee USD 320 (small entity) +
   attorney draft.
3. **Inventor identification**. Lux Industries cryptography team
   inventors per `docs/patent-claims.md` §0. Confirm + sign IP
   assignment agreements.

### G.2 NIST MPTC submission preparation

4. **Cut release-candidate tag** within 14 days: `submission-rc-2026-11-16-01`
   from current `main`. Validate `scripts/build.sh` + `scripts/check-high-assurance.sh`
   + `scripts/test.sh` + `scripts/bench.sh` all green on a fresh clone.
5. **Reviewer-mirror checklist**: confirm `spec/pulsar.pdf` builds
   reproducibly, `vectors/` regenerates deterministically from the
   committed seed, the `submission-` tag references are consistent.
6. **Final pass on AXIOM-INVENTORY.md** — re-grep `grep -rEn "^axiom\s+\w" proofs/easycrypt/`
   and confirm the document's enumerated count matches the raw grep.
   Currently 71 axioms; document text claims "~36 named axioms on the
   corollary cone"; reconcile or explain the discrepancy.
7. **Wait period**: do NOT cut the final `submission-2026-11-16` tag
   until US provisional is filed.

### G.3 External audit scoping

8. **Issue three audit RFPs within 30 days**. Recommended labs:
   - **Cryspen** (`info@cryspen.com`) — strong HACL* / formal-methods
     adjacency; ideal for the proof-artifact-led portion.
   - **NCC Group cryptography practice** (`cryptoservices@nccgroup.com`) —
     hardware-side-channel partner for B.15 Round 3.
   - **Trail of Bits** (`hello@trailofbits.com`) — implementation focus.
   - Alternate: **Kudelski Security** (`security.communications@nagra.com`),
     **Atredis Partners**, **Quarkslab**.
   Scope each RFP: Pulsar v0.1 submission package (spec + ref impl +
   EC proofs + Jasmin sources + KAT vectors). Budget: USD 250-400 k
   per audit. Engagement: Q1 2027 start.

### G.4 IETF / CFRG engagement

9. **Submit `draft-hanzo-pulsar-threshold-mldsa-00` to IETF datatracker**
   within 30 days. Convert `docs/ietf-draft-skeleton.md` from Markdown
   to XML2RFC v3 via `mmark` or `kramdown-rfc`. Author block: Lux
   Industries cryptography team. Expiration date: 6 months from submit.
10. **Post Pulsar announcement to CFRG mailing list** (`cfrg@irtf.org`)
    on the same day as draft submission. Subject:
    `[CFRG] Pulsar — threshold ML-DSA-65 with byte-identical FIPS 204 output`.
    Reference the draft + the github repo. Invite review.

### G.5 Public-channel readiness

11. **Open public GitHub Discussions** at `https://github.com/luxfi/pulsar-mptc/discussions`
    with categories: `nist-submission`, `proofs`, `magnetar`, `corona`,
    `general-q-and-a`. Pin a "Reviewer Onboarding" thread with the
    `SUBMISSION.md` reading order.
12. **Publish blog post / announcement** on `lux.network` and IACR ePrint
    (IACR ePrint preprint number assigned once submitted). Tie to the
    NIST submission deadline.

### G.6 Stream B.1 immediate sub-tasks (within 30 days)

13. **Begin codec decomposition v14** (`stage-level → narrower sub-axioms
    for combine_body_h_spec`) in a feature branch. Land within 30 days.
    No external dependency; mechanical engineering. Trust footprint
    drops by 1 axiom.
14. **Document discrepancy** between AXIOM-INVENTORY.md "~36 axioms"
    and `grep` raw count of 71. Likely explanation: 71 includes
    internal axioms not on the corollary cone (MLDSA65_Functional
    internals, share-structure axioms). Update AXIOM-INVENTORY.md
    §0 trust-footprint summary table to reconcile.

### G.7 Critical-path summary

The unconditional commitments in the next 30 days:

1. **Engage patent counsel** (week 1)
2. **File US provisional** (before week 3)
3. **Issue audit RFPs** (week 4)
4. **Submit IETF draft -00** (by week 4)

Everything else is desirable but can slip by ≤ 30 days without invalidating
the Q4 2026 NIST submission deadline.

---

## §H Roadmap Maintenance

This document is the authoritative crypto-stack roadmap. It supersedes
prior ad-hoc planning in `HANZO-CRYPTO-SUITE.md` §"Recommended next-quarter
work plan" and `SUITE.md` §"Equivalent-packaging roadmap".

**Update cadence**:
- End-of-quarter: roadmap maintainer publishes a 1-page status update
  citing this document with green/yellow/red status per stream.
- Mid-year: full roadmap revision; re-estimate effort, re-prioritize
  risks, update milestone dates.
- Each NIST / IETF / FIPS round: insert a status row in the relevant
  stream's milestone table.

**Where to track progress**:
- Per-stream progress: each stream's "Acceptance gate" item is a
  github milestone in the relevant repo.
- Cross-stream progress: `lps/CRYPTO-CANONICAL.md` updates per
  quarter.
- Audit findings: `audits/<lab>-<year>/findings.md` per engagement.
- External-body status: `external/{nist,ietf,fips140,acvp}/status.md`.

---

**Document metadata**

- Name: `ROADMAP.md`
- Version: v1.0 (initial)
- Date: 2026-05-18
- Maintainer: `crypto-suite@lux.network`
- Companion documents: `SUITE.md`, `HANZO-CRYPTO-SUITE.md`,
  `INFORMATION-ARCHITECTURE.md`, `SUBMISSION.md`, `AXIOM-INVENTORY.md`,
  `PROOF-CLAIMS.md`, `TRUSTED-COMPUTING-BASE.md`, `FIPS-TRACEABILITY.md`,
  `BLOCKERS.md`, `PATENTS.md`, `docs/patent-claims.md`,
  `docs/evaluation.md`, `docs/ietf-draft-skeleton.md`,
  `docs/magnetar.md`, `docs/x-wing-sig.md`, `lps/CRYPTO-CANONICAL.md`,
  LPs 019, 020, 062, 063, 066, 070, 072, 073, 075, 077, 078, 110, 115,
  134, 141, 154, 155, 167, 168-180.
- License: Apache-2.0 (consistent with `LICENSE`).
