# STATUS — Submission readiness

**Status: READY FOR SUBMISSION.**

Reviewer-facing checkpoint for the NIST MPTC v0.1 Pulsar package
(deadline 2026-11-16). The package is cut from a tag on `main` via
`scripts/cut-submission.sh`; this document is the live status pin.

## Headline

| Field | Value |
|---|---|
| Submission name | **Pulsar** (Tier 1, Hanzo PQ Threshold Suite) |
| Status | **READY FOR SUBMISSION** |
| Open items | **0** |
| Date of this declaration | 2026-05-31 |
| Date of NIST deadline | 2026-11-16 |

## Proof-gate dashboard (all green)

| Gate | Result | Source of truth |
|---|---|---|
| EasyCrypt admit budget | **0 / 0** hard-pinned | `scripts/checks/ec-admits.sh` |
| EasyCrypt files compile | **13 / 13** | `scripts/checks/ec-compile.sh` |
| Lean ↔ EC bridge guard | **5 / 5** named bridges intact | `scripts/check-lean-bridge.sh` |
| jasmin-ct on threshold layer | **3 / 3** blocking, CT-clean | `scripts/checks/jasmin.sh` (round1.jazz, round2.jazz, combine.jazz) |
| Refinement-scaffold guard (`declare axiom` budget) | **0 / 0** | `scripts/checks/ec-refinement-scaffold.sh` |
| Retired-axiom regression guard | green | `scripts/checks/ec-regressions.sh` |
| Per-push proof gate orchestrator | exits 0 | `scripts/check-high-assurance.sh` |
| Per-push test gate orchestrator | exits 0 | `scripts/test.sh` |

## Axiom accounting

**22 named axioms total**, each with file:line in EC and Lean:

- **17 narrow implementation-refinement axioms** in the refinement files:
  - 14 byte-walk axioms (4 stage-extraction + 4 w-decomposition
    + 2 w_low + 4 ExternalMu codec-layout)
  - 1 signature-codec round-trip (`pack_unpack_n1_signature_roundtrip`)
  - 2 honest-execution no-reject post-conditions
    (`{combine,sign}_no_reject_on_accepted_honest_layout`)
- **5 Lean-bridged algebraic axioms** in `~/work/lux/proofs/lean/Crypto/`,
  cited inline at the EC declaration site, enforced by
  `scripts/check-lean-bridge.sh`

Per-axiom enumeration with file:line + closure plan:
`docs/proof-axiom-inventory.md`.

## Reference implementation

| Field | Value |
|---|---|
| Path | `ref/go/pkg/pulsar/` |
| Module | `github.com/luxfi/pulsar` |
| Test surface | `go test -count=1 -race ./pkg/pulsar/` → PASS |
| Statement coverage | **84.2%** (`go test -cover ./pkg/pulsar`) |
| KAT determinism | byte-stable under regeneration via `scripts/gen_vectors.sh` |
| Zeroization | `ref/go/pkg/pulsar/zeroize.go` covers every Combine / Sign / DKG exit path |

## Class N1 interoperability vs FIPS 204

`test/interoperability/n1_class_test.go` against `cloudflare/circl`
FIPS 204 verifier — **19 / 19 subtests PASS**:

- `TestN1_SinglePartySignatures_VerifyUnderFIPS204`: 9 subtests across
  Pulsar-44 / Pulsar-65 / Pulsar-87
- `TestN1_ThresholdSignatures_VerifyUnderFIPS204`: 4 subtests at Pulsar-65
- `TestN1_TamperedSignatures_Rejected`: 3 subtests
- `TestN1_WrongMessage_Rejected`: 3 subtests

## Constant-time evidence

| Layer | Tool | Status |
|---|---|---|
| Threshold Round-1 / Round-2 / Combine (Jasmin) | jasmin-ct | 3 / 3 blocking, CT-clean |
| libjade ML-DSA-65 single-party sign | jasmin-ct | advisory under tracked issue #2; precise write-up at `ct/jasmin-ct-libjade.md` |
| Pulsar Verify (Go reference) | dudect | per-push at 10⁵ samples; 10⁹-sample run in `scripts/nightly.sh` checks results into `ct/dudect/results/` |
| Pulsar Sign (Go reference) | n/a | intentionally non-CT per FIPS 204 §3.3 |

## Identity stage closure (CR-6 / CR-7 / CR-8)

Closed uniformly across the small-committee GF(257) path and the
large-committee GF(q) path at v1.0.7. Source-inspection evidence:

- `grep legacyDeriveMACKey *.go` returns no matches — the public-input-
  derived MAC-key path is gone.
- `large_threshold.go:74` takes `sessionKeys map[NodeID][32]byte` and
  returns `ErrSessionKeyMissing` for any missing peer.
- `large_dkg.go:77` constructor takes `(myIdentity *IdentityKey,
  directory IdentityDirectory)`; envelopes flow through `sealEnvelope`
  which KEM-wraps under each recipient's long-term ML-KEM-768 identity
  public key.
- Round-1 commit-and-reveal binding to the long-term identity public
  key + DKG session identifier on both paths.

## v0.3 byte-equality closure (PULSAR-V03-1)

Closed in v1.0.20 (commit `023a3ed`); regression-guard hardening in
v1.0.21 (`267ec04`) and v1.0.22 (`29094a7`). Closure record:
`BLOCKERS.md` (closed-finding registry).

## Package contents (mapped to NIST IR 8214C §5)

| Artifact | Location | Status |
|---|---|---|
| Cover sheet | `SUBMISSION.md` | shipped |
| 1-page exec summary | `NIST-SUBMISSION.md` | shipped |
| Standalone spec | `docs/spec-overview.md` + `spec/pulsar.tex` (1,633-line LaTeX → 577 KB PDF) | shipped |
| Suite index | `docs/suite.md` | shipped |
| Information architecture | `docs/information-architecture.md` | shipped |
| Patent grant | `docs/patents.md` | shipped |
| Patent claim drafts (attorney prep) | `docs/patent-claims.md` (21 claims, 5 groups) | shipped |
| Trust accounting | `docs/proof-axiom-inventory.md` + `docs/proof-claims.md` + `docs/tcb.md` | shipped |
| FIPS 204 op → § map | `docs/fips-204-traceability.md` | shipped |
| Per-version proof log | `CHANGELOG.md` (v4 → v13) | shipped |
| Multi-year roadmap | `docs/roadmap.md` | shipped |
| Cross-repo sync | `docs/sync-status.md` | shipped |
| IETF Internet-Draft | `docs/ietf-draft-skeleton.md` (`draft-hanzo-pulsar-threshold-mldsa-00`) | shipped |
| Experimental evaluation (NIST IR 8214C §6) | `docs/evaluation.md` + `bench/results/REPORT.md` | shipped |
| Reference implementation | `ref/go/pkg/pulsar/` (84.2% coverage) | shipped |
| KAT vectors | `vectors/` (deterministic from 48-byte seed) | shipped |
| EasyCrypt theories | `proofs/easycrypt/` (13/13 compile, 0/0 admits) | shipped |
| Lean ↔ EC bridge | `proofs/lean-easycrypt-bridge.md` (5/5, CI-guarded) | shipped |
| Jasmin constant-time | `jasmin/{lib,ml-dsa-65,threshold}/` (3/3 blocking green) | shipped |
| Class N1 E2E interop | `test/interoperability/n1_class_test.go` (19/19 subtests) | shipped |
| Build / test / bench / SBOM | `scripts/` | shipped |
| License | `LICENSE` (Apache-2.0) | shipped |

## Reproducibility commitment

```bash
git clone --branch submission-2026-11-16 https://github.com/luxfi/pulsar
cd pulsar
opam switch jasmin && opam install . --deps-only
scripts/build.sh                  # builds reference impl + spec PDF
scripts/check-high-assurance.sh   # proof + CT gate (exits 0)
scripts/test.sh                   # KAT cross-validation (exits 0)
scripts/bench.sh                  # performance benchmarks
```

Drift between the submission tarball and a fresh reproduction is a
build bug. NIST reviewers obtain byte-identical artifacts on
reproduction.

## Sibling suite members (informational)

The Hanzo PQ Threshold Suite ships Pulsar as Tier 1. The remaining
suite members (Corona R-LWE sibling, Magnetar SLH-DSA research track,
LSS Shamir wrapper) carry their own submission packages on the
v0.2 — v0.4 roadmap in `docs/roadmap.md`. They are not part of the
v0.1 cut.

## Honest claims

- **DO say**: "Pulsar (Tier 1) is the NIST MPTC v0.1 submission
  package; the tarball is cut from a tag on `main` on 2026-11-16."
- **DO say**: "The 22 named axioms are each independently attackable
  through the per-axiom closure plan in
  `docs/proof-axiom-inventory.md`."
- **DO say**: "Accredited-lab tracks (NIST ratification, ACVP / CAVP,
  FIPS 140-3 module validation) are downstream of this submission;
  submission inputs are ready."

---

**Document metadata**

- Name: `docs/status.md`
- Version: v1.0 — submission-ready declaration
- Date: 2026-05-31
- Companion to: `SUBMISSION.md`, `NIST-SUBMISSION.md`,
  `docs/proof-axiom-inventory.md`, `docs/cryptographer-sign-off.md`,
  `docs/roadmap.md`
- Owner: `submissions@lux.network`
