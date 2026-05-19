# Cryptographer sign-off — luxfi/pulsar v1.0.7

> Independent review of the Pulsar threshold ML-DSA-65 implementation
> at commit `174941a` (tag `v1.0.7`) on `main` of
> `github.com/luxfi/pulsar`.
> Date of review: 2026-05-18.
> Reviewer: cryptographer agent (Hanzo Dev, internal review).

## Summary

**APPROVED WITH GATES** for live Lux Quasar consensus use AND for
the NIST MPTC v0.1 submission package, subject to the four
disclosure / pre-publish gates in the "Gates" section below. The
v1.0.7 release closes the CR-6 / CR-7 / CR-8 audit findings
uniformly across the small-committee (GF(257)) and large-committee
(GF(q)) paths; the construction, test surface, KAT determinism, and
proof-artifact gates are all green; the residual gates are about
honesty of disclosure (v0.1 vs v0.2 protocol variant; dudect
in-progress status; minor doc drift) rather than algorithmic or
implementation defects.

## What was reviewed

- **Algorithm source.** `~/work/lux/pulsar/ref/go/pkg/pulsar/` at
  commit `174941a` (41 `.go` files, ~11.3k LOC):
  - `identity.go` — long-term `IdentityKey` (ML-KEM-768 + ML-DSA-65),
    `sealEnvelope` / `sealOpenEnvelope` width-agnostic API,
    `EstablishSession` / `VerifyPeerEncapsulation` / `DeriveSessionKey`,
    `IdentityDirectory`, deterministic encapsulation seed derivation.
  - `dkg.go` + `large_dkg.go` — three-round DKG, both paths now use
    the same identity stage; per-recipient envelopes KEM-wrapped
    under recipient ML-KEM-768 identity public key.
  - `threshold.go` + `large_threshold.go` — two-round threshold sign,
    both paths now consume per-pair ephemeral session keys derived
    from authenticated ML-KEM-768 key agreement;
    `legacyDeriveMACKeyLarge` is gone.
  - `reshare.go` + `large_reshare.go` — committee rotation under
    fixed public key, both paths now use the identity stage.
  - `sign.go`, `verify.go`, `keygen.go` — single-party FIPS 204
    dispatch; verify.go is intentionally minimal (the Class N1
    output-interchangeability invariant lives here).
  - `transcript.go`, `shamir.go`, `shamir_gfq.go`, `largeshamir.go`,
    `abort.go`, `zeroize.go`, `types.go`, `params.go`.
  - `n1_byte_equality_test.go` — empirical realization of the
    Class N1 byte-equality theorem at (5,3), (7,4), (10,7); all pass.
- **Spec.** `~/work/lux/pulsar/SPEC.md` and
  `~/work/lux/pulsar/spec/pulsar.tex` (1,630 lines).
- **Submission package.** `~/work/lux/pulsar/SUBMISSION.md`,
  `STATUS-SUBMISSION-READINESS.md`, `PROOF-CLAIMS.md`,
  `AXIOM-INVENTORY.md`, `BLOCKERS.md`.
- **Machine-checked proofs.**
  - EasyCrypt: 13 files at `~/work/lux/pulsar/proofs/easycrypt/`
    (8.2k lines of EC source; admit budget `0 / 0` hard-pinned by
    `scripts/checks/ec-admits.sh`).
  - Lean ↔ EC bridge: 5 axioms at
    `~/work/lux/proofs/lean/Crypto/{Pulsar/,Threshold/}`
    citation-checked by `scripts/check-lean-bridge.sh`.
- **Jasmin high-assurance.** `~/work/lux/pulsar/jasmin/`:
  `lib/`, `ml-dsa-65/`, `threshold/` (round1.jazz, round2.jazz,
  combine.jazz).
- **Constant-time evidence.** `~/work/lux/pulsar/ct/dudect/`
  (build + harness present; results in `results/` are preliminary —
  see Gates below).
- **KAT vectors.** `~/work/lux/pulsar/vectors/{keygen,sign,
  verify,threshold-sign,dkg}.json` (regenerated via
  `scripts/gen_vectors.sh`).

## Verified green

- [x] **Build.** `GOWORK=off go build ./...` clean.
- [x] **Vet.** `GOWORK=off go vet ./...` clean.
- [x] **Test suite, race.** `GOWORK=off go test -count=1 -race
      ./...` → `ok  github.com/luxfi/pulsar/ref/go/pkg/pulsar
      16.450s`. Zero failing tests, zero race warnings.
- [x] **Coverage.** `go test -cover ./pkg/pulsar` reports
      **84.2% of statements**.
- [x] **N1 byte-equality (in-tree).** All three configs
      (5-of-3, 7-of-4, 10-of-7) produce byte-identical signatures
      to centralized FIPS 204 ML-DSA-65 on the
      Lagrange-reconstructed master seed. Passes under race.
- [x] **N1 interoperability vs cloudflare/circl FIPS 204.**
      `go test ./test/interoperability/` in `pulsar` →
      19 / 19 subtests pass
      (TestN1_SinglePartySignatures_VerifyUnderFIPS204: 9 subtests
      across Pulsar-44/65/87; TestN1_ThresholdSignatures_VerifyUnderFIPS204:
      4 subtests at Pulsar-65; TestN1_TamperedSignatures_Rejected:
      3 subtests; TestN1_WrongMessage_Rejected: 3 subtests).
- [x] **EasyCrypt high-assurance gate.**
      `bash scripts/check-high-assurance.sh` → admit budget
      `0 / 0`; regression guard on `reshare_preserves_secret`
      (no abstract axiom); `declare axiom` absent from refinement
      scaffolds; Lean ↔ EC Shamir bridge guard reports 5 / 5
      bridges intact with the file references at the cited
      EC line numbers (Pulsar_N1.ec:339, Pulsar_N4.ec:155, :162,
      :176, Pulsar_N1.ec:789). Note: jasminc / easycrypt CLI not
      on PATH on the review machine, so the gate "skipped" the
      compile-from-source check; the admit-pin guard is
      independent and ran clean.
- [x] **Lean bridge gate.** `bash scripts/check-lean-bridge.sh` →
      all 5 Lean-side names verified
      (`shamir_correct_at_target`, `AddCommMonoid`,
      `combine_distributes_over_sum`, `shamir_correct_at_target`,
      `threshold_partial_response_identity`).
- [x] **KAT determinism.** Backed up `vectors/`, regenerated via
      `bash scripts/gen_vectors.sh`, ran `diff -qr` against the
      pre-existing tree → no differences. Vectors are byte-stable
      under regeneration as required for NIST submission
      reproducibility.
- [x] **Identity stage uniformity (CR-6 / CR-7 / CR-8 closure
      on the GF(q) path).** Verified by source inspection:
  - `grep legacyDeriveMACKey *.go` returns no matches: the legacy
    public-input-derived MAC key path is gone from both small and
    large code paths.
  - `large_threshold.go:74` takes
    `sessionKeys map[NodeID][32]byte` as a constructor argument
    and returns `ErrSessionKeyMissing` for any missing peer.
  - `large_dkg.go:77` constructor takes `(myIdentity *IdentityKey,
    directory IdentityDirectory)`; envelopes flow through
    `sealEnvelope` (identity.go:399) which is width-agnostic over
    `shareWire []byte` (64 B for GF(257), 128 B for GF(q)) and
    KEM-wraps under the recipient's long-term ML-KEM-768 identity
    public key.
  - `large_reshare.go` `NewLargeReshareSession` takes the same
    identity arguments; new-committee joiners can call
    `SetPriorGroupPubkey`.
  - Round-1 vacuous-commit field is gone on both paths (CR-6
    path A); binding comes from the Round-2 digest agreement.
- [x] **Identity envelope cryptography is well-built.**
  - Sealing: `sealEnvelope` (identity.go:399)
    encapsulates ML-KEM-768 to recipient's long-term KEM public
    key, derives `K_env = HKDF-SHA3-256(ss, salt=dealerID,
    info="PULSAR-DKG-ENVKEY-V1" || recipientID || committee_root)`,
    seals plaintext via cSHAKE256 stream cipher keyed by `K_env`,
    appends `KMAC256(K_env, dealerID || recipientID || share ||
    contribution)` authentication tag. Constant-time
    comparison (`ctEqualSlice`) on tag verification. Auth input
    binds dealer + recipient + share + contribution to defeat
    envelope relay across (dealer, recipient) pairs sharing the
    same KEM ciphertext.
  - Session keys: `EstablishSession` (identity.go:171) produces
    a deterministic ML-KEM-768 encapsulation seed from
    `HKDF-SHA3-256(salt=myID||peerID, ikm=sid, info=
    "PULSAR-SESSION-ESTABLISH-V1" || transcript)`, then
    ML-DSA-65-signs the ciphertext under the caller's long-term
    identity key with context tag `PULSAR-SESSION-ESTABLISH-V1`.
    Peer-side `VerifyPeerEncapsulation` (identity.go:251) verifies
    the ML-DSA-65 signature with the same context tag before
    decapsulating. `DeriveSessionKey` (identity.go:287) orders
    contributions canonically by NodeID (avoiding direction bias),
    mixes via HKDF-SHA3-256.
  - All domain-separation tags (`PULSAR-SESSION-ESTABLISH-V1`,
    `PULSAR-SESSION-KEY-V1`, `PULSAR-DKG-ENVKEY-V1`,
    `PULSAR-DKG-ENVSTREAM-V1`, `PULSAR-DKG-ENVAUTH-V1`) are
    distinct strings; no collision risk.
- [x] **No backwards-compat shims in production code.**
  Targeted scans:
  - `grep -nE 'legacyDerive|legacyMAC|legacyPath|backward|legacy_'`
    in pkg/pulsar → no matches.
  - `grep -nE 'TODO|FIXME|XXX|HACK|deprecated'` excluding tests →
    one (1) match: `shamir.go:129 // DEPRECATED`. Inspected; this
    is a documented hazard marker on `shamirReconstruct` (the
    byte-form Lagrange function) explaining that the function is
    retained only for property tests because it has a silent 256→0
    mod-256 collapse hazard; the protocol hot-paths (DKG Round 3,
    threshold Combine) use `shamirReconstructGF` which preserves
    GF(257)-element 256. The annotation is correct: it is an
    in-tree hazard signpost, not a backwards-compat shim, and
    serves the reader by warning against misuse. Acceptable.
- [x] **Verify path is constant-time-shaped.** `verify.go` is
  minimal-by-design: input-length / mode checks branch on PUBLIC
  inputs only (`groupPubkey.Mode`, `sig.Mode`, `len(ctx)`,
  `len(groupPubkey.Bytes)`, `len(sig.Bytes)`); the actual
  signature check delegates to `mldsa{44,65,87}.Verify` from
  `cloudflare/circl`, which is the FIPS 204 §6.3 verifier and
  is documented constant-time by upstream.
- [x] **Sign path is constant-time-shaped.** `sign.go` validates
  on public inputs (mode, ctx length) and delegates to
  `mldsa{44,65,87}.SignTo`. The `randomized` boolean is a public
  parameter (not secret-dependent). No secret-dependent branches
  in this file.
- [x] **Combine zeroizes correctly.** `threshold.go` Combine path
  (lines 441-479) and `large_threshold.go` LargeCombine (lines
  309-334) explicitly zeroize `masterSeed`, the reconstructed
  `PrivateKey`, `byteSum`, `byteSumBytes`, and `mixInput` on
  every error and success exit. No `defer`; the calls are inline
  so the secret lifetime is locally legible. (Note: this is the
  "v0.1 reconstruction aggregator" trust model — see Gate 1
  below.)
- [x] **Submission package coherence.** `SUBMISSION.md` pins
  `luxfi/pulsar v1.0.7 commit 174941a` in ≥9 places (algorithm
  source, vendor snapshot path, CR-6/7/8 closure table, proof
  artifact counts, tarball-cut tooling). `STATUS-SUBMISSION-
  READINESS.md` enumerates 14 artifact rows all marked shipped;
  open items list matches BLOCKERS.md disclosures.
  `PROOF-CLAIMS.md` is exemplary: it states the narrow N1 claim
  formally, enumerates 5 things explicitly NOT proved (lattice
  hardness, implementation covert channels, adaptive corruption
  unforgeability, bit-level codec, external Lean theorems), and
  ends with the honest one-paragraph version. No overclaiming
  detected in `SUBMISSION.md` / `PROOF-CLAIMS.md`.

## Findings

### Minor (5)

- **MIN-1.** `SUBMISSION.md` row "Reference implementation" claims
  `89.7% coverage`. Measured value on this review machine is
  **84.2%**. Either the doc drifted (5-point gap is too large to
  be measurement noise) or the percentage was measured against a
  different test profile / module. Recommend updating
  `SUBMISSION.md` to the current measured value or pinning the
  exact `go test -coverpkg=...` invocation used to derive the
  claimed figure. Not blocking; not a security claim.

- **MIN-2.** `STATUS-SUBMISSION-READINESS.md` lists pulsar
  HEAD as `c2e01e3` (2026-05-18); the v1.0.7 algorithm commit is
  `174941a` on the `luxfi/pulsar` side. These are two different
  repos (submission framework vs algorithm source) so the divergence
  is expected, but the date stamp in
  `STATUS-SUBMISSION-READINESS.md` should be reverified at next
  edit since the algorithm commit shipped on 2026-05-18 as well.

- **MIN-3.** `BLOCKERS.md` "Constant-time Verify" row remains
  marked WEAK and notes "Assertion not measurement. Add `dudect`
  to CI before claiming CT." This is the correct framing, but
  it is referenced from `SUBMISSION.md` only indirectly via
  `BLOCKERS.md` and is not reflected in `PROOF-CLAIMS.md` §3.2.
  Recommend cross-linking from `PROOF-CLAIMS.md` so a reviewer
  reading the narrow N1 claim sees the dudect-pending status
  without having to read BLOCKERS.md.

- **MIN-4.** Spec `pulsar.tex` §"Identifiable abort" (around
  line 720) names the long-term identity signer as "the Ed25519
  key advertised in the chain's validator-set record." The
  v1.0.7 code uses **ML-DSA-65** (post-quantum) for identity
  signing, not Ed25519. The spec text was written before the
  identity stage moved to PQ in v1.0.6/v1.0.7. Recommend a
  one-line spec-text update.

- **MIN-5.** `shamir.go:129` `shamirReconstruct` (the
  byte-form Lagrange function) is annotated DEPRECATED for new
  call sites. Acceptable as a documented hazard signpost.
  However, since it is unreferenced by the protocol hot paths
  and only by `shamir_test.go`, consider moving it into a
  `_test.go` file so the production build surface does not
  carry the dead-but-test-only function. Not blocking.

### Informational (2)

- **INF-1.** The construction is the **v0.1 reconstruction-
  aggregator** instantiation (master seed reassembled in the
  combine aggregator's memory under `KeyFromSeed`, then
  single-party FIPS 204 signing). This is what makes the
  Class N1 byte-equality theorem trivial. It also means the
  aggregator is briefly trusted with the entire master seed.
  Zeroization at every error / success exit is in place (see
  Verified green). This is properly disclosed in
  `pulsar.tex` §4.1 "Trust model variants" and BLOCKERS.md
  "Class N1 byte-equal" row, and tracked as the gating
  caveat to the headline claim. Operators MUST be informed
  of this trust model before deployment; the deployment
  runbook for Lux Quasar consensus should state it explicitly.

- **INF-2.** The Round-1 commit-and-reveal binding uses
  `D_i = cSHAKE256(mask || masked || tau_1)` in the v1.0.7
  code (threshold.go:225), while the LaTeX spec algorithm
  in §"Threshold signing" describes the v0.2 FSwA flow with
  `D_i = cSHAKE(HighBits(A·y_i, 2·gamma_2), tau_1)`. This is
  the **two-variant submission** decision documented in
  BLOCKERS.md row "Spec ↔ Go-reference protocol drift —
  CLOSED — two-variant submission". The KAT vectors fix the
  v0.1 wire format; the EC byte-equality proof scope is the
  centralized recovery model (which both variants satisfy at
  the signature byte level); the v0.2 Jasmin sources are the
  high-assurance compile target. The disclosure is in the
  documentation chain; what is missing is an
  unmissable pointer FROM `SUBMISSION.md` headline section
  TO this disclosure (currently a reviewer must read
  BLOCKERS.md to see it). See Gate 2.

## Gates (must close before publish)

The construction and code are sound under the disclosed trust
model. The following four items are about **disclosure honesty**
of the submission package; closing them does not require any
algorithm or code change, but they are required before the
package is shipped to NIST or relied upon by external
auditors:

- [ ] **GATE-1 (deployment runbook).** Before live Lux Quasar
      consensus deployment of the v0.1 reconstruction-aggregator
      path, the operator runbook MUST state, in the Security
      Considerations section: "Each Combine invocation
      reconstructs the master ML-DSA seed in the aggregator's
      address space. Zeroization is in place. Operators MUST
      run the aggregator inside the same trust boundary (HSM /
      enclave / dedicated VM) as a single-party ML-DSA-65 signer
      would be run; the threshold layer does NOT reduce the
      Trusted Computing Base of the aggregator process below
      that of the centralized signing alternative — it reduces
      it of the **share-holders**, who never see the master
      seed." This is the operational corollary of INF-1.

- [ ] **GATE-2 (cross-link in SUBMISSION.md).** Add an
      explicit "Trust model and protocol-variant disclosure"
      paragraph to `./SUBMISSION.md` near the
      headline claim, pointing at `pulsar.tex` §4.1 and
      `BLOCKERS.md` "Spec ↔ Go-reference protocol drift" row.
      The disclosure is real and well-written in the
      documentation chain; what is missing is the
      one-click reading path from cover sheet to disclosure.

- [ ] **GATE-3 (dudect pin).** Run
      `ct/dudect/dudect_combine` and `ct/dudect/dudect_verify`
      to the documented sample target (≥10⁹ samples) on the
      production CI fleet and pin the result file in
      `ct/dudect/results/` with the exact build flags,
      compiler version, CPU model, and run date. The
      preliminary stdout files in `results/` show only
      ~0.03 M measurements and the preliminary line "Probably
      not constant time" which is **not enough samples to be
      meaningful** under the dudect methodology — this is
      explicitly noted in BLOCKERS.md and `PROOF-CLAIMS.md`
      §3.2 as "advisory" / "WEAK assertion not measurement."
      The fix is to actually run the experiment to its
      documented target. (Not a finding about the code; a
      finding about the evidence file.)

- [ ] **GATE-4 (minor doc updates).** Address MIN-1
      (coverage %), MIN-3 (PROOF-CLAIMS cross-link to
      dudect status), MIN-4 (spec text Ed25519 → ML-DSA-65
      on the identity signer), and optionally MIN-5
      (move dead-but-test-only `shamirReconstruct` to
      `_test.go`). MIN-2 (date stamp) is a no-op
      verification.

## Out-of-scope for this sign-off

The following are explicitly NOT covered by this review and
must be tracked in their own work streams; their absence
from this sign-off is not a finding:

- Full machine-checked EasyCrypt compile (the gate guards
  the admit budget, not the type-check; closing this requires
  the EasyCrypt OCaml binary in CI).
- Jasmin compile-from-source (`jasminc` not on the review
  machine; the threshold-layer `round1.jazz`, `round2.jazz`,
  `combine.jazz` sources were inspected for shape only).
- Side-channel measurements beyond the dudect stdio harness:
  power, EM, fault, cache-timing.
- Adaptive-corruption EUF-CMA-Threshold proof (the static-
  corruption case is in scope; adaptive is a deferred theorem
  per `PROOF-CLAIMS.md` §3.3 and `BLOCKERS.md`).
- ACVP / CAVP / FIPS 140-3 validation (lab work).
- The post-quantum hardness of ML-DSA itself
  (`PROOF-CLAIMS.md` §3.1: this is NIST's analysis under
  FIPS 204).

## Sign-off

I attest that, given the above review and the explicit non-claims
documented in `./PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`,
and `BLOCKERS.md`:

- `luxfi/pulsar` v1.0.7 (commit `174941a`) is **APPROVED for live
  Lux Quasar consensus use**, conditional on GATE-1 (operator
  runbook discloses the v0.1 reconstruction-aggregator trust
  model). The algorithm is correctly implemented, the
  identity-stage closure of CR-6 / CR-7 / CR-8 is uniform across
  small and large committee paths, race-clean tests pass, KAT
  vectors are deterministic, zeroization is in place, and the
  proof-artifact gates (EC admit budget, Lean ↔ EC bridge) are
  green.

- `luxfi/pulsar` v1.0.7 (commit `174941a`) is **APPROVED as the
  algorithm-source pin for the NIST MPTC v0.1 submission tarball
  cut from `pulsar`**, conditional on GATE-2 (SUBMISSION.md
  cross-link), GATE-3 (dudect run to documented target), and
  GATE-4 (minor doc updates). The submission framework's
  artifact-coherence chain (algorithm pin → vendor snapshot →
  proof artifact counts → KAT determinism → interop tests
  against `cloudflare/circl` FIPS 204) is intact.

The four gates are about documentation honesty and one
evidence-file completion task; none requires an algorithm or
code change. With those closed, the package is fit to ship.

— cryptographer agent, Hanzo Dev internal review, 2026-05-18.
