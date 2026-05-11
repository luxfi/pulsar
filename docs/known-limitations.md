# Known limitations

Maintained as a living document. Better that reviewers see the gaps before
they find them.

## Spec / protocol

### Output interchangeability with FIPS 204 — DEMONSTRATED IN v0.1

The headline claim — "Pulsar-M signatures verify under unmodified
FIPS 204 ML-DSA.Verify" — holds for the v0.1 reference. The
`pulsarm.Verify` entry point dispatches to
`cloudflare/circl/sign/mldsa{44,65,87}.Verify` verbatim; the
threshold-sign output is the same byte-for-byte signature an
unmodified FIPS 204 signer would have produced on the
reconstructed seed. KAT cross-validation lives at
`ref/go/pkg/pulsarm/kat_test.go: TestKAT_ThresholdSign_Replay`,
which verifies every committed threshold signature under
`pulsarm.Verify` and therefore under the underlying FIPS 204
verifier.

### v0.1 uses reconstruction-aggregator; v0.2 will use Lagrange-linearity

v0.1 instantiates the threshold protocol via a
**reconstruction-aggregator** model: a threshold quorum delivers
byte-wise Shamir shares of the FIPS 204 seed to an aggregator
(any honest quorum member), which Lagrange-reconstructs the
master byte-sum in GF(257), runs the deterministic cSHAKE256 mix
that DKG committed to, and calls FIPS 204 Sign once. The master
seed lives in the aggregator's memory for the duration of one
Sign call.

The pulsar-m.tex §4.2 **Lagrange-linearity sign** path — each
party computes `z_i = y_i + c · λ_i · s_i` locally and the
aggregator sums them, with the master secret never reconstructed
— is the v0.2 target. It is mathematically equivalent at the
output level (the produced signature is byte-equal) but
information-theoretically stronger because no party ever holds
the master secret.

The v0.1 model is acceptable for the round-1 MPTC submission
when paired with the reshare cadence specified in
`spec/system-model.tex` (no aggregator holds a secret across more
than one signature). v0.2 ships the stronger soundness property
that adaptive-corruption analysis requires.

### Pedersen commitments: RO model in v0.1, M-LWE in v0.2

v0.1 uses cSHAKE256 RO-binding commitments
`C_i = cSHAKE256(c_i || blind_i)`. v0.2 replaces them with the
R_q^k Pedersen commitment of `spec/pulsar-m.tex` §3.2:
`C_{i,k} = A · c_{i,k} + B · r_{i,k}`. Both bindings are sound;
the v0.2 M-LWE binding is the post-quantum-safe variant required
for the formal proof to reduce to an M-LWE / MSIS hardness
assumption (the v0.1 RO-binding reduces to cSHAKE256 collision
resistance, which itself reduces to SHA-3 security).

### Per-byte Shamir over GF(257) vs. polynomial Shamir over R_q^k

v0.1 Shamir-shares the FIPS 204 seed byte-wise over GF(257). v0.2
will reshape this to polynomial Shamir over R_q^k matching
`spec/pulsar-m.tex` §3.3. The output is the same FIPS 204
signature in both cases; the v0.2 reshape is required to make
the Lagrange-linearity sign path work without round-tripping
through the byte-sum representation.

### Adaptive corruption proof not yet written

Static-corruption security is the baseline target. Adaptive-corruption
security is a stretch goal for the round-1 submission and a hard
requirement for round 2.

### Mobile-adversary (proactive resharing) proof inherits Pulsar's gaps

Pulsar's `reshare/` package has documented soundness against mobile
adversaries with deterministic quorum selection (the F10 weakness in
HIP-0077). Pulsar-M's `reshare/` ports this with beacon-randomized
quorum selection, which strictly improves on Pulsar — but the formal
proof of the strengthened protocol is still in draft.

## Implementation

### Reference implementation is Go-only for round 1

The C reference comes after spec encoding freeze. Round-1 reviewers
have only the Go reference. NIST MPTC permits any language; a C
companion is strongly recommended for round 2.

### No optimized implementation

`ref/go/` is the boring, clear, slow reference. AVX-512 / NEON / SHA-3-NI
optimization is post-submission work. Performance numbers in the
experimental-evaluation report reflect the reference, not optimized
implementations.

### No first-order masking

Power analysis resistance via masking is post-submission hardening.
The reference is constant-time at the algorithmic level (no
secret-dependent branches, no secret-dependent memory access patterns
in inner loops) but has no power-side-channel countermeasures.

### No HSM integration

Production-deployment patches (HSM integration, FIPS 140-3 module
shim) are post-submission. The reference is software-only.

### Constant-time analysis is dudect-level

Go's compiler is not guaranteed constant-time at the IR level. We use
dudect (`ct/dudect/`) to check the leading-edge timing distribution for
secret-correlated values. This catches the obvious leaks but does not
provide the formal guarantee of e.g. Jasmin-verified C kernels. Formal
verification (Jasmin/Formosa/EasyCrypt) is post-submission.

## NIST process

### No prior NIST MPTC preview submission

We're starting from cold. The third-preview window deadline (2026-Jul-20)
is roughly two months out. Achieving a credible preview writeup in that
window is the immediate gate. If we miss the third preview, we lose the
ability to submit the round-1 package without a preview, which is a hard
requirement per IR 8214C §5.1.

### Patent claims not yet inventoried

Pulsar inherits Ringtail's IP posture. Pulsar-M needs a fresh
patent-claim review for the M-LWE adaptation. `docs/patent-notes-draft.md`
collects claims as they're discovered; final notice for the package is
on the critical path for 2026-Nov-16.

### External cryptanalysis engagement not yet contracted

NIST MPTC submissions are strengthened by independent academic
cryptanalysis. We have not yet engaged a third party. A 6-month
engagement starting July 2026 is the target — this aligns with the
post-package public-analysis window rather than blocking the package
itself.

## Repo / build

### Go module initialised

`go.mod` brings in `cloudflare/circl@v1.6.3` (FIPS 204 backbone)
and `golang.org/x/crypto/sha3` (FIPS 202 / SP 800-185 transcripts).
Cleanly builds with `GOWORK=off`.

### Spec PDF not yet built

`spec/pulsar-m.tex` is a stub. The full MPTC-format technical
specification — Front matter / Notation / Preliminaries / Crypto-system
chapters / System model / Algorithms+Protocols / Security analysis /
Complexity analysis / Deployment considerations / Appendices — is on
the active writing track.

### KAT suite generated

`vectors/{keygen,sign,verify,threshold-sign,dkg}.json` are committed.
`scripts/gen_vectors.sh` re-runs the generator and verifies that
re-running produces byte-identical output (the deterministic-fixture
gate). The CAVS-style `kat-v1.rsp` ACVP companion is on the v0.2
path; ACVP support requires the post-encoding-freeze byte layout.

### Lattice-estimator parameter table empty

`estimator/results.md` will hold the classical + quantum security-level
table. Generated by lattice-estimator runs once the parameter set is
finalized.

## Compared to Pulsar (R-LWE)

| dimension | Pulsar | Pulsar-M |
|---|---|---|
| Algebraic basis | Ring-LWE | Module-LWE |
| Hash | SHA-3 cSHAKE / BLAKE3 legacy | SHA-3 cSHAKE only |
| FIPS 204 output interchange | no (R-LWE) | yes (target) |
| MPTC class | S1/S4 | N1/N4 |
| Parameter sets | Pulsar-internal | ML-DSA-44/65/87 |
| DKG | Pedersen over `R_q` | Pedersen over `R_q^k` |
| Reshare | deterministic quorum | beacon-randomized quorum |

Where Pulsar provides feature X and Pulsar-M doesn't yet, Pulsar-M's
goal is to inherit X verbatim from Pulsar's `dkg2/` and `reshare/`
packages with the M-LWE shape change.
