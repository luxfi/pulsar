// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// distributed_bcc_dkg.go — the dealerless-DKG obstruction for byte-FIPS-204
// ML-DSA, DERIVED from the parameter arithmetic (not asserted). This is the
// honest Part-2 deliverable of PULSAR-V12-PARALLEL-PQ: a genuinely
// dealerless DKG that produces a key whose signatures verify byte-for-byte
// under unmodified FIPS 204 is NOT achievable with known techniques, and
// THIS FILE COMPUTES WHY rather than faking a key or falling back to a
// dealer/TEE.
//
// It mirrors rangeproof.go's pattern: the fail-closed decision is a
// COMPUTED consequence of the FIPS 204 bounds (assessDealerlessFIPS), and a
// test (distributed_bcc_dkg_test.go) pins the arithmetic so the obstruction
// is reproducible, not a claim.
//
// ─────────────────────────────────────────────────────────────────────────
// THE OBSTRUCTION (precise; which step breaks).
//
// FIPS 204 KeyGen samples s1, s2 UNIFORMLY from S_η = {p ∈ R : ‖p‖∞ ≤ η}.
// The ENTIRE parameter set is calibrated to ‖s1‖∞, ‖s2‖∞ ≤ η:
//
//	β = τ·η      — the verifier's ‖z‖∞ < γ1 − β ceiling AND the bound on the
//	               key-dependent shift ‖c·s2‖∞ ≤ β,
//	ω            — the hint weight bound,
//	2β margin    — the BCC boundary-clearance slack (boundary.go
//	               boundaryThreshold = γ2 − 2β − slack) that guarantees
//	               HighBits(w − c·s2) = HighBits(w) for the no-leak hint.
//
// A dealerless DKG (Pedersen/Gennaro: no party knows the secret) forms the
// joint secret as a SUM / Lagrange combination of N ≥ 2 independent
// contributions, each itself in S_η. The result is NOT S_η-distributed and
// has ℓ∞-support up to N·η > η. Then:
//
//  1. BYTE-VALIDITY breaks at the BCC boundary-clearance hypothesis. The
//     fixed 2β margin certifies HighBits stability ONLY when ‖c·s2‖∞ ≤ β,
//     i.e. ‖s2‖∞ ≤ η. With ‖s2‖∞ ≤ N·η the shift is ‖c·s2‖∞ ≤ N·β, so a
//     nonce passing the FIXED-margin BoundaryClear can still have
//     HighBits(w − c·s2) ≠ HighBits(w) ⇒ FindHint cannot reach w1 ⇒ NO
//     FIPS-204-valid signature. The BCC correctness theorem's hypothesis is
//     violated for every N ≥ 2 (assessDealerlessFIPS computes N·β vs β).
//     Enlarging the margin to 2N·β is non-standard (it changes the
//     protocol, and the yield falls to zero as N → γ2/2β); it does not
//     restore FIPS-204 byte-compatibility, and it still leaves (2).
//
//  2. SECURITY EQUIVALENCE breaks regardless of (1). ML-DSA's EUF-CMA
//     reduction and concrete MLWE/Module-SIS hardness are stated for the
//     S_η secret distribution. A sum-of-contributions secret is a different
//     (and efficiently distinguishable) distribution; the FIPS-204 security
//     claim does not transfer.
//
//  3. FORCING the joint secret back into S_η is infeasible. Rejection-
//     sampling the joint into S_η requires every one of (L+K)·256
//     coefficients to independently land in [−η, η]; the acceptance
//     probability is (≈ (2η+1)/q)^… — negligible. A norm-reduction MPC
//     would change the (A, t) relation and hence the public key, breaking
//     verifiability under the same key. Constraining a Shamir RECONSTRUCTION
//     to S_η without a party knowing the secret is exactly a dealer.
//
// NOT the obstruction: t0. The joint t0 = Power2Round-low(joint t) lies in
// (−2^(d−1), 2^(d−1)] BY DEFINITION for ANY joint t, so ‖c·t0‖∞ ≤ τ·2^(d−1)
// < γ2 holds for every N. The wall is the SECRET (s1, s2) distribution, not
// the rounding residual. (assessDealerlessFIPS records this explicitly so
// the t0 red herring is ruled out by computation.)
//
// ─────────────────────────────────────────────────────────────────────────
// THE CORONA / RACCOON NOISE-FLOODING ADAPTATION (assessed, honest verdict).
//
// Corona's keyera.BootstrapPedersen IS genuinely dealerless. It escapes the
// wall above because corona is a NOISE-FLOODED Ring-LWE scheme, not ML-DSA:
//
//	β_j = A·(λ_j·s_j) + e_j'   with a fresh Gaussian e_j' ~ D(κ·σ_E·√n),
//	b   = Σ_j β_j = A·s + e''   (the √n-grown flooding noise),
//	bTilde = Round_Ξ(b)         (a rounding step that ABSORBS the noise).
//
// The √n-grown flooding noise is what LWE-protects each share, and corona's
// verifier TOLERATES it because its bounds are set for flooded noise and the
// Round_Ξ step folds the noise into the rounded public key. This is the
// RIGHT technique for a threshold-friendly lattice signature — and it is
// exactly why corona is dealerless.
//
// It does NOT adapt to byte-FIPS-204 ML-DSA. Noise-flooding deliberately
// ENLARGES the secret/error norms beyond S_η; ML-DSA has NO noise-absorbing
// rounding step (its t0 is the Power2Round residual, already consumed by the
// hint), a FIXED β = τη ceiling, and a verifier with no slack for flooded
// terms. Any noise-flooded / Gaussian-secret variant of ML-DSA is a
// Raccoon-family scheme (del Pino–Katsumata–Prest–Rossi, "Threshold
// Raccoon", EUROCRYPT 2024) with DIFFERENT parameters and a DIFFERENT
// verifier — its signatures do not verify under FIPS 204. This is precisely
// why the Quasar finality cert is AND-mode dual-PQ: a genuinely dealerless
// CORONA (Ring-LWE, noise-flooded) leg in parallel with a dealer/TEE-genesis
// PULSAR (FIPS-204 ML-DSA) leg. Permissionless safety rests on Corona; the
// Pulsar leg is FIPS-204-standard defence-in-depth.
//
// ─────────────────────────────────────────────────────────────────────────
// CANDIDATE RESEARCH DIRECTIONS (none ships byte-FIPS-204 dealerless today).
//
//  1. Threshold-friendly variant (NOT byte-ML-DSA): Threshold Raccoon /
//     NIST MPTC. Accepts a non-FIPS verifier; this is what Corona already
//     provides for the dealerless lane.
//  2. Distributed-rejection DKG with an EXACT ℓ∞ lattice range proof: each
//     party proves the joint secret ∈ S_η and the cohort resamples on
//     failure. Blocked twice: the exact ℓ∞ range proof does not exist in
//     this package (rangeproof.go: the available constructions certify ℓ2,
//     not ℓ∞), and the sum-lands-in-S_η acceptance probability is negligible.
//  3. Verifiable pseudorandom secret sharing whose reconstruction is in S_η
//     by construction — open for ML-DSA's exact distribution.
//  4. MPC-with-abort genesis (e.g. garbled-circuit KeyGen) that never
//     materialises the secret on one node — heavyweight, and sampling S_η
//     uniformly inside the MPC is the hard part; not "dealerless" in the
//     Pedersen sense.

import "errors"

// ErrDealerlessByteFIPSUnreachable is returned by DealerlessMLDSADKG. A
// genuinely dealerless DKG producing byte-FIPS-204 ML-DSA keys is not
// achievable with known techniques (see the file header). This entry point
// fails closed — it NEVER fakes a key and NEVER silently falls back to a
// trusted dealer or a TEE (those are the explicit, opt-in DealAlgShares /
// mldsa-tee paths). Production dealerless genesis is Corona's job in the
// AND-mode dual-PQ cert.
var ErrDealerlessByteFIPSUnreachable = errors.New(
	"pulsar: dealerless byte-FIPS-204 ML-DSA DKG is not achievable — a " +
		"dealerless joint secret is a sum of N≥2 contributions with ‖s2‖∞ ≤ Nη, " +
		"violating the BCC boundary-clearance hypothesis ‖c·s2‖∞ ≤ β (and ML-DSA's " +
		"S_η-calibrated EUF-CMA); use DealAlgShares (dealer/TEE genesis) for the " +
		"Pulsar leg and rely on the dealerless Corona leg for permissionless safety")

// DealerlessFIPSObstruction is the COMPUTED obstruction for a dealerless DKG
// over `parties` contributors at a given parameter set. Every field is
// derived from the FIPS 204 bounds; the test pins them. ByteFIPSReachable is
// true only in the degenerate single-contributor case (which is a dealer).
type DealerlessFIPSObstruction struct {
	Mode    Mode
	Parties int

	Eta          uint32 // η — the FIPS 204 S_η secret bound
	Tau          uint32 // τ — challenge weight
	Beta         uint32 // β = τ·η — the calibrated ‖c·s2‖∞ ≤ β bound + ‖z‖ ceiling slack
	Gamma2       uint32 // γ2 — the HighBits bucket half-width
	T0Bound      uint32 // 2^(d−1) — the Power2Round residual bound

	// Joint-secret norm growth under a dealerless sum of `parties`
	// contributions, each in S_η.
	JointS2Linf      uint32 // worst-case ‖s2_joint‖∞ ≤ parties·η
	JointCS2Linf     uint32 // worst-case ‖c·s2_joint‖∞ ≤ parties·β
	BCCMarginCovers  uint32 // the shift the FIXED 2β margin certifies: ≤ β
	JointCT0Linf     uint32 // worst-case ‖c·t0_joint‖∞ ≤ τ·2^(d−1)  (N-INDEPENDENT)

	// Derived verdicts.
	BoundaryHypothesisHolds bool // JointCS2Linf ≤ BCCMarginCovers  (β)
	T0BoundHolds            bool // JointCT0Linf < Gamma2  (always true — t0 via Power2Round)
	ByteFIPSReachable       bool // BoundaryHypothesisHolds && parties ≤ 1
}

// assessDealerlessFIPS computes the dealerless-DKG obstruction for `parties`
// contributors at `mode`. It is the single source of truth for the
// fail-closed decision: ByteFIPSReachable is false for every real dealerless
// committee (parties ≥ 2), and the reason is the boundary-clearance
// hypothesis ‖c·s2‖∞ ≤ β, computed here as JointCS2Linf vs BCCMarginCovers.
//
// ok=false for parameter sets outside the BCC-proven scope (ML-DSA-44),
// where the no-leak signing path itself does not apply.
func assessDealerlessFIPS(mode Mode, parties int) (DealerlessFIPSObstruction, bool) {
	gamma2, beta, _, ok := bccParams(mode)
	if !ok {
		return DealerlessFIPSObstruction{}, false
	}
	tau, _, _, _ := modeTauOmega(mode)
	_, _, eta := modeShape(mode)
	if parties < 1 {
		parties = 1
	}
	n := uint32(parties)
	t0Bound := uint32(1) << (bccD - 1)

	o := DealerlessFIPSObstruction{
		Mode:    mode,
		Parties: parties,
		Eta:     eta,
		Tau:     uint32(tau),
		Beta:    beta,
		Gamma2:  gamma2,
		T0Bound: t0Bound,

		// Dealerless sum of N S_η contributions: ‖s2_joint‖∞ ≤ N·η.
		JointS2Linf:  n * eta,
		JointCS2Linf: n * beta, // ‖c·s2_joint‖∞ ≤ τ·(N·η) = N·β
		// The FIXED BCC margin (boundary.go) certifies HighBits stability for
		// a shift of magnitude ≤ β only.
		BCCMarginCovers: beta,
		// t0 = Power2Round-low(joint t): in (−2^(d−1), 2^(d−1)] for ANY joint
		// t, so ‖c·t0‖∞ ≤ τ·2^(d−1), INDEPENDENT of N.
		JointCT0Linf: uint32(tau) * t0Bound,
	}
	o.BoundaryHypothesisHolds = o.JointCS2Linf <= o.BCCMarginCovers
	o.T0BoundHolds = o.JointCT0Linf < o.Gamma2
	o.ByteFIPSReachable = o.BoundaryHypothesisHolds && parties <= 1
	return o, true
}

// DealerlessMLDSADKG is the fail-closed dealerless-DKG entry point. There is
// no byte-FIPS-204 dealerless construction (see the file header and
// assessDealerlessFIPS), so for any real committee (parties ≥ 2) it returns
// ErrDealerlessByteFIPSUnreachable with the COMPUTED obstruction. It NEVER
// fabricates a key and NEVER falls back to a dealer/TEE — those are the
// explicit, opt-in DealAlgShares / mldsa-tee paths a caller must choose by
// name. The Corona leg provides the dealerless guarantee in the AND-mode
// dual-PQ cert.
func DealerlessMLDSADKG(params *Params, committee []NodeID, threshold int) (*DealerlessFIPSObstruction, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	o, ok := assessDealerlessFIPS(params.Mode, len(committee))
	if !ok {
		return nil, ErrBCCParamSet
	}
	if o.ByteFIPSReachable {
		// parties ≤ 1 — degenerate (a single contributor is a dealer). There
		// is no dealerless setting to satisfy; route through DealAlgShares.
		return &o, ErrDealerlessByteFIPSUnreachable
	}
	return &o, ErrDealerlessByteFIPSUnreachable
}
