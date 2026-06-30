// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// naive_additive_seta_obstruction.go — the obstruction to a NAIVE dealerless
// DKG for byte-FIPS-204 ML-DSA, DERIVED from the parameter arithmetic (not
// asserted). This is the honest Part-2 deliverable of PULSAR-V12-PARALLEL-PQ: a
// Pedersen/Gennaro-style dealerless DKG that forms the joint secret as a SUM
// of N≥2 independent S_η contributions does NOT produce a key whose
// signatures verify byte-for-byte under unmodified FIPS 204, and THIS FILE
// COMPUTES WHY rather than faking a key or falling back to a dealer/TEE.
//
// SCOPE — do not over-read this as a general impossibility. The obstruction
// below is for (a) the NAIVE additive Pedersen/Gennaro lift and (b) noise-
// flooding (Raccoon/Corona, which yields a non-FIPS-204 verifier). It is NOT
// a proof that dealerless threshold ML-DSA cannot exist. Replicated secret
// sharing with SHORT shares + local per-party rejection sampling (Mithril:
// Celi–del Pino–Espitau–Niot–Prest, ia.cr/2026/013, USENIX Security 2026) is
// a KNOWN, published technique that achieves a dealerless DKG AND a-posteriori
// sharing of an existing key whose signatures verify under the STANDARD ML-DSA
// verifier, for a small party count N (≲8; replicated-share cost grows with
// (T,N)). Pulsar IMPLEMENTS it — mithril_rss.go (MithrilRSSKeygen) is the
// production dealerless escape past this wall. What is genuinely barred is the
// naive additive sum, not "dealerless ML-DSA" as a class.
//
// It mirrors rangeproof.go's pattern: the fail-closed decision is a
// COMPUTED consequence of the FIPS 204 bounds (assessDealerlessFIPS), and a
// test (naive_additive_seta_obstruction_test.go) pins the arithmetic so the
// obstruction is reproducible, not a claim.
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
// wall above because corona is a NOISE-FLOODED Module-LWE scheme (Ringtail/Raccoon line), not ML-DSA:
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
// CORONA (Module-LWE, noise-flooded) leg in parallel with a dealer/TEE-genesis
// PULSAR (FIPS-204 ML-DSA) leg. Permissionless safety rests on Corona; the
// Pulsar leg is FIPS-204-standard defence-in-depth.
//
// ─────────────────────────────────────────────────────────────────────────
// DEALERLESS ESCAPE (implemented) + remaining research directions for a
// byte-FIPS-204 dealerless threshold ML-DSA. Direction (1) is IMPLEMENTED
// (mithril_rss.go); (2)–(4) remain open.
//
//  1. SHORT replicated secret sharing + local per-party rejection (Mithril:
//     Celi–del Pino–Espitau–Niot–Prest, ia.cr/2026/013, USENIX Security 2026).
//     IMPLEMENTED — mithril_rss.go (MithrilRSSKeygen). This is the byte-FIPS-204
//     dealerless path: it keeps shares SHORT by construction (replicated, not
//     Shamir/Lagrange — naive Lagrange blows up coefficient norms and breaks
//     ML-DSA's short-vector requirement), enables local rejection (no
//     global-abort MPC), supports DKG AND a-posteriori sharing of an existing
//     key, and emits STANDARD ML-DSA-verifiable sigs. Practical at small N
//     (≲8; replicated-share cost grows with (T,N)). Contrast Threshold Raccoon
//     (EUROCRYPT 2024 / NIST MPTC): noise-flooded, NON-FIPS verifier — that is
//     Corona's dealerless lane, not byte-ML-DSA.
//  2. Distributed-rejection DKG with an EXACT ℓ∞ lattice range proof: each
//     party proves the joint secret ∈ S_η and the cohort resamples on
//     failure. Blocked twice in THIS package: the exact ℓ∞ range proof does
//     not exist here (rangeproof.go: the available constructions certify ℓ2,
//     not ℓ∞), and the naive sum-lands-in-S_η acceptance probability is
//     negligible. (Mithril (1) sidesteps both via short replicated shares.)
//  3. Masked Lagrange reconstruction for arbitrary threshold T while emitting
//     standard FIPS-204 signatures — research branch for large T (ordinary
//     Lagrange coefficients grow too large and fail ML-DSA rejection; masking
//     is what tames them).
//  4. MPC-with-abort genesis (e.g. garbled-circuit KeyGen) that never
//     materialises the secret on one node — heavyweight, and sampling S_η
//     uniformly inside the MPC is the hard part; not "dealerless" in the
//     Pedersen sense.

import "errors"

// ErrDealerlessByteFIPSUnreachable is returned by DealerlessMLDSADKG: the NAIVE
// additive (Pedersen/Gennaro) dealerless byte-FIPS-204 ML-DSA DKG is barred by
// the computed S_η obstruction below. This is NOT a general impossibility — a
// short-replicated-share construction (Mithril) achieves it at small N and is
// IMPLEMENTED in mithril_rss.go. This entry point fails closed — it NEVER fakes
// a key and NEVER silently falls back to a trusted dealer or a TEE; the
// production dealerless keygen is Mithril RSS (mithril_rss.go), and Corona's
// noise-flooded leg carries the second dealerless lane in the AND-mode dual-PQ
// cert.
var ErrDealerlessByteFIPSUnreachable = errors.New(
	"pulsar: naive additive (Pedersen/Gennaro) dealerless byte-FIPS-204 ML-DSA " +
		"DKG is unsound — a summed joint secret has ‖s2‖∞ ≤ Nη, violating the BCC " +
		"boundary-clearance hypothesis ‖c·s2‖∞ ≤ β (and ML-DSA's S_η-calibrated " +
		"EUF-CMA). This is the naive lift only, NOT a general impossibility: the " +
		"production dealerless keygen is Mithril RSS (mithril_rss.go, ia.cr/2026/013) " +
		"— short replicated shares that escape this wall at small N")

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

// DealerlessMLDSADKG is the fail-closed guard against the NAIVE additive
// dealerless DKG. There is no byte-FIPS-204 dealerless construction via the
// naive Pedersen/Gennaro sum (see the file header and assessDealerlessFIPS), so
// for any real committee (parties ≥ 2) it returns ErrDealerlessByteFIPSUnreachable
// with the COMPUTED obstruction. It NEVER fabricates a key and NEVER falls back
// to a dealer/TEE; the production dealerless keygen is Mithril RSS
// (mithril_rss.go), and Corona's leg carries the second dealerless lane in the
// AND-mode dual-PQ cert.
func DealerlessMLDSADKG(params *Params, committee []NodeID, threshold int) (*DealerlessFIPSObstruction, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	o, ok := assessDealerlessFIPS(params.Mode, len(committee))
	if !ok {
		return nil, ErrBCCParamSet
	}
	if o.ByteFIPSReachable {
		// parties ≤ 1 — degenerate (a single contributor IS a dealer). There is
		// no dealerless setting for the naive lift to satisfy; the production
		// dealerless keygen is Mithril RSS (mithril_rss.go).
		return &o, ErrDealerlessByteFIPSUnreachable
	}
	return &o, ErrDealerlessByteFIPSUnreachable
}
