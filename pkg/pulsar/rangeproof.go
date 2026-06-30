// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// rangeproof.go — the small-norm range-proof gate, decided by the bound
// arithmetic of the only well-reviewed constructions that apply here.
//
// SCOPE OF THIS FILE. The DKG well-formedness proof
// (dkg_wellformed_proof.go) and the nonce-transcript proof
// (nonce_transcript_proof.go) each prove ONE sound linear identity over
// R_q (a Maurer / generalized-Schnorr preimage proof, special-soundness
// from the invertibility of challenge differences in the prime field
// Z_q). What they CANNOT prove with a uniform-mask linear sigma is a
// norm bound on the witness. This file is the single, decomplected home
// for the question "is there a faithful, peer-reviewed range proof that
// soundly implies the FIPS 204 norm bound these checks need?", and it
// answers that question by ARITHMETIC, not by assertion.
//
// THE FIPS 204 BOUNDS ARE L-INFINITY (per-coefficient), NOT L2.
//
//	DKG:    ‖s1‖∞ ≤ η,  ‖s2‖∞ ≤ η,  ‖t0‖∞ ≤ 2^(d−1).
//	nonce:  ‖w0‖∞ ≤ γ2 − 2β − slack   (boundaryThreshold).
//
// THE WELL-REVIEWED LATTICE NORM PROOFS CERTIFY L2 (EUCLIDEAN) NORMS.
//
//	[BDLOP18] Baum, Damgård, Lyubashevsky, Oechsner, Peikert, "More
//	  Efficient Commitments from Structured Lattice Assumptions", SCN
//	  2018. A BDLOP/Ajtai commitment to a message m (binding under
//	  Module-SIS) plus a rejection-sampled opening proof certifies a
//	  RELAXED opening: an extracted m̄ and an invertible challenge
//	  difference c̄ (ℓ1-norm ≤ 2τ) with c̄·(commitment) opening to c̄·m̄.
//	  The norm it pins on the message is Euclidean, and only up to the
//	  rejection-sampling slack.
//
//	[LNS20] Lyubashevsky, Nguyen, Seiler, "Practical Lattice-Based Zero-
//	  Knowledge Proofs for Integer Relations" / "Shorter Lattice-Based
//	  Zero-Knowledge Proofs via One-Time Commitments" (ePrint 2020/1183,
//	  ASIACRYPT 2020). The EXACT norm proof certifies ⟨s,s⟩ = v over the
//	  NTT/CRT slots — the EXACT squared Euclidean norm of the committed
//	  s. No slack on the value, but still an ℓ2 statement.
//
//	[ENS20]/[LNS21] approximate range / approximate shortness proofs:
//	  certify ‖s‖2 ≤ ψ·B with a √-dimension soundness slack ψ ≥ 1.
//
// All three certify an ℓ2 bound. The only norm inequality relating ℓ2 to
// ℓ∞ in the useful direction is ‖x‖∞ ≤ ‖x‖2 (so an ℓ2 bound B implies an
// ℓ∞ bound B). The converse fails by a factor up to √(dimension).
//
// WHY AN ℓ2 PROOF CANNOT GATE THE FIPS ℓ∞ BOUND HERE (the crux).
//
// A faithful ℓ2 proof on, e.g., s1 must be COMPLETE for a real key: a
// genuine s1 has many coefficients at ±η, so ‖s1‖2 ≈ η·√(#nonzero), far
// larger than η. Completeness forces the proved bound B ≥ ‖s1‖2 ≈
// η·√(d). Soundness then guarantees only ‖s1‖2 ≤ ψ·B, hence the IMPLIED
// per-coefficient bound is ‖s1‖∞ ≤ ψ·B ≈ ψ·η·√(d) ≫ η. The gap is not
// "loose slack tunable down" — it is STRUCTURAL: an ℓ2 (Euclidean) proof
// carries no per-coefficient information, and the √-dimension factor is
// inherent. For the nonce w0 the implied ℓ∞ bound even EXCEEDS q (it is
// vacuous: every element of R_q satisfies it). See approxRangeImpliesFIPS
// and rangeproof_test.go, which compute these numbers from the live
// parameters.
//
// THE EXACT ℓ∞ RANGE PROOF (which WOULD imply the FIPS bound) IS NOT A
// SMALL PATCH AND IS NOT IMPLEMENTABLE FAITHFULLY HERE TODAY. The LNS
// exact range proof (ePrint 2020/1183 §5–6) proving every coefficient in
// {−η,…,η} requires (i) a BDLOP commitment to the witness whose binding
// reduces to Module-SIS — a fresh commitment matrix / CRS and an MSIS
// parameter set that DOES NOT EXIST anywhere in Pulsar today — and (ii) a
// product/quadratic-relation argument over the committed slots (the
// automorphism σ_{−1} toolbox, auxiliary "garbage" commitments, the
// invertible-difference challenge space). Writing that from the paper
// without the commitment layer is precisely the hand-rolled novel scheme
// the engineering rules forbid, and a wrong MSIS parameter or challenge
// space silently breaks soundness. The existing uniform-mask linear sigma
// cannot be extended to bound any norm: with a ←$ R_q the response
// u = a + e·s is uniform regardless of ‖s‖, so the transcript provably
// carries zero norm information.
//
// DECISION. Because no faithful, peer-reviewed construction available to
// this package soundly implies the FIPS ℓ∞ bound, the range gate stays
// FAIL-CLOSED — and that decision is DERIVED from the bound arithmetic
// below (approxRangeImpliesFIPS), not asserted. If a future externally-
// reviewed exact-range verifier is supplied, it is installed via
// RegisterDKGRangeProofVerifier / (a nonce analogue) and the gate opens.

// rangeProofClass enumerates the well-reviewed lattice norm-proof
// families. Recorded so the gate's reasoning is explicit and testable.
type rangeProofClass int

const (
	// rangeApproxL2 is a BDLOP/LNS/ENS approximate Euclidean-norm proof:
	// sound for ‖s‖2 ≤ ψ·B (ψ ≥ 1 the √-dimension soundness slack).
	rangeApproxL2 rangeProofClass = iota

	// rangeExactL2 is the LNS exact Euclidean-norm proof: sound for
	// ‖s‖2 ≤ B with no slack on the value (ψ = 1), still an ℓ2 statement.
	rangeExactL2

	// rangeExactLinf is the LNS exact range proof (every coefficient in
	// {−bound,…,bound}); the only family that directly certifies the FIPS
	// ℓ∞ bound. Not implementable faithfully in this package today.
	rangeExactLinf
)

// fipsRangeRequirement names a single FIPS 204 ℓ∞ small-norm requirement
// the protocol must enforce, with the per-coefficient bound it needs and
// the number of coefficients in the committed vector (used to compute the
// √-dimension gap between any ℓ2 proof and this ℓ∞ requirement).
type fipsRangeRequirement struct {
	name      string // human-readable witness name (s1, s2, t0, w0)
	linfBound uint32 // FIPS-required per-coefficient bound B∞ (‖·‖∞ ≤ B∞)
	numCoeffs int    // dimension of the committed vector (K·N or L·N)
}

// dkgRangeRequirements returns the three FIPS ℓ∞ small-norm requirements
// the DKG well-formedness check must enforce, for the given mode.
func dkgRangeRequirements(mode Mode) []fipsRangeRequirement {
	K, L, eta := modeShape(mode)
	const t0Bound = 1 << (mldsaD - 1) // ‖t0‖∞ ≤ 2^(d−1)
	return []fipsRangeRequirement{
		{name: "s1", linfBound: eta, numCoeffs: L * mldsaN},
		{name: "s2", linfBound: eta, numCoeffs: K * mldsaN},
		{name: "t0", linfBound: t0Bound, numCoeffs: K * mldsaN},
	}
}

// nonceRangeRequirement returns the single FIPS ℓ∞ small-norm requirement
// the nonce-transcript check must enforce (the w0 boundary margin), for
// the given mode. ok=false outside the BCC-proven parameter scope.
func nonceRangeRequirement(mode Mode) (fipsRangeRequirement, bool) {
	gamma2, beta, _, ok := bccParams(mode)
	if !ok {
		return fipsRangeRequirement{}, false
	}
	K, _, _ := modeShape(mode)
	return fipsRangeRequirement{
		name:      "w0",
		linfBound: boundaryThreshold(gamma2, beta), // γ2 − 2β − slack
		numCoeffs: K * mldsaN,
	}, true
}

// approxRangeImpliesFIPS reports whether a faithful norm proof of the
// given class, made COMPLETE for a witness meeting the FIPS requirement,
// soundly implies that requirement's ℓ∞ bound.
//
// The reasoning is exact, not heuristic:
//
//   - An ℓ2-class proof (approx or exact) must, for completeness, prove a
//     Euclidean bound B ≥ max real ‖witness‖2. A vector whose every
//     coefficient is within the FIPS ℓ∞ bound B∞ can have ‖·‖2 as large
//     as B∞·√(numCoeffs). So completeness forces B ≥ B∞·√(numCoeffs).
//     Soundness then certifies only ‖witness‖2 ≤ ψ·B, hence the strongest
//     IMPLIED per-coefficient bound is ‖witness‖∞ ≤ ψ·B ≥ B∞·√(numCoeffs).
//     For numCoeffs > 1 (always true here: ≥ N = 256) this implied ℓ∞
//     bound STRICTLY EXCEEDS the required B∞, so the FIPS bound is NOT
//     implied. (Often it even exceeds q, i.e. is vacuous.) Returns false.
//
//   - Only rangeExactLinf certifies a per-coefficient bound directly, so
//     only it can imply the FIPS ℓ∞ requirement. Returns true.
//
// This function is the single source of truth for the fail-closed
// decision: the range gate is closed precisely when this returns false
// for the class of proof actually available to the package.
func approxRangeImpliesFIPS(class rangeProofClass, req fipsRangeRequirement) bool {
	switch class {
	case rangeExactLinf:
		// A per-coefficient (ℓ∞) range proof of bound B∞ certifies exactly
		// the FIPS requirement. (The product argument prod_{v}(x−v)=0 pins
		// every coefficient into the discrete set.)
		return true
	case rangeApproxL2, rangeExactL2:
		// Euclidean-norm proof. Completeness forces the proved ℓ2 bound
		// B ≥ B∞·√(numCoeffs); the implied ℓ∞ bound ψ·B ≥ B∞·√(numCoeffs)
		// > B∞ whenever numCoeffs > 1. The only case where an ℓ2 bound
		// would coincide with the ℓ∞ requirement is a genuine SINGLE
		// coefficient (numCoeffs == 1). A degenerate requirement
		// (numCoeffs ≤ 0 — e.g. an unknown mode whose witness shape is
		// undefined, or a zero ℓ∞ bound) carries no statement to imply, so
		// it is never "implied" and the gate stays closed. Real ML-DSA
		// witnesses always have numCoeffs ≥ N = 256, so this branch is
		// always false in production — which is the whole point.
		return req.numCoeffs == 1 && req.linfBound > 0
	default:
		return false
	}
}

// availableRangeProofClass is the strongest range-proof family that can
// be implemented FAITHFULLY (standard, peer-reviewed, no hand-rolled
// commitment layer) inside this package today.
//
// It is rangeApproxL2: a BDLOP/LNS approximate Euclidean-shortness proof
// is faithful to published constructions. The EXACT ℓ∞ range proof
// (rangeExactLinf) needs a BDLOP commitment + Module-SIS parameter set +
// product argument that Pulsar does not have, so building it here would
// be hand-rolling — explicitly out of scope. This constant makes the gate
// honest: it says "the best faithful tool we have is an ℓ2 proof", and
// approxRangeImpliesFIPS then shows an ℓ2 proof cannot gate these ℓ∞
// bounds.
const availableRangeProofClass = rangeApproxL2

// rangeGateOpen reports whether the small-norm range gate can be opened
// for ALL of the supplied FIPS requirements using the strongest range
// proof faithfully available to the package. It is the parameterized,
// derived basis for the fail-closed defaults: it returns false (gate
// stays closed) exactly because availableRangeProofClass is an ℓ2 proof
// and an ℓ2 proof does not imply any of these ℓ∞ bounds.
func rangeGateOpen(reqs []fipsRangeRequirement) bool {
	for _, r := range reqs {
		if !approxRangeImpliesFIPS(availableRangeProofClass, r) {
			return false
		}
	}
	return len(reqs) > 0
}
