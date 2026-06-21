package pulsar

import "errors"

// Boundary-Cleared / Carry-Elimination threshold ML-DSA (Pulsar-BCC/CEF).
//
// No-MPC / no-TEE hint path replacing the leaking AlgebraicAggregate
// reconstruction (BLOCKERS.md PULSAR-V13-HINT-LEAK,
// spec/threshold-mldsa-boundary-clearance.tex).
//
// CONFORMANCE RULE (central invariant): the final hint h is determined by
// public nonce-region certificates and the public challenge — NEVER by
// reconstructing the secret residual. Nothing here forms c·s2, c·t0, r0,
// or LowBits(w + Δ). The hint is derived from the public reconstructed
// w' = A·z − c·t1·2^d and the public target w1 strictly via the FIPS 204
// UseHint primitive (no informal "±1 corrector").

var (
	// ErrBCCParamSet rejects parameter sets outside the proven scope.
	ErrBCCParamSet = errors.New(
		"pulsar: Pulsar-BCC/CEF is proven for ML-DSA-65/87 only; this " +
			"parameter set violates the ||c*t0||_inf < gamma2 bound")

	// ErrNoFIPSHint means no valid FIPS 204 hint reaches the target w1 for
	// some coefficient (boundary/region violated, or weight > omega).
	ErrNoFIPSHint = errors.New(
		"pulsar: no valid FIPS hint reaches target w1 (boundary/region " +
			"violated); consume the nonce and retry")
)

// bccD is the ML-DSA Power2Round low-bit drop; t0 ∈ [−2^(d−1), 2^(d−1)].
const bccD = 13

// bccParams returns (gamma2, beta = τ·η, omega) for a mode, and ok=false
// for any FIPS 204 parameter set outside the proven BCC scope. The scope
// condition is ‖c·t0‖∞ ≤ τ·2^(d−1) < γ2: it makes the FIPS c·t0 check
// vacuous and bounds the carry to ±1 high-bit. It holds for ML-DSA-65
// (49·4096 < 261888) and ML-DSA-87 (60·4096 < 261888) but NOT ML-DSA-44
// (39·4096 > 95232). Callers MUST gate on ok before signing.
func bccParams(mode Mode) (gamma2, beta, omega uint32, ok bool) {
	tau, om, _, g2 := modeTauOmega(mode)
	_, _, eta := modeShape(mode)
	if uint32(tau)*(1<<(bccD-1)) >= g2 {
		return 0, 0, 0, false
	}
	return g2, uint32(tau) * eta, uint32(om), true
}

// boundaryThreshold is the centered-low-bits magnitude below which a
// coefficient is boundary-clear: |a0_centered(w_j)| < γ2 − 2β. The 2β
// margin covers BOTH the HighBits boundary (the ±β shift c·s2 cannot
// change HighBits) AND the FIPS r0 rejection edge (‖LowBits(w − c·s2)‖∞ <
// γ2 − β stays in range) — high-bit stability alone is insufficient.
const bccSlack = 16 // one-coefficient safety slack against edge ambiguity

// boundaryThreshold saturates at 0: if the margin 2β+slack meets or exceeds
// γ2 (a degenerate or out-of-scope parameter set, e.g. the γ2=0 returned by
// bccParams for ML-DSA-44), NOTHING is boundary-clear. Without this guard the
// uint32 subtraction would underflow to a near-2³² threshold and mark every
// coefficient "clear" — a silent fail-OPEN. Callers MUST still gate on
// bccParams ok; this is defense in depth on the arithmetic itself.
func boundaryThreshold(gamma2 uint32, beta uint32) uint32 {
	margin := 2*beta + bccSlack
	if gamma2 <= margin {
		return 0
	}
	return gamma2 - margin
}

// centeredLowBits returns the FIPS Decompose low part of a, centered into
// (−γ2, γ2]. a must be normalized to [0, q).
func centeredLowBits(a uint32, gamma2 uint32) int32 {
	a0plusQ, _ := decompose(a, gamma2)
	a0 := int32(a0plusQ)
	if a0plusQ > (mldsaQ-1)/2 {
		a0 -= mldsaQ
	}
	return a0
}

// highBitsCoeff returns the FIPS Decompose high part a1 of a.
func highBitsCoeff(a uint32, gamma2 uint32) uint32 {
	_, a1 := decompose(a, gamma2)
	return a1
}

// boundaryClearCoeff reports whether coefficient a is far enough from
// every HighBits boundary that a hidden ±β shift cannot move its high bits
// and its hidden r0 stays in FIPS range.
func boundaryClearCoeff(a uint32, gamma2 uint32, beta uint32) bool {
	a0 := centeredLowBits(a, gamma2)
	if a0 < 0 {
		a0 = -a0
	}
	return uint32(a0) < boundaryThreshold(gamma2, beta)
}

// BoundaryClear is the offline, message-independent, fully-public nonce-
// certification predicate: every coefficient of the public commitment w is
// boundary-clear for the c·s2 perturbation. A surviving nonce guarantees
// HighBits(w − c·s2) = HighBits(w) = w1 and the FIPS r0-norm check for
// every valid challenge — without ever computing c·s2.
func BoundaryClear(w polyVec, gamma2 uint32, beta uint32) bool {
	for i := range w {
		for j := 0; j < mldsaN; j++ {
			if !boundaryClearCoeff(w[i][j], gamma2, beta) {
				return false
			}
		}
	}
	return true
}

// highBitsVec returns HighBits(w) coefficient-wise. w must be normalized.
func highBitsVec(w polyVec, gamma2 uint32) polyVec {
	out := make(polyVec, len(w))
	for i := range w {
		for j := 0; j < mldsaN; j++ {
			out[i][j] = highBitsCoeff(w[i][j], gamma2)
		}
	}
	return out
}

// useHint applies one FIPS 204 (Algorithm 40) hint bit to coefficient r,
// returning the corrected high part r1. m = (q−1)/(2γ2) high-bit buckets.
// r must be normalized to [0, q).
func useHint(hbit, r, gamma2 uint32) uint32 {
	m := uint32((mldsaQ - 1) / (2 * gamma2))
	r0plusQ, r1 := decompose(r, gamma2)
	if hbit == 0 {
		return r1
	}
	r0 := int32(r0plusQ)
	if r0plusQ > (mldsaQ-1)/2 {
		r0 -= mldsaQ
	}
	if r0 > 0 {
		return (r1 + 1) % m
	}
	return (r1 + m - 1) % m
}

// FindHint derives the ML-DSA hint from PUBLIC data only — the
// public reconstructed wPrime = A·z − c·t1·2^d and the public target w1 =
// HighBits(w). It NEVER forms c·s2, c·t0, or r0. The hint bit is not a
// signed correction: a coefficient takes h_j = 0 when HighBits already
// matches, h_j = 1 iff UseHint(1, ·) reaches the target, else there is no
// valid FIPS hint (boundary/region violated) and signing must consume the
// nonce and retry. Returns the hint and ok; ok=false ⇒ ErrNoFIPSHint.
//
// Theorem: FindHint(wPrime, w1) = (h, true) iff
// UseHint(h, wPrime) = w1 and weight(h) ≤ omega.
func FindHint(wPrime, targetW1 polyVec, gamma2, omega uint32) (polyVec, bool) {
	h := make(polyVec, len(wPrime))
	var weight uint32
	for i := range wPrime {
		for j := 0; j < mldsaN; j++ {
			switch {
			case highBitsCoeff(wPrime[i][j], gamma2) == targetW1[i][j]:
				h[i][j] = 0
			case useHint(1, wPrime[i][j], gamma2) == targetW1[i][j]:
				h[i][j] = 1
				weight++
			default:
				return nil, false // no valid FIPS hint for this coefficient
			}
		}
	}
	if weight > omega {
		return nil, false
	}
	return h, true
}
