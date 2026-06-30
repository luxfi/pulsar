// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus.go — the TALUS vocabulary: the two trust profiles, the per-parameter
// suite identifiers, the Quasar evidence kind, and the honest-majority bound.
//
// Pulsar implements the TALUS construction (Kao, "TALUS: Threshold ML-DSA with
// One-Round Online Signing via Boundary Clearance and Carry Elimination",
// arXiv:2603.22109). TALUS is the SOTA owner-authoritative threshold ML-DSA: it
// sidesteps the FROST-style additive-nonce wall (ML-DSA's HighBits/r0/carry
// rounding is non-linear, so no homomorphic nonce commitment exists) via three
// pillars that this package realises across talus_*.go and the existing BCC/CEF
// core (boundary.go, bcc_sign.go, distributed_bcc.go):
//
//  1. Boundary Clearance Condition (BCC) — boundary.go BoundaryClear:
//     accept only nonces whose commitment w = A·y has ‖r0‖∞ < γ2 − β, so the
//     secret shift c·s2 cannot cross a HighBits boundary and the hint is
//     PUBLIC-computable (FindHint over w' = A·z − c·t1·2^d). ~31.7% pass.
//  2. Carry Elimination Framework (CEF) — talus_cef.go: compute the challenge
//     input w1 = HighBits(A·y) distributedly over a secret-shared nonce y,
//     without reconstructing y or the full w (only w0 = LowBits(w) must stay
//     hidden — revealing it reconstructs the key residual w' − w = c·t0 − c·s2,
//     PULSAR-V13-W-LEAK).
//  3. Shamir Nonce DKG — talus_nonce_dkg.go: a dealerless one-time joint nonce.
//
// Online signing is ONE broadcast round: c = H(μ ‖ w1), each signer broadcasts
// z_i = λ_i·y_i + c·λ_i·s1_i (distributed_bcc.go Round2), the coordinator sums
// z, recovers the hint from public data, and emits a STOCK FIPS 204 signature
// that verifies under unmodified cloudflare/circl mldsa{65,87}.Verify.
//
// Security reduces to ML-DSA EUF-CMA (Module-LWE / Module-SIS): the output is a
// byte-standard FIPS 204 signature; BCC + CEF only change HOW the same (c̃, z, h)
// is produced, never WHAT a verifier checks. HONEST CAVEAT: the threshold
// signing transcript may be DISTINGUISHABLE in distribution from a single-party
// ML-DSA transcript (the masked CEF broadcasts and per-party z_i are extra
// observables), even though the final signature's byte format and verify path
// are identical and standard.

import "errors"

// TalusProfile selects the trust model for the OFFLINE w1 computation. It is
// orthogonal to the signing round shape (always one online broadcast) and to
// the FIPS parameter set (the TalusSuite). The online path and the emitted
// signature are byte-identical across profiles; only the custody of the nonce
// commitment w during preprocessing differs.
type TalusProfile uint8

const (
	// TalusProfileUnspecified rejects every operation (zero value is invalid).
	TalusProfileUnspecified TalusProfile = iota

	// TalusTEE (= TALUS-TEE) accelerates preprocessing with a trusted
	// coordinator / TEE that holds the joint nonce y, computes
	// w1 = HighBits(A·y) and the BCC filter directly, and deals the per-party
	// y-shares. NO honest-majority restriction: any N ≥ T. The TEE is the
	// w-custody boundary; it is wired through the OPTIONAL luxfi/tee extension
	// (attest.go AttestationContext), never baked into the core. This is the
	// profile the existing dealer-modelled nonce path (DealNonceMPCDebug)
	// honestly realises: a single trusted process forms w.
	TalusTEE

	// TalusMPC (= TALUS-MPC) is TEE-FREE and fully distributed: no process ever
	// holds the joint nonce y or the full commitment w. w1 is computed by the
	// CEF/CSCP over secret-shared y (talus_cef.go). Malicious-secure with
	// identifiable abort under an HONEST MAJORITY: T ≥ 2 for any N; T ≥ 3
	// requires N ≥ 2T−1 (TALUS Theorem 10.1 — any single-round Shamir carry
	// protocol needs this for information-theoretic privacy; concretely
	// enforced by the BGW multiplication substrate, talus_cef.go bgwMulShares).
	// This is the permissionless-validator profile. HONEST: TEE-free but NOT
	// MPC-free — one ONLINE round, but a multi-round OFFLINE preprocessing
	// phase (Shamir nonce DKG + CEF carry compare + Beaver-triple generation).
	TalusMPC
)

// String renders the profile name.
func (p TalusProfile) String() string {
	switch p {
	case TalusTEE:
		return "Pulsar-TEE"
	case TalusMPC:
		return "Pulsar-MPC"
	default:
		return "Pulsar-unspecified"
	}
}

// EvidenceKindPulsarTALUS is the Quasar consensus evidence kind for a TALUS
// threshold ML-DSA finality leg. It is DISTINCT from the Corona (Ring-LWE)
// evidence kind so a suite string can never dispatch a Pulsar leg to the Corona
// verifier or vice-versa: the AND-mode dual-PQ cert (lux dualpq) routes each
// kind to its own verifier. The output a verifier checks is a stock FIPS 204
// ML-DSA signature (VerifyBytes → mldsa{65,87}.Verify).
const EvidenceKindPulsarTALUS = "pulsar-talus-mldsa"

// TalusSuite is the full suite identifier carried in Quasar evidence: it pins
// the FIPS 204 parameter set so a verifier selects the correct ML-DSA verifier
// (mldsa65 vs mldsa87) and the correct BCC bounds. ML-DSA-44 has NO TALUS suite
// — it is outside the proven BCC scope (‖c·t0‖∞ < γ2 fails), so no suite string
// can request a TALUS-44 leg.
type TalusSuite string

const (
	// SuiteTalusMLDSA65 is the production target (NIST Category 3).
	SuiteTalusMLDSA65 TalusSuite = EvidenceKindPulsarTALUS + "-65"
	// SuiteTalusMLDSA87 is the Category-5 target.
	SuiteTalusMLDSA87 TalusSuite = EvidenceKindPulsarTALUS + "-87"
)

// ErrTalusSuiteUnsupported is returned for any mode outside the BCC-proven
// scope (notably ML-DSA-44).
var ErrTalusSuiteUnsupported = errors.New(
	"pulsar: no TALUS suite for this parameter set — TALUS is proven for " +
		"ML-DSA-65/87 only (ML-DSA-44 violates ‖c·t0‖∞ < γ2)")

// TalusSuiteFor returns the canonical suite identifier for a FIPS parameter
// set, refusing any set outside the BCC-proven scope.
func TalusSuiteFor(mode Mode) (TalusSuite, error) {
	switch mode {
	case ModeP65:
		return SuiteTalusMLDSA65, nil
	case ModeP87:
		return SuiteTalusMLDSA87, nil
	default:
		return "", ErrTalusSuiteUnsupported
	}
}

// Mode resolves the FIPS parameter set a suite identifier pins. The inverse of
// TalusSuiteFor; a verifier uses it to select mldsa65 vs mldsa87.
func (s TalusSuite) Mode() (Mode, error) {
	switch s {
	case SuiteTalusMLDSA65:
		return ModeP65, nil
	case SuiteTalusMLDSA87:
		return ModeP87, nil
	default:
		return ModeUnspecified, ErrTalusSuiteUnsupported
	}
}

// TalusMinPartiesMPC returns the minimum committee size N for a reconstruction
// threshold T in the TalusMPC profile. It encodes TALUS Theorem 10.1: a
// single-round Shamir-based carry-elimination protocol with T ≥ 3 needs
// N ≥ 2T−1 for information-theoretic privacy (the degree-2(T−1) product of two
// degree-(T−1) sharings, which the BGW multiplication substrate forms during
// CarryCompare, is only reconstructable when N ≥ 2T−1). For T ≤ 2 any N ≥ T
// suffices. The TalusTEE profile has no such bound (the TEE replaces the
// honest-majority carry protocol).
func TalusMinPartiesMPC(threshold int) int {
	if threshold < 3 {
		return threshold
	}
	return 2*threshold - 1
}

// TalusProfileAllows reports whether a committee (threshold T of N parties) is
// admissible for a profile. TalusTEE accepts any 1 ≤ T ≤ N; TalusMPC additionally
// requires N ≥ TalusMinPartiesMPC(T).
func TalusProfileAllows(profile TalusProfile, threshold, parties int) bool {
	if threshold < 1 || parties < threshold {
		return false
	}
	switch profile {
	case TalusTEE:
		return true
	case TalusMPC:
		return parties >= TalusMinPartiesMPC(threshold)
	default:
		return false
	}
}
