package pulsar

import "errors"

// Zero-knowledge proof obligations for production BCC/CEF threshold ML-DSA.
//
// Two proofs are required and are NOT yet soundly implemented — they are
// research-grade lattice ZK constructions that MUST pass external
// cryptographic review before production:
//
//   1. Boundary-clearance proof (PULSAR-V13-W-LEAK): proves that a hidden
//      committed w = A·y satisfies w1 = HighBits(w) and BoundaryClear(w, 2β)
//      WITHOUT revealing w, LowBits(w), or per-coefficient distances. Full w
//      must never be public (else w' − w = c·t0 − c·s2 leaks long-term key
//      material).
//   2. Partial-z correctness proof (PULSAR-V13-PARTIAL-Z-PROOF): proves
//      z_i = λ_i·y_i + c·λ_i·s1_i bound to the DKG share commitment and the
//      nonce commitment WITHOUT revealing y_i or s1_i.
//
// To prevent a silent prototype from shipping, the default verifiers FAIL
// CLOSED: the production BCC signing path refuses to run until sound,
// externally-reviewed verifiers are explicitly registered. This is honest
// containment, not a stand-in for the proofs.

var (
	// ErrClearanceProofUnsound is returned by the default boundary-clearance
	// verifier: no sound construction exists yet.
	ErrClearanceProofUnsound = errors.New(
		"pulsar: BCC boundary-clearance ZK proof not implemented " +
			"(PULSAR-V13-W-LEAK); production BCC signing is DISABLED until a " +
			"sound, externally-reviewed proof is registered")

	// ErrPartialZProofUnsound is returned by the default partial-z verifier.
	ErrPartialZProofUnsound = errors.New(
		"pulsar: partial-z correctness proof not implemented " +
			"(PULSAR-V13-PARTIAL-Z-PROOF); production BCC signing is DISABLED " +
			"until a sound, externally-reviewed proof is registered")
)

// ClearanceVerifier verifies a boundary-clearance proof on a nonce cert
// without learning the hidden w.
type ClearanceVerifier interface {
	VerifyClearance(cert *BCCNonceCert) error
}

// PartialZVerifier verifies a z-partial's correctness proof without learning
// y_i or s1_i.
type PartialZVerifier interface {
	VerifyPartial(p *BCCZPartial, challenge []byte, dkgShareCommit, nonceCommit []byte) error
}

// failClosedClearance is the default: no sound proof exists yet.
type failClosedClearance struct{}

func (failClosedClearance) VerifyClearance(*BCCNonceCert) error { return ErrClearanceProofUnsound }

// failClosedPartialZ is the default: no sound proof exists yet.
type failClosedPartialZ struct{}

func (failClosedPartialZ) VerifyPartial(*BCCZPartial, []byte, []byte, []byte) error {
	return ErrPartialZProofUnsound
}

// Registered verifiers. Production must replace these with sound,
// externally-reviewed implementations before enabling BCC signing.
var (
	registeredClearanceVerifier ClearanceVerifier = failClosedClearance{}
	registeredPartialZVerifier  PartialZVerifier  = failClosedPartialZ{}
)

// RegisterClearanceVerifier installs a sound boundary-clearance verifier.
func RegisterClearanceVerifier(v ClearanceVerifier) { registeredClearanceVerifier = v }

// RegisterPartialZVerifier installs a sound partial-z verifier.
func RegisterPartialZVerifier(v PartialZVerifier) { registeredPartialZVerifier = v }

// ProductionBCCSigningReady reports whether BOTH required ZK proofs have
// sound verifiers registered. Until true, production BCC signing must not
// run. It is true only when neither default fail-closed verifier is active.
func ProductionBCCSigningReady() bool {
	_, clearanceUnsound := registeredClearanceVerifier.(failClosedClearance)
	_, partialUnsound := registeredPartialZVerifier.(failClosedPartialZ)
	return !clearanceUnsound && !partialUnsound
}
