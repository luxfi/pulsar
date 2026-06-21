package pulsar

import "testing"

// Production BCC signing must be disabled until BOTH required ZK proofs have
// sound, externally-reviewed verifiers registered (PULSAR-V13-W-LEAK,
// PULSAR-V13-PARTIAL-Z-PROOF). The default verifiers fail closed.
func TestProductionBCCSigningDisabledUntilSoundZK(t *testing.T) {
	if ProductionBCCSigningReady() {
		t.Fatal("production BCC signing must be disabled by default (no sound ZK proofs)")
	}
	if err := registeredClearanceVerifier.VerifyClearance(&BoundaryNonceCert{}); err != ErrClearanceProofUnsound {
		t.Fatalf("clearance verifier must fail closed, got %v", err)
	}
	if err := registeredPartialZVerifier.VerifyPartial(&BCCZPartial{}, nil, nil, nil); err != ErrPartialZProofUnsound {
		t.Fatalf("partial-z verifier must fail closed, got %v", err)
	}
}
