// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_cscp_dkg_test.go — Phase-3b CSCP-lift fidelity proof (step 4).
//
// Proves the deduplication is byte-faithful: the production CarryCompare now
// runs on the SHARED, malicious-secure luxfi/dkg cscp.SecureHighBitsVec (via the
// cscpSecureHighBitsVecDKG bridge), and its w1 is identical to BOTH
//
//  1. the in-house ideal functionality cefIdealSecureHighBits — kept in pulsar
//     as the test oracle per the Phase-3b handoff, and
//  2. the ground truth HighBits(A·ȳ) computed in the clear,
//
// for ML-DSA-65 (K=6) and ML-DSA-87 (K=8, exercising the K-override profile
// shim). This is a direct, per-coefficient proof of the lift's correctness that
// complements the end-to-end stock-FIPS-204 round-trip
// (TestTalus_MPC_EndToEnd_StockVerify / _Mode87): the round-trip proves the
// signature verifies; this proves the secure-comparison output itself is exact.

import (
	"crypto/rand"
	"testing"
)

// TestCSCP_DKGBridge_MatchesIdealOracle proves the luxfi/dkg malicious-secure
// CSCP bridge realises the same ideal HighBits functionality as the retained
// in-house oracle, and matches the cleartext ground truth — for both in-scope
// parameter sets.
func TestCSCP_DKGBridge_MatchesIdealOracle(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		const n, threshold = 5, 3
		var nonceID [32]byte
		nonceID[0] = 0xD0
		nonceID[1] = byte(mode)
		_, _, bus, evalPoints, wGround := cscpCommitteeBus(t, mode, n, threshold, nonceID)

		// Production path: the shared luxfi/dkg malicious-secure CSCP.
		got, err := cscpSecureHighBitsVecDKG(mode, bus, evalPoints, threshold, rand.Reader)
		if err != nil {
			t.Fatalf("%s dkg CSCP bridge: %v", mode, err)
		}

		// (1) equals the in-house ideal functionality (retained test oracle).
		want, err := cefIdealSecureHighBits(bus, mode)
		if err != nil {
			t.Fatalf("%s ideal oracle: %v", mode, err)
		}
		if !polyVecEqual(got, want) {
			t.Fatalf("%s dkg CSCP bridge w1 ≠ ideal F_HighBits", mode)
		}

		// (2) equals the cleartext ground truth HighBits(A·ȳ).
		gamma2, _, _, _ := bccParams(mode)
		if !polyVecEqual(got, highBitsVec(wGround, gamma2)) {
			t.Fatalf("%s dkg CSCP bridge w1 ≠ HighBits(A·ȳ)", mode)
		}
	}
}
