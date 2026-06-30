// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsard_test

import (
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/pulsar/pkg/pulsard"
	"github.com/luxfi/warp"
)

// testID builds a deterministic ids.ID from a label (left-aligned, zero-padded).
func testID(label string) ids.ID {
	var x ids.ID
	copy(x[:], label)
	return x
}

// testThreshold is a representative stake-weighted quorum (2/3).
var testThreshold = warp.WeightThreshold{Numerator: 2, Denominator: 3}

// subject32 returns a 32-byte subject filled from a label.
func subject32(label string) []byte {
	b := make([]byte, pulsard.SubjectLen)
	copy(b, label)
	return b
}

// newRefSigner builds a reference (trusted-dealer) signer + its era for tests.
// FOOTGUN path — proves the verify integration only.
func newRefSigner(t *testing.T) (*pulsard.Signer, warp.PulsarKeyEra) {
	t.Helper()
	signer, era, err := pulsard.NewReferenceSigner(
		testID("chain"), testID("signer-set"),
		7 /*keyEraID*/, 0 /*generation*/, 42 /*pChainHeight*/, testThreshold, nil,
	)
	if err != nil {
		t.Fatalf("NewReferenceSigner: %v", err)
	}
	return signer, era
}
