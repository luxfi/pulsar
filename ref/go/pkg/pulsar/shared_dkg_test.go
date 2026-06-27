// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"testing"
)

// shared_dkg_test.go — DKG ceremony helpers shared across the test
// suite (dkg_test.go, reshare_test.go, threshold_v03_*_test.go, …).
//
// These formerly lived in threshold_test.go alongside the v0.1
// reconstruct-then-sign tests. When that v0.1 sign path was removed,
// the DKG helpers were relocated here so the v0.3 algebraic tests,
// reshare tests, and DKG tests retain their shared keygen fixture.

// runDKG runs a deterministic DKG with the given committee and threshold
// and returns the group public key + per-party shares.
func runDKG(t *testing.T, n, threshold int, mode Mode) (*PublicKey, []*KeyShare, [48]byte) {
	t.Helper()
	pub, shares, transcript, _ := runDKGWithIdentities(t, n, threshold, mode)
	return pub, shares, transcript
}

// runDKGWithIdentities is the extended helper that also returns the
// identity fixture used by the DKG ceremony. Threshold-sign tests
// reuse the fixture to derive the per-pair session keys for the
// signing quorum.
func runDKGWithIdentities(t *testing.T, n, threshold int, mode Mode) (*PublicKey, []*KeyShare, [48]byte, *identityFixture) {
	t.Helper()
	params := MustParamsFor(mode)
	committee := makeCommittee(n)
	ident := newIdentityFixture(t, committee, []byte{byte(n), byte(threshold), byte(mode)})
	sessions := make([]*DKGSession, n)
	for i := range sessions {
		s, err := NewDKGSession(params, committee, threshold, committee[i], ident.keys[committee[i]], ident.directory, deterministicReader([]byte{byte(i), 0xCA, 0xFE}))
		if err != nil {
			t.Fatal(err)
		}
		sessions[i] = s
	}
	r1 := make([]*DKGRound1Msg, n)
	for i, s := range sessions {
		r1[i], _ = s.Round1()
	}
	r2 := make([]*DKGRound2Msg, n)
	for i, s := range sessions {
		r2[i], _ = s.Round2(r1)
	}
	outputs := make([]*DKGOutput, n)
	for i, s := range sessions {
		out, err := s.Round3(r1, r2)
		if err != nil {
			t.Fatal(err)
		}
		if out.AbortEvidence != nil {
			t.Fatalf("DKG aborted at party %d: %s", i, out.AbortEvidence.Kind)
		}
		outputs[i] = out
	}
	shares := make([]*KeyShare, n)
	for i := range outputs {
		shares[i] = outputs[i].SecretShare
	}
	return outputs[0].GroupPubkey, shares, outputs[0].TranscriptHash, ident
}
