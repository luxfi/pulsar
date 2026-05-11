// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"testing"
)

// runDKG runs a deterministic DKG with the given committee and threshold
// and returns the group public key + per-party shares.
func runDKG(t *testing.T, n, threshold int, mode Mode) (*PublicKey, []*KeyShare, [48]byte) {
	t.Helper()
	params := MustParamsFor(mode)
	committee := makeCommittee(n)
	sessions := make([]*DKGSession, n)
	for i := range sessions {
		s, err := NewDKGSession(params, committee, threshold, committee[i], deterministicReader([]byte{byte(i), 0xCA, 0xFE}))
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
	return outputs[0].GroupPubkey, shares, outputs[0].TranscriptHash
}

func TestThresholdSign_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"5of3", 5, 3},
		{"7of4", 7, 4},
		{"10of7", 10, 7},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params := MustParamsFor(ModeP65)
			pub, shares, _ := runDKG(t, tc.n, tc.t, ModeP65)

			msg := []byte("threshold sign — Class N1 round-trip")
			var sid [16]byte
			copy(sid[:], "pulsar-m-test-01")
			attempt := uint32(1)
			// Quorum = first t parties in canonical (sorted) order.
			quorum := make([]NodeID, tc.t)
			for i := 0; i < tc.t; i++ {
				quorum[i] = shares[i].NodeID
			}

			// Per-party ThresholdSigner.
			signers := make([]*ThresholdSigner, tc.t)
			for i := 0; i < tc.t; i++ {
				s, err := NewThresholdSigner(params, sid, attempt, quorum, shares[i], msg, deterministicReader([]byte{byte(i), 0xFE}))
				if err != nil {
					t.Fatal(err)
				}
				signers[i] = s
			}

			// Round 1.
			r1 := make([]*Round1Message, tc.t)
			for i, s := range signers {
				m, err := s.Round1(msg)
				if err != nil {
					t.Fatalf("Round1 party %d: %v", i, err)
				}
				r1[i] = m
			}

			// Round 2.
			r2 := make([]*Round2Message, tc.t)
			for i, s := range signers {
				m, ev, err := s.Round2(r1)
				if err != nil {
					t.Fatalf("Round2 party %d: %v (ev=%v)", i, err, ev)
				}
				r2[i] = m
			}

			// Combine.
			sig, err := Combine(params, pub, msg, nil, false, sid, attempt, quorum, tc.t, r1, r2, shares)
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if len(sig.Bytes) != params.SignatureSize {
				t.Fatalf("sig size %d want %d", len(sig.Bytes), params.SignatureSize)
			}

			// Verify under unmodified FIPS 204 — this is the Class N1 claim.
			if err := Verify(params, pub, msg, sig); err != nil {
				t.Fatalf("threshold-produced sig fails FIPS 204 Verify: %v", err)
			}
		})
	}
}

func TestThresholdSign_BadMAC_Detected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	pub, shares, _ := runDKG(t, 5, 3, ModeP65)
	msg := []byte("test-bad-mac")
	var sid [16]byte
	copy(sid[:], "bad-mac-sess-01")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[i], msg, deterministicReader([]byte{byte(i)}))
		signers[i] = s
	}
	r1 := make([]*Round1Message, 3)
	for i, s := range signers {
		r1[i], _ = s.Round1(msg)
	}

	// Tamper a MAC: party 0 sent a MAC to party 1. Corrupt it.
	if mac, ok := r1[0].MACs[quorum[1]]; ok {
		mac[0] ^= 0xff
		r1[0].MACs[quorum[1]] = mac
	}

	_, ev, err := signers[1].Round2(r1)
	if err != ErrRound1MACBad {
		t.Fatalf("expected MAC failure, got %v", err)
	}
	if ev == nil || ev.Kind != ComplaintMACFailure {
		t.Fatalf("expected MAC complaint, got %v", ev)
	}
	_ = pub
}

func TestThresholdSign_DifferentAttempt_Rejected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	pub, shares, _ := runDKG(t, 5, 3, ModeP65)
	msg := []byte("attempt-mismatch")
	var sid [16]byte
	copy(sid[:], "attempt-mism-01")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[i], msg, deterministicReader([]byte{byte(i)}))
		signers[i] = s
	}
	r1 := make([]*Round1Message, 3)
	for i, s := range signers {
		r1[i], _ = s.Round1(msg)
	}
	// Corrupt one party's attempt counter.
	r1[1].Attempt = 99
	if _, _, err := signers[0].Round2(r1); err != ErrAttemptMismatch {
		t.Fatalf("attempt mismatch not detected: %v", err)
	}
	_ = pub
}

func TestThresholdSign_TamperedReveal_RejectedAtCombine(t *testing.T) {
	params := MustParamsFor(ModeP65)
	pub, shares, _ := runDKG(t, 5, 3, ModeP65)
	msg := []byte("tampered-reveal")
	var sid [16]byte
	copy(sid[:], "tamper-reveal-01")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[i], msg, deterministicReader([]byte{byte(i)}))
		signers[i] = s
	}
	r1 := make([]*Round1Message, 3)
	for i, s := range signers {
		r1[i], _ = s.Round1(msg)
	}
	r2 := make([]*Round2Message, 3)
	for i, s := range signers {
		r2[i], _, _ = s.Round2(r1)
	}
	// Tamper one Round-2 PartialSig. With the v0.1 commit binding both
	// (mask, masked) under D_i, tampering ANY byte of the reveal is
	// caught at Combine time via commit-mismatch.
	r2[1].PartialSig[0] ^= 0xaa
	_, err := Combine(params, pub, msg, nil, false, sid, 1, quorum, 3, r1, r2, shares)
	if err != ErrRound2CommitBad {
		t.Fatalf("tampered reveal not detected: %v", err)
	}
	// Also tamper a byte in the masked half.
	r2[1].PartialSig[0] ^= 0xaa // revert
	r2[1].PartialSig[64] ^= 0x33
	_, err = Combine(params, pub, msg, nil, false, sid, 1, quorum, 3, r1, r2, shares)
	if err != ErrRound2CommitBad {
		t.Fatalf("tampered masked-half not detected: %v", err)
	}
}

func TestThresholdSign_QuorumTooSmall(t *testing.T) {
	params := MustParamsFor(ModeP65)
	_, shares, _ := runDKG(t, 5, 3, ModeP65)
	msg := []byte("small-q")
	var sid [16]byte
	quorum := []NodeID{shares[0].NodeID}
	_, err := NewThresholdSigner(params, sid, 1, quorum, shares[0], msg, deterministicReader([]byte{1}))
	if err != nil {
		t.Fatalf("single-party quorum: %v", err)
	}
	// Now try with empty quorum.
	_, err = NewThresholdSigner(params, sid, 1, nil, shares[0], msg, deterministicReader([]byte{1}))
	if err != ErrEmptyQuorum {
		t.Fatalf("empty quorum not rejected: %v", err)
	}
	// Member not in quorum.
	_, err = NewThresholdSigner(params, sid, 1, []NodeID{NodeID{0xff}}, shares[0], msg, deterministicReader([]byte{1}))
	if err != ErrNotInQuorum {
		t.Fatalf("non-member not rejected: %v", err)
	}
}

func TestThresholdSign_DifferentQuorum_SameMessage(t *testing.T) {
	// Two different quorums of size t over the same DKG should both
	// produce valid FIPS 204 signatures on the same message.
	params := MustParamsFor(ModeP65)
	pub, shares, _ := runDKG(t, 7, 4, ModeP65)
	msg := []byte("multi-quorum-test")
	for round, idxs := range [][4]int{{0, 1, 2, 3}, {3, 4, 5, 6}} {
		var sid [16]byte
		sid[0] = byte(round)
		quorum := []NodeID{shares[idxs[0]].NodeID, shares[idxs[1]].NodeID, shares[idxs[2]].NodeID, shares[idxs[3]].NodeID}
		signers := make([]*ThresholdSigner, 4)
		for j, idx := range idxs {
			s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[idx], msg, deterministicReader([]byte{byte(idx)}))
			signers[j] = s
		}
		r1 := make([]*Round1Message, 4)
		for j, s := range signers {
			r1[j], _ = s.Round1(msg)
		}
		r2 := make([]*Round2Message, 4)
		for j, s := range signers {
			r2[j], _, _ = s.Round2(r1)
		}
		sig, err := Combine(params, pub, msg, nil, false, sid, 1, quorum, 4, r1, r2, shares)
		if err != nil {
			t.Fatalf("quorum %v Combine: %v", idxs, err)
		}
		if err := Verify(params, pub, msg, sig); err != nil {
			t.Fatalf("quorum %v sig fails FIPS 204 Verify: %v", idxs, err)
		}
	}
}
