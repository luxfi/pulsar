// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"testing"
)

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
			pub, shares, _, ident := runDKGWithIdentities(t, tc.n, tc.t, ModeP65)

			msg := []byte("threshold sign — Class N1 round-trip")
			var sid [16]byte
			copy(sid[:], "pulsar-test-01")
			attempt := uint32(1)
			// Quorum = first t parties in canonical (sorted) order.
			quorum := make([]NodeID, tc.t)
			for i := 0; i < tc.t; i++ {
				quorum[i] = shares[i].NodeID
			}

			// Establish per-pair session keys for the quorum (CR-7).
			sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

			// Per-party ThresholdSigner.
			signers := make([]*ThresholdSigner, tc.t)
			for i := 0; i < tc.t; i++ {
				s, err := NewThresholdSigner(params, sid, attempt, quorum, shares[i], sessionKeys[shares[i].NodeID], msg, deterministicReader([]byte{byte(i), 0xFE}))
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
	pub, shares, _, ident := runDKGWithIdentities(t, 5, 3, ModeP65)
	msg := []byte("test-bad-mac")
	var sid [16]byte
	copy(sid[:], "bad-mac-sess-01")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[i], sessionKeys[shares[i].NodeID], msg, deterministicReader([]byte{byte(i)}))
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
	pub, shares, _, ident := runDKGWithIdentities(t, 5, 3, ModeP65)
	msg := []byte("attempt-mismatch")
	var sid [16]byte
	copy(sid[:], "attempt-mism-01")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[i], sessionKeys[shares[i].NodeID], msg, deterministicReader([]byte{byte(i)}))
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
	pub, shares, _, ident := runDKGWithIdentities(t, 5, 3, ModeP65)
	msg := []byte("tampered-reveal")
	var sid [16]byte
	copy(sid[:], "tamper-reveal-01")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[i], sessionKeys[shares[i].NodeID], msg, deterministicReader([]byte{byte(i)}))
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

// TestThresholdSwap_RejectedByCommitBind confirms the
// cross-party Round-2 swap attack does NOT go through.
//
// Adversarial premise (Agent 4 CRITICAL-1, downgraded after
// verification): Round2Message has no MAC field; an attacker could
// (in principle) swap two parties' Round-2 reveals to fool Combine.
//
// Why this attack actually fails: Combine looks up each Round-2 by
// its NodeID against the corresponding Round-1 commit and re-derives
// D_i = cSHAKE256(mask||masked||tau_1). Swapping NodeIDs makes the
// re-derived D_i not match the Round-1 commit → ErrRound2CommitBad.
//
// This test proves the rejection mechanically. As long as it passes,
// the dead-code `tagSignR2` constant (now removed) does NOT indicate
// a soundness gap — Round-2 integrity is provided by commit-bind,
// not by an explicit MAC. A future Round-2 MAC remains
// defense-in-depth, not a current soundness blocker.
func TestThresholdSwap_RejectedByCommitBind(t *testing.T) {
	params := MustParamsFor(ModeP65)
	pub, shares, _, ident := runDKGWithIdentities(t, 5, 3, ModeP65)
	msg := []byte("round-2 swap regression")
	var sid [16]byte
	copy(sid[:], "swap-test-sid-01")
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, err := NewThresholdSigner(params, sid, 1, quorum, shares[i],
			sessionKeys[shares[i].NodeID], msg,
			deterministicReader([]byte{byte(i), 0xC0, 0xDE}))
		if err != nil {
			t.Fatal(err)
		}
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

	// Sanity: the un-tampered tape must Combine cleanly.
	if _, err := Combine(params, pub, msg, nil, false, sid, 1,
		quorum, 3, r1, r2, shares); err != nil {
		t.Fatalf("un-tampered Combine failed: %v", err)
	}

	// --- Attack 1: swap two Round-2 messages outright ---
	// Take party-1's Round-2 PartialSig bytes and put them under
	// party-2's NodeID (and vice versa). The attacker is hoping
	// Combine accepts the swap because the bytes themselves are
	// authentic — they came from a real party reveal.
	swapped := make([]*Round2Message, 3)
	swapped[0] = r2[0]
	// Party-2's NodeID now carries party-1's reveal bytes.
	mut12 := *r2[1]
	mut12.NodeID = r2[2].NodeID
	swapped[1] = &mut12
	mut21 := *r2[2]
	mut21.NodeID = r2[1].NodeID
	swapped[2] = &mut21
	if _, err := Combine(params, pub, msg, nil, false, sid, 1,
		quorum, 3, r1, swapped, shares); err == nil {
		t.Fatal("Round-2 swap was NOT rejected — commit-bind broken")
	}

	// --- Attack 2: swap only the PartialSig bytes (keep NodeIDs) ---
	// Combine looks up Round-1 by NodeID then re-derives D_i. If
	// party-2's NodeID carries party-1's mask/masked bytes, the
	// re-derived D_2 won't match party-2's Round-1 commit.
	bodySwap := make([]*Round2Message, 3)
	bodySwap[0] = r2[0]
	mutB1 := *r2[1]
	mutB1.PartialSig = append([]byte{}, r2[2].PartialSig...)
	bodySwap[1] = &mutB1
	mutB2 := *r2[2]
	mutB2.PartialSig = append([]byte{}, r2[1].PartialSig...)
	bodySwap[2] = &mutB2
	if _, err := Combine(params, pub, msg, nil, false, sid, 1,
		quorum, 3, r1, bodySwap, shares); err != ErrRound2CommitBad {
		t.Fatalf("PartialSig swap not caught by commit-bind: %v", err)
	}
}

func TestThresholdSign_QuorumTooSmall(t *testing.T) {
	params := MustParamsFor(ModeP65)
	_, shares, _, _ := runDKGWithIdentities(t, 5, 3, ModeP65)
	msg := []byte("small-q")
	var sid [16]byte
	// Single-party quorum: no peers needed, so empty sessionKeys is OK.
	quorum := []NodeID{shares[0].NodeID}
	_, err := NewThresholdSigner(params, sid, 1, quorum, shares[0], map[NodeID][32]byte{}, msg, deterministicReader([]byte{1}))
	if err != nil {
		t.Fatalf("single-party quorum: %v", err)
	}
	// Now try with empty quorum.
	_, err = NewThresholdSigner(params, sid, 1, nil, shares[0], map[NodeID][32]byte{}, msg, deterministicReader([]byte{1}))
	if err != ErrEmptyQuorum {
		t.Fatalf("empty quorum not rejected: %v", err)
	}
	// Member not in quorum.
	_, err = NewThresholdSigner(params, sid, 1, []NodeID{{0xff}}, shares[0], map[NodeID][32]byte{}, msg, deterministicReader([]byte{1}))
	if err != ErrNotInQuorum {
		t.Fatalf("non-member not rejected: %v", err)
	}
	// Missing session key for peer.
	twoQ := []NodeID{shares[0].NodeID, shares[1].NodeID}
	_, err = NewThresholdSigner(params, sid, 1, twoQ, shares[0], map[NodeID][32]byte{}, msg, deterministicReader([]byte{1}))
	if err != ErrSessionKeyMissing {
		t.Fatalf("missing session key not rejected: %v", err)
	}
}

func TestThresholdSign_DifferentQuorum_SameMessage(t *testing.T) {
	// Two different quorums of size t over the same DKG should both
	// produce valid FIPS 204 signatures on the same message.
	params := MustParamsFor(ModeP65)
	pub, shares, _, ident := runDKGWithIdentities(t, 7, 4, ModeP65)
	msg := []byte("multi-quorum-test")
	for round, idxs := range [][4]int{{0, 1, 2, 3}, {3, 4, 5, 6}} {
		var sid [16]byte
		sid[0] = byte(round)
		quorum := []NodeID{shares[idxs[0]].NodeID, shares[idxs[1]].NodeID, shares[idxs[2]].NodeID, shares[idxs[3]].NodeID}
		sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
		signers := make([]*ThresholdSigner, 4)
		for j, idx := range idxs {
			s, _ := NewThresholdSigner(params, sid, 1, quorum, shares[idx], sessionKeys[shares[idx].NodeID], msg, deterministicReader([]byte{byte(idx)}))
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
