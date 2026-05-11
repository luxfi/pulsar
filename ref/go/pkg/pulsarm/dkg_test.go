// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"bytes"
	"testing"
)

func makeCommittee(n int) []NodeID {
	committee := make([]NodeID, n)
	for i := 0; i < n; i++ {
		committee[i] = NodeID{byte(i + 1)}
	}
	return committee
}

func TestDKG_HappyPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"3of2", 3, 2},
		{"5of3", 5, 3},
		{"7of4", 7, 4},
		{"10of7", 10, 7},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params := MustParamsFor(ModeP65)
			committee := makeCommittee(tc.n)

			sessions := make([]*DKGSession, tc.n)
			for i := 0; i < tc.n; i++ {
				rng := deterministicReader([]byte{byte(i), 0xDE, 0xAD})
				s, err := NewDKGSession(params, committee, tc.t, committee[i], rng)
				if err != nil {
					t.Fatal(err)
				}
				sessions[i] = s
			}

			// Round 1.
			r1 := make([]*DKGRound1Msg, tc.n)
			for i, s := range sessions {
				m, err := s.Round1()
				if err != nil {
					t.Fatalf("Round1 party %d: %v", i, err)
				}
				r1[i] = m
			}

			// Round 2.
			r2 := make([]*DKGRound2Msg, tc.n)
			for i, s := range sessions {
				m, err := s.Round2(r1)
				if err != nil {
					t.Fatalf("Round2 party %d: %v", i, err)
				}
				r2[i] = m
			}

			// Verify all parties computed the same digest.
			for i := 1; i < tc.n; i++ {
				if r2[i].Digest != r2[0].Digest {
					t.Fatalf("Round-2 digest mismatch between parties 0 and %d", i)
				}
			}

			// Round 3.
			outputs := make([]*DKGOutput, tc.n)
			for i, s := range sessions {
				out, err := s.Round3(r1, r2)
				if err != nil {
					t.Fatalf("Round3 party %d: %v", i, err)
				}
				if out.AbortEvidence != nil {
					t.Fatalf("party %d aborted: kind=%s", i, out.AbortEvidence.Kind)
				}
				outputs[i] = out
			}

			// All parties must agree on the group public key.
			groupPub := outputs[0].GroupPubkey
			for i := 1; i < tc.n; i++ {
				if !outputs[i].GroupPubkey.Equal(groupPub) {
					t.Fatalf("group pubkey mismatch parties 0 and %d", i)
				}
			}

			// All parties must agree on the transcript hash.
			for i := 1; i < tc.n; i++ {
				if outputs[i].TranscriptHash != outputs[0].TranscriptHash {
					t.Fatalf("transcript hash mismatch parties 0 and %d", i)
				}
			}

			// Each party has a share at its committee position.
			for i := 0; i < tc.n; i++ {
				if outputs[i].SecretShare.EvalPoint != uint32(i+1) {
					t.Fatalf("party %d: eval point %d want %d",
						i, outputs[i].SecretShare.EvalPoint, i+1)
				}
			}
		})
	}
}

func TestDKG_Equivocation_Detected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(3)
	sessions := make([]*DKGSession, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewDKGSession(params, committee, 2, committee[i], deterministicReader([]byte{byte(i)}))
		sessions[i] = s
	}
	r1 := make([]*DKGRound1Msg, 3)
	for i, s := range sessions {
		m, _ := s.Round1()
		r1[i] = m
	}
	r2 := make([]*DKGRound2Msg, 3)
	for i, s := range sessions {
		m, _ := s.Round2(r1)
		r2[i] = m
	}
	// Tamper one Round-2 digest.
	r2[1].Digest[0] ^= 0x01
	out, err := sessions[0].Round3(r1, r2)
	if err != nil {
		t.Fatalf("Round3: %v", err)
	}
	if out.AbortEvidence == nil {
		t.Fatalf("expected AbortEvidence on tampered digest")
	}
	if out.AbortEvidence.Kind != ComplaintEquivocation {
		t.Fatalf("expected equivocation, got %s", out.AbortEvidence.Kind)
	}
	if out.AbortEvidence.Accused != committee[1] {
		t.Fatalf("expected accused to be party 1, got %x", out.AbortEvidence.Accused[:8])
	}
}

func TestDKG_ProducesValidPubkey_VerifiableSign(t *testing.T) {
	// Run DKG, then have the trusted-aggregator (party 0) reconstruct
	// the seed from the threshold-sized share set and produce a
	// FIPS 204 signature. Verify it.
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(5)
	threshold := 3
	sessions := make([]*DKGSession, 5)
	for i := range sessions {
		s, _ := NewDKGSession(params, committee, threshold, committee[i], deterministicReader([]byte{byte(i), 0xAB}))
		sessions[i] = s
	}
	r1 := make([]*DKGRound1Msg, 5)
	for i, s := range sessions {
		r1[i], _ = s.Round1()
	}
	r2 := make([]*DKGRound2Msg, 5)
	for i, s := range sessions {
		r2[i], _ = s.Round2(r1)
	}
	outputs := make([]*DKGOutput, 5)
	for i, s := range sessions {
		outputs[i], _ = s.Round3(r1, r2)
	}
	groupPub := outputs[0].GroupPubkey

	// All shares.
	keyShares := make([]*KeyShare, 5)
	for i := range outputs {
		keyShares[i] = outputs[i].SecretShare
	}

	// Threshold signing — use the threshold protocol below.
	// Here we just verify that reconstructing the seed from the
	// threshold-sized share quorum recovers the same pubkey.
	shares := make([]shamirShare, threshold)
	for i := 0; i < threshold; i++ {
		var buf [shareWireSize]byte
		copy(buf[:], keyShares[i].Share[:])
		shares[i] = shareFromBytes(keyShares[i].EvalPoint, buf)
	}
	byteSum, err := shamirReconstructGF(shares)
	if err != nil {
		t.Fatal(err)
	}
	committeeRoot := committeeRootFromShares(keyShares)
	byteSumBytes := make([]byte, SeedSize*2)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes[2*b] = byte(byteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	var masterSeed [SeedSize]byte
	copy(masterSeed[:], cshake256(mixInput, SeedSize, tagSeedShare))
	sk, err := KeyFromSeed(params, masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !sk.Pub.Equal(groupPub) {
		t.Fatalf("reconstructed pubkey != DKG group pubkey")
	}
	// Sign + verify.
	msg := []byte("DKG produced a valid FIPS 204 key pair")
	sig, err := Sign(params, sk, msg, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(params, groupPub, msg, sig); err != nil {
		t.Fatalf("FIPS 204 verify failed on DKG-produced signature: %v", err)
	}
}

func TestDKG_NodeNotInCommittee(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(3)
	stranger := NodeID{0xff}
	if _, err := NewDKGSession(params, committee, 2, stranger, nil); err != ErrNotInCommittee {
		t.Fatalf("non-committee node not rejected: %v", err)
	}
}

func TestDKG_DuplicateCommittee(t *testing.T) {
	params := MustParamsFor(ModeP65)
	c := []NodeID{{1}, {2}, {1}}
	if _, err := NewDKGSession(params, c, 2, NodeID{1}, nil); err != ErrCommitteeDuplicate {
		t.Fatalf("dup committee not rejected: %v", err)
	}
}

func TestDKG_EmptyCommittee(t *testing.T) {
	params := MustParamsFor(ModeP65)
	if _, err := NewDKGSession(params, nil, 1, NodeID{1}, nil); err != ErrCommitteeEmpty {
		t.Fatalf("empty committee not rejected: %v", err)
	}
}

// deterministicReader returns a reader seeded by the given bytes,
// producing a long stream via cSHAKE256. Used for KAT-reproducible tests.
func deterministicReader(seed []byte) *detReader {
	return &detReader{seed: seed}
}

type detReader struct {
	seed []byte
	buf  []byte
	off  int
}

func (r *detReader) Read(p []byte) (int, error) {
	for n := 0; n < len(p); {
		if r.off >= len(r.buf) {
			// Generate a new chunk.
			input := append(append([]byte{}, r.seed...), byte(r.off>>16), byte(r.off>>8), byte(r.off))
			r.buf = cshake256(input, 4096, "PULSAR-M-TESTRAND-V1")
			r.off = 0
		}
		copied := copy(p[n:], r.buf[r.off:])
		n += copied
		r.off += copied
	}
	return len(p), nil
}

func TestDeterministicReader_Reproducible(t *testing.T) {
	a := deterministicReader([]byte{1, 2, 3})
	b := deterministicReader([]byte{1, 2, 3})
	bufA := make([]byte, 4096)
	bufB := make([]byte, 4096)
	a.Read(bufA)
	b.Read(bufB)
	if !bytes.Equal(bufA, bufB) {
		t.Fatalf("deterministic reader produced different streams")
	}
}
