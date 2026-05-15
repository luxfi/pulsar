// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"crypto/rand"
	"testing"
)

func BenchmarkKeyGen_P44(b *testing.B) { benchKeyGen(b, ModeP44) }
func BenchmarkKeyGen_P65(b *testing.B) { benchKeyGen(b, ModeP65) }
func BenchmarkKeyGen_P87(b *testing.B) { benchKeyGen(b, ModeP87) }

func benchKeyGen(b *testing.B, mode Mode) {
	params := MustParamsFor(mode)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateKey(params, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_P44(b *testing.B) { benchSign(b, ModeP44) }
func BenchmarkSign_P65(b *testing.B) { benchSign(b, ModeP65) }
func BenchmarkSign_P87(b *testing.B) { benchSign(b, ModeP87) }

func benchSign(b *testing.B, mode Mode) {
	params := MustParamsFor(mode)
	sk, _ := GenerateKey(params, rand.Reader)
	msg := []byte("benchmark message — measures FIPS 204 Sign latency end-to-end")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Sign(params, sk, msg, nil, true, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_P44(b *testing.B) { benchVerify(b, ModeP44) }
func BenchmarkVerify_P65(b *testing.B) { benchVerify(b, ModeP65) }
func BenchmarkVerify_P87(b *testing.B) { benchVerify(b, ModeP87) }

func benchVerify(b *testing.B, mode Mode) {
	params := MustParamsFor(mode)
	sk, _ := GenerateKey(params, rand.Reader)
	msg := []byte("benchmark message — measures FIPS 204 Verify latency end-to-end")
	sig, _ := Sign(params, sk, msg, nil, true, rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(params, sk.Pub, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDKG_5of3_P65(b *testing.B) { benchDKG(b, 5, 3, ModeP65) }
func BenchmarkDKG_7of4_P65(b *testing.B) { benchDKG(b, 7, 4, ModeP65) }
func BenchmarkDKG_10of7_P65(b *testing.B) { benchDKG(b, 10, 7, ModeP65) }

func benchDKG(b *testing.B, n, t int, mode Mode) {
	params := MustParamsFor(mode)
	committee := makeCommittee(n)
	b.ResetTimer()
	for iter := 0; iter < b.N; iter++ {
		sessions := make([]*DKGSession, n)
		for i := range sessions {
			rng := deterministicReader([]byte{byte(iter), byte(i)})
			s, _ := NewDKGSession(params, committee, t, committee[i], rng)
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
		for _, s := range sessions {
			_, _ = s.Round3(r1, r2)
		}
	}
}

func BenchmarkThresholdSign_5of3_P65(b *testing.B) { benchThresholdSign(b, 5, 3, ModeP65) }
func BenchmarkThresholdSign_7of4_P65(b *testing.B) { benchThresholdSign(b, 7, 4, ModeP65) }
func BenchmarkThresholdSign_10of7_P65(b *testing.B) { benchThresholdSign(b, 10, 7, ModeP65) }

func benchThresholdSign(b *testing.B, n, t int, mode Mode) {
	params := MustParamsFor(mode)
	committee := makeCommittee(n)
	// Set up DKG once outside the timer.
	sessions := make([]*DKGSession, n)
	for i := range sessions {
		rng := deterministicReader([]byte{byte(i), 0xBE})
		s, _ := NewDKGSession(params, committee, t, committee[i], rng)
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
		outputs[i], _ = s.Round3(r1, r2)
	}
	pub := outputs[0].GroupPubkey
	shares := make([]*KeyShare, n)
	for i := range outputs {
		shares[i] = outputs[i].SecretShare
	}
	msg := []byte("benchmark threshold sign — Class N1 round trip")
	quorum := make([]NodeID, t)
	for i := 0; i < t; i++ {
		quorum[i] = shares[i].NodeID
	}

	b.ResetTimer()
	for iter := 0; iter < b.N; iter++ {
		var sid [16]byte
		sid[0] = byte(iter)
		sid[1] = byte(iter >> 8)
		signers := make([]*ThresholdSigner, t)
		for i := 0; i < t; i++ {
			rng := deterministicReader([]byte{byte(iter), byte(i)})
			signers[i], _ = NewThresholdSigner(params, sid, 1, quorum, shares[i], msg, rng)
		}
		sr1 := make([]*Round1Message, t)
		for i, s := range signers {
			sr1[i], _ = s.Round1(msg)
		}
		sr2 := make([]*Round2Message, t)
		for i, s := range signers {
			sr2[i], _, _ = s.Round2(sr1)
		}
		_, err := Combine(params, pub, msg, nil, false, sid, 1, quorum, t, sr1, sr2, shares)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReshare_5to5_t3_P65(b *testing.B) { benchReshare(b, 5, 3, 5, 3, ModeP65) }

func benchReshare(b *testing.B, oldN, oldT, newN, newT int, mode Mode) {
	params := MustParamsFor(mode)
	oldCommittee := makeCommittee(oldN)
	newCommittee := makeCommittee(newN)
	// Set up DKG to get the old shares.
	sessions := make([]*DKGSession, oldN)
	for i := range sessions {
		rng := deterministicReader([]byte{byte(i), 0xCD})
		s, _ := NewDKGSession(params, oldCommittee, oldT, oldCommittee[i], rng)
		sessions[i] = s
	}
	r1 := make([]*DKGRound1Msg, oldN)
	for i, s := range sessions {
		r1[i], _ = s.Round1()
	}
	r2 := make([]*DKGRound2Msg, oldN)
	for i, s := range sessions {
		r2[i], _ = s.Round2(r1)
	}
	outputs := make([]*DKGOutput, oldN)
	for i, s := range sessions {
		outputs[i], _ = s.Round3(r1, r2)
	}
	oldShares := make([]*KeyShare, oldN)
	for i := range outputs {
		oldShares[i] = outputs[i].SecretShare
	}

	b.ResetTimer()
	for iter := 0; iter < b.N; iter++ {
		resh := make([]*ReshareSession, 0)
		for i := 0; i < oldN; i++ {
			var os *KeyShare
			if i < oldT {
				os = oldShares[i]
			}
			s, _ := NewReshareSession(params, oldCommittee, oldT, newCommittee, newT,
				oldCommittee[i], os, nil, deterministicReader([]byte{byte(iter), byte(i)}))
			resh = append(resh, s)
		}
		rr1 := []*DKGRound1Msg{}
		for _, s := range resh {
			if !s.InReshareQuorum() {
				continue
			}
			m, _ := s.Round1()
			rr1 = append(rr1, m)
		}
		rr2 := []*DKGRound2Msg{}
		for _, s := range resh {
			if !s.InReshareQuorum() {
				continue
			}
			m, _ := s.Round2(rr1)
			rr2 = append(rr2, m)
		}
		for _, s := range resh {
			_, _, _ = s.Round3(rr1, rr2)
		}
	}
}
