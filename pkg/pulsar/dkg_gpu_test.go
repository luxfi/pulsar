// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"testing"
)

// TestDKG_GPU_ByteEqual_Small proves byte-equal share output between the
// CPU dispatch leg and the parallel byte-slot fan-out leg for the GF(257)
// path. Same RNG seed → same coefficient stream → same shares.
//
// This is the core correctness theorem: GPU dispatch CANNOT diverge from
// the historical reference, otherwise a cross-validator KAT failure
// becomes a consensus halt during a DKG ceremony.
func TestDKG_GPU_ByteEqual_Small(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"n3_t2", 3, 2},
		{"n5_t3", 5, 3},
		{"n7_t4", 7, 4},
		{"n10_t7", 10, 7},
		{"n21_t14", 21, 14},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			seed := append([]byte("PULSAR-DKG-GPU-BYTEEQUAL-V1"), byte(tc.n), byte(tc.t))
			var secret [SeedSize]uint16
			for b := 0; b < SeedSize; b++ {
				secret[b] = uint16(seed[b%len(seed)])
			}
			needed := (tc.t - 1) * SeedSize * 2
			if needed < 2 {
				needed = 2
			}
			stream := cshake256(seed, needed, tagSeedShare)

			// CPU leg.
			prev := SetDKGGPUForTest(false)
			cpuShares, err := shamirDealRandomGFAccel(secret, tc.n, tc.t, stream)
			if err != nil {
				t.Fatalf("cpu leg: %v", err)
			}

			// GPU leg.
			SetDKGGPUForTest(true)
			gpuShares, err := shamirDealRandomGFAccel(secret, tc.n, tc.t, stream)
			if err != nil {
				t.Fatalf("gpu leg: %v", err)
			}
			SetDKGGPUForTest(prev)

			// Both must produce byte-equal share output.
			if len(cpuShares) != len(gpuShares) {
				t.Fatalf("share count mismatch: cpu=%d gpu=%d", len(cpuShares), len(gpuShares))
			}
			for i := range cpuShares {
				if cpuShares[i].X != gpuShares[i].X {
					t.Fatalf("share[%d] X mismatch: cpu=%d gpu=%d",
						i, cpuShares[i].X, gpuShares[i].X)
				}
				for b := 0; b < SeedSize; b++ {
					if cpuShares[i].Y[b] != gpuShares[i].Y[b] {
						t.Fatalf("share[%d].Y[%d] mismatch: cpu=%d gpu=%d",
							i, b, cpuShares[i].Y[b], gpuShares[i].Y[b])
					}
				}
			}
		})
	}
}

// TestDKG_GPU_ByteEqual_Large is the GF(q) counterpart of the small-path
// byte-equal test. Exercises shamirDealRandomQAccel.
func TestDKG_GPU_ByteEqual_Large(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"n3_t2", 3, 2},
		{"n7_t4", 7, 4},
		{"n21_t14", 21, 14},
		{"n40_t27", 40, 27},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			seed := append([]byte("PULSAR-DKG-GPU-LARGE-V1"), byte(tc.n), byte(tc.t))
			var secret [SeedSize]byte
			for b := 0; b < SeedSize; b++ {
				secret[b] = byte(seed[b%len(seed)] ^ byte(b))
			}
			needed := (tc.t - 1) * SeedSize * 4
			if needed < 4 {
				needed = 4
			}
			stream := cshake256(seed, needed, tagSeedShare)

			prev := SetDKGGPUForTest(false)
			cpuShares, err := shamirDealRandomQAccel(secret, tc.n, tc.t, stream)
			if err != nil {
				t.Fatalf("cpu leg: %v", err)
			}
			SetDKGGPUForTest(true)
			gpuShares, err := shamirDealRandomQAccel(secret, tc.n, tc.t, stream)
			if err != nil {
				t.Fatalf("gpu leg: %v", err)
			}
			SetDKGGPUForTest(prev)

			if len(cpuShares) != len(gpuShares) {
				t.Fatalf("share count mismatch: cpu=%d gpu=%d", len(cpuShares), len(gpuShares))
			}
			for i := range cpuShares {
				if cpuShares[i].X != gpuShares[i].X {
					t.Fatalf("share[%d] X mismatch: cpu=%d gpu=%d",
						i, cpuShares[i].X, gpuShares[i].X)
				}
				for b := 0; b < SeedSize; b++ {
					if cpuShares[i].Y[b] != gpuShares[i].Y[b] {
						t.Fatalf("share[%d].Y[%d] mismatch: cpu=%d gpu=%d",
							i, b, cpuShares[i].Y[b], gpuShares[i].Y[b])
					}
				}
			}
		})
	}
}

// TestDKG_GPU_SameGroupPubkey is the end-to-end byte-equal test. Runs the
// full DKG ceremony with the parallel byte-slot fan-out leg active, then
// re-runs it with the leg disabled, and asserts both ceremonies produce
// the SAME 32-byte group public key. This is the consensus-relevant
// guarantee: a validator that toggles GPU dispatch between ceremonies
// must still agree on the master public key with its peers.
func TestDKG_GPU_SameGroupPubkey(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"n5_t3", 5, 3},
		{"n7_t4", 7, 4},
		{"n21_t14", 21, 14},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params := MustParamsFor(ModeP65)
			committee := makeCommittee(tc.n)
			ident := newIdentityFixture(t, committee, []byte("dkg-gpu-pubkey-eq"))

			runCeremony := func(gpuOn bool) (*DKGOutput, [48]byte) {
				prev := SetDKGGPUForTest(gpuOn)
				defer SetDKGGPUForTest(prev)

				sessions := make([]*DKGSession, tc.n)
				for i := 0; i < tc.n; i++ {
					rng := deterministicReader([]byte{byte(i), 0xC0, 0xDE})
					s, err := NewDKGSession(params, committee, tc.t, committee[i],
						ident.keys[committee[i]], ident.directory, rng)
					if err != nil {
						t.Fatalf("session %d: %v", i, err)
					}
					sessions[i] = s
				}
				r1 := make([]*DKGRound1Msg, tc.n)
				for i, s := range sessions {
					m, err := s.Round1()
					if err != nil {
						t.Fatalf("r1 %d: %v", i, err)
					}
					r1[i] = m
				}
				r2 := make([]*DKGRound2Msg, tc.n)
				for i, s := range sessions {
					m, err := s.Round2(r1)
					if err != nil {
						t.Fatalf("r2 %d: %v", i, err)
					}
					r2[i] = m
				}
				outs := make([]*DKGOutput, tc.n)
				for i, s := range sessions {
					o, err := s.Round3(r1, r2)
					if err != nil {
						t.Fatalf("r3 %d: %v", i, err)
					}
					if o.AbortEvidence != nil {
						t.Fatalf("party %d aborted: %s", i, o.AbortEvidence.Kind)
					}
					outs[i] = o
				}
				// All parties must agree per ceremony.
				for i := 1; i < tc.n; i++ {
					if !outs[i].GroupPubkey.Equal(outs[0].GroupPubkey) {
						t.Fatalf("intra-ceremony pubkey mismatch parties 0 and %d", i)
					}
				}
				return outs[0], outs[0].TranscriptHash
			}

			cpuOut, cpuTH := runCeremony(false)
			gpuOut, gpuTH := runCeremony(true)

			// Group pubkey byte-equal.
			if !bytes.Equal(cpuOut.GroupPubkey.Bytes, gpuOut.GroupPubkey.Bytes) {
				t.Fatalf("group pubkey mismatch:\n  cpu=%x\n  gpu=%x",
					cpuOut.GroupPubkey.Bytes[:16], gpuOut.GroupPubkey.Bytes[:16])
			}
			// Transcript hash byte-equal.
			if cpuTH != gpuTH {
				t.Fatalf("transcript hash mismatch:\n  cpu=%x\n  gpu=%x", cpuTH, gpuTH)
			}
			// Secret share Y values byte-equal too (committee position 0).
			cpuShareY := cpuOut.SecretShare.Share
			gpuShareY := gpuOut.SecretShare.Share
			if !bytes.Equal(cpuShareY[:], gpuShareY[:]) {
				t.Fatalf("party-0 share Y mismatch:\n  cpu=%x\n  gpu=%x",
					cpuShareY[:16], gpuShareY[:16])
			}
		})
	}
}

// TestDKG_GPU_OutputPassesCorrectness re-runs the existing DKG correctness
// gate (reconstruct seed from threshold-sized share quorum; KeyFromSeed;
// verify against group pubkey; FIPS 204 sign + verify) with the GPU
// dispatch leg active. The pre-existing TestDKG_ProducesValidPubkey_
// VerifiableSign exercises the CPU leg; this case asserts the GPU leg
// produces output that satisfies the same correctness gate.
func TestDKG_GPU_OutputPassesCorrectness(t *testing.T) {
	prev := SetDKGGPUForTest(true)
	defer SetDKGGPUForTest(prev)

	params := MustParamsFor(ModeP65)
	committee := makeCommittee(5)
	threshold := 3
	ident := newIdentityFixture(t, committee, []byte("dkg-gpu-correctness"))

	sessions := make([]*DKGSession, 5)
	for i := range sessions {
		s, _ := NewDKGSession(params, committee, threshold, committee[i],
			ident.keys[committee[i]], ident.directory,
			deterministicReader([]byte{byte(i), 0x77}))
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

	keyShares := make([]*KeyShare, 5)
	for i := range outputs {
		keyShares[i] = outputs[i].SecretShare
	}

	// Reconstruct from a threshold-sized quorum.
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
		t.Fatalf("reconstructed pubkey != GPU-DKG group pubkey")
	}
	// FIPS 204 sign + verify on GPU-produced key material.
	msg := []byte("DKG-GPU produced a valid FIPS 204 key pair")
	sig, err := Sign(params, sk, msg, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(params, groupPub, msg, sig); err != nil {
		t.Fatalf("FIPS 204 verify failed on GPU-DKG signature: %v", err)
	}
}

// BenchmarkDKG_GPU_21of14_P65 measures the full multi-party DKG ceremony
// at the canonical Lux consensus committee size (n=21 validators, t=14
// threshold ≈ 2/3 BFT). The CPU baseline runs through shamirDealRandomGF
// single-threaded; the GPU run flips the parallel byte-slot fan-out on.
// The benchmark reports both so the user can read the speedup directly.
func BenchmarkDKG_GPU_21of14_P65_CPU(b *testing.B) {
	prev := SetDKGGPUForTest(false)
	defer SetDKGGPUForTest(prev)
	benchDKG(b, 21, 14, ModeP65)
}

func BenchmarkDKG_GPU_21of14_P65_GPU(b *testing.B) {
	prev := SetDKGGPUForTest(true)
	defer SetDKGGPUForTest(prev)
	benchDKG(b, 21, 14, ModeP65)
}

// BenchmarkDKG_GPU_PolyEvalOnly_21of14 isolates the polynomial-eval inner
// loop (the part GPU dispatch actually accelerates), without the
// ML-KEM-768 envelope-sealing overhead that dominates at small committee
// sizes. This is the kernel cost — the rest of the DKG is bounded by
// network IO and KEM ops, neither of which the GPU dispatch touches.
func BenchmarkDKG_GPU_PolyEvalOnly_21of14_CPU(b *testing.B) {
	prev := SetDKGGPUForTest(false)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnly(b, 21, 14)
}

func BenchmarkDKG_GPU_PolyEvalOnly_21of14_GPU(b *testing.B) {
	prev := SetDKGGPUForTest(true)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnly(b, 21, 14)
}

// Medium-committee benchmarks: probe the dispatch threshold.
func BenchmarkDKG_GPU_PolyEvalOnly_64of43_CPU(b *testing.B) {
	prev := SetDKGGPUForTest(false)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnly(b, 64, 43)
}

func BenchmarkDKG_GPU_PolyEvalOnly_64of43_GPU(b *testing.B) {
	prev := SetDKGGPUForTest(true)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnly(b, 64, 43)
}

func BenchmarkDKG_GPU_PolyEvalOnly_128of86_CPU(b *testing.B) {
	prev := SetDKGGPUForTest(false)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnly(b, 128, 86)
}

func BenchmarkDKG_GPU_PolyEvalOnly_128of86_GPU(b *testing.B) {
	prev := SetDKGGPUForTest(true)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnly(b, 128, 86)
}

// Large-committee benchmarks: the parallel byte-slot fan-out amortises
// once n × t is large enough that the goroutine-setup cost is small
// relative to the inner-loop work. At n=256, t=171 (3/4 BFT at the
// GF(257) cap) the parallel path opens a real lead.
func BenchmarkDKG_GPU_PolyEvalOnly_256of171_CPU(b *testing.B) {
	prev := SetDKGGPUForTest(false)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnly(b, 256, 171)
}

func BenchmarkDKG_GPU_PolyEvalOnly_256of171_GPU(b *testing.B) {
	prev := SetDKGGPUForTest(true)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnly(b, 256, 171)
}

// The GF(q) large-committee path scales further. At n=1024, t=683 the
// per-party work is ~32 × 1024 × 683 ≈ 22M modular ops — well above the
// kDKGParallelMinCells threshold.
func BenchmarkDKG_GPU_PolyEvalOnlyQ_1024of683_CPU(b *testing.B) {
	prev := SetDKGGPUForTest(false)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnlyQ(b, 1024, 683)
}

func BenchmarkDKG_GPU_PolyEvalOnlyQ_1024of683_GPU(b *testing.B) {
	prev := SetDKGGPUForTest(true)
	defer SetDKGGPUForTest(prev)
	benchPolyEvalOnlyQ(b, 1024, 683)
}

// benchPolyEvalOnly runs only the Shamir polynomial evaluation kernel —
// the hot path that GPU dispatch optimises. Measures pure compute, no
// KEM / cSHAKE / I/O.
func benchPolyEvalOnly(b *testing.B, n, t int) {
	var secret [SeedSize]uint16
	for i := 0; i < SeedSize; i++ {
		secret[i] = uint16(i * 7)
	}
	needed := (t - 1) * SeedSize * 2
	stream := cshake256([]byte("PULSAR-DKG-POLYEVAL-BENCH"), needed, tagSeedShare)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := shamirDealRandomGFAccel(secret, n, t, stream)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchPolyEvalOnlyQ(b *testing.B, n, t int) {
	var secret [SeedSize]byte
	for i := 0; i < SeedSize; i++ {
		secret[i] = byte(i * 7)
	}
	needed := (t - 1) * SeedSize * 4
	stream := cshake256([]byte("PULSAR-DKG-POLYEVALQ-BENCH"), needed, tagSeedShare)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := shamirDealRandomQAccel(secret, n, t, stream)
		if err != nil {
			b.Fatal(err)
		}
	}
}
