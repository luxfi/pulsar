// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_gpu_bench_test.go — CPU vs accelerator wall-clock
// benchmarks for the v0.3 algebraic-threshold sign path at small
// quorum shapes. Mirrors the corona/dkg2 bench discipline at
// corona/dkg2/dkg2_gpu_test.go (BenchmarkDKG2_GPU_Round1_{5of7,
// 7of11, 14of21}_{CPU,GPU}).
//
// Today the dispatcher is vacuous on pulsar's N=256 single-poly NTT
// (gpu.defaultThreshold=1024 > 256) so the CPU and GPU legs report
// equivalent ns/op modulo measurement noise. The benches exist as
// the wall-clock regression guard for the v0.4 lift that widens
// mldsa_lattice.go's NTT to 64-bit Montgomery and routes through
// ring.SubRing — at that point the GPU leg measures the BATCHED
// dispatch path and should win at production sizes.

import (
	"testing"

	pgpu "github.com/luxfi/pulsar/ref/go/pkg/pulsar/gpu"
)

// 5-of-7 — the headline shape the task asks for (matches corona's
// equivalent dkg2 bench).
func BenchmarkPulsarSign_5of7_CPU(b *testing.B) {
	pgpu.DisableAccelerator()
	benchV03Ceremony(b, 7, 5)
}

func BenchmarkPulsarSign_5of7_GPU(b *testing.B) {
	if err := pgpu.UseAccelerator(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(pgpu.DisableAccelerator)
	benchV03Ceremony(b, 7, 5)
}

// 7-of-11 — intermediate.
func BenchmarkPulsarSign_7of11_CPU(b *testing.B) {
	pgpu.DisableAccelerator()
	benchV03Ceremony(b, 11, 7)
}

func BenchmarkPulsarSign_7of11_GPU(b *testing.B) {
	if err := pgpu.UseAccelerator(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(pgpu.DisableAccelerator)
	benchV03Ceremony(b, 11, 7)
}

// 14-of-21 — production Lux consensus committee shape, matches
// BenchmarkDKG2_GPU_Round1_14of21 in corona.
func BenchmarkPulsarSign_14of21_CPU(b *testing.B) {
	pgpu.DisableAccelerator()
	benchV03Ceremony(b, 21, 14)
}

func BenchmarkPulsarSign_14of21_GPU(b *testing.B) {
	if err := pgpu.UseAccelerator(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(pgpu.DisableAccelerator)
	benchV03Ceremony(b, 21, 14)
}

// benchV03Ceremony drives the v0.3 ceremony to one successful
// signature per iteration. The rejection-restart loop is part of the
// measurement because operationally a higher restart probability
// pulls the GPU-leg wall-clock down proportionally with the per-
// attempt NTT cost — that is what we want the bench to reflect.
func benchV03Ceremony(b *testing.B, n, threshold int) {
	b.Helper()
	msg := []byte("pulsar v03 bench")
	var sid [16]byte
	copy(sid[:], "v03-bench-001-aa")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Vary sid per iteration so the rejection-restart RNG path
		// doesn't latch onto a single deterministic acceptance.
		sid[8] = byte(i)
		sid[9] = byte(i >> 8)
		var (
			sig *Signature
			err error
		)
		for attempt := uint32(0); attempt < 64; attempt++ {
			sig, _, _, _, _, _, _, err = stageAlgebraic(b, n, threshold, msg, sid, attempt)
			if err == nil {
				break
			}
			if err != ErrAlgebraicRestart {
				b.Fatalf("attempt %d unexpected err: %v", attempt, err)
			}
		}
		if sig == nil {
			b.Fatalf("no acceptance within 64 attempts")
		}
	}
}
