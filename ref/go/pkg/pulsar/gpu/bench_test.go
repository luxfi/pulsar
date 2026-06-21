// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu_test

// bench_test.go — accelerator surface microbenchmarks.
//
// End-to-end signing timings live in the pulsar package's bench_test.go
// (the per-mode signing cost is what matters operationally; the
// accelerator flag has no semantic effect at N=256 on the dispatcher
// today).
//
// The microbenches here exercise:
//   BenchmarkUseAccelerator           — flag flip cost (atomic store)
//   BenchmarkRegisterRing_N256        — per-ring SubRing registry add
//   BenchmarkLatticeRingNTT_N256      — direct lattice/v7 SubRing.NTT
//                                       call timing under the same
//                                       defaultThreshold the accel
//                                       wrapper installs (showing the
//                                       single-poly cost the dispatcher
//                                       would face if engaged).
//
// These are diagnostic; operators inspecting accelerator hot-loop
// budgets read these to confirm the wrapper overhead is dwarfed by
// the SubRing.NTT cost.

import (
	"testing"

	"github.com/luxfi/lattice/v7/ring"

	"github.com/luxfi/pulsar/ref/go/pkg/pulsar/gpu"
)

func BenchmarkUseAccelerator(b *testing.B) {
	b.Cleanup(gpu.DisableAccelerator)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gpu.UseAccelerator()
	}
}

func BenchmarkRegisterRing_N256(b *testing.B) {
	b.Cleanup(gpu.DisableAccelerator)
	if err := gpu.UseAccelerator(); err != nil {
		b.Fatal(err)
	}
	r, err := ring.NewRing(256, []uint64{0x1000000004A01})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := gpu.RegisterRing(r); err != nil {
			b.Skipf("GPU registration unavailable on this build: %v", err)
		}
	}
}

// BenchmarkLatticeRingNTT_N256 measures the cost of one ring.SubRing
// forward NTT at pulsar's production ring degree N=256 on the q used
// by the surface tests. This is the throughput the lattice dispatcher
// would have to beat for single-poly dispatch to be a net win at
// N=256 — and the reason gpu.defaultThreshold is set to 1024 instead
// of 256 on the wrapper.
func BenchmarkLatticeRingNTT_N256(b *testing.B) {
	r, err := ring.NewRing(256, []uint64{0x1000000004A01})
	if err != nil {
		b.Fatal(err)
	}
	s := r.SubRings[0]
	src := make([]uint64, 256)
	for i := range src {
		src[i] = uint64(i)
	}
	dst := make([]uint64, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.NTT(src, dst)
	}
}
