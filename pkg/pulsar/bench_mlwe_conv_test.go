// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// bench_mlwe_conv_test.go — DECOMPLECTED benchmark, ONE concern: the per-op
// poly↔mlwe.Poly CONVERSION overhead the Phase-4 DRY de-dup introduced into the
// ring hot loop. After routing the FIPS-204 ring core through
// github.com/luxfi/mlwe (mldsa_lattice.go / mldsa_sample.go), every ntt/invNTT/
// mulHat first widens Pulsar's [256]uint32 poly into an mlwe.Poly{[]uint64}
// (toMLWE — which ALLOCATES make([]uint64, 256)) and narrows the result back
// (fromMLWE). This benchmark measures whether that marshal is a measurable
// regression on the signing hot path, where polyDotHat → mulHat runs per matrix
// element and ntt runs per poly.
//
// The measurement is decomplected into the pure conversion vs the real ring math:
//
//   - toMLWE   : widen [256]uint32 → mlwe.Poly (1 heap alloc, 256-coeff copy)
//   - fromMLWE : narrow mlwe.Poly → [256]uint32 (0 allocs, value return)
//   - RoundTrip: fromMLWE(p.toMLWE()) — the PURE conversion tax per ring op,
//     no ring math; this is exactly the cost the de-dup added to each ntt
//   - NTT      : p.ntt()  = toMLWE + ring NTT + fromMLWE  (conversion + math)
//   - MulNTT   : p.mulHat = 2×toMLWE + ring MulNTT + fromMLWE (conversion + math)
//
// The de-dup OVERHEAD FRACTION is RoundTrip / NTT: if the conversion is a small
// slice of the actual transform, the DRY win cost nothing measurable; if it
// dominates, it is flagged. The number is reported honestly in the suite report;
// this file does NOT refactor the production conversion (a bench task must not
// touch production crypto — any braid is FLAGGED, not fixed).
//
// Run:
//
//	cd pulsar && export SDKROOT="$(xcrun --show-sdk-path)"; export GOWORK=off
//	go test -run='^$' -bench='BenchmarkMLWE|BenchmarkRing' -benchmem ./ref/go/pkg/pulsar/
package pulsar

import (
	"testing"

	"github.com/luxfi/mlwe"
)

// Package-level sinks defeat dead-code elimination so the compiler cannot
// optimize the measured op away.
var (
	sinkPoly poly
	sinkMLWE mlwe.Poly
)

// benchRingPoly builds a deterministic poly with all coefficients in [0, q)
// (a valid ring element) via a small LCG — no randomness in the timed path.
func benchRingPoly(seed uint32) poly {
	var p poly
	x := seed | 1
	for i := 0; i < mldsaN; i++ {
		x = x*1664525 + 1013904223
		p[i] = x % mldsaQ
	}
	return p
}

// BenchmarkMLWE_toMLWE isolates the widen [256]uint32 → mlwe.Poly conversion
// (the allocating half the de-dup added to every ring op).
func BenchmarkMLWE_toMLWE(b *testing.B) {
	p := benchRingPoly(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkMLWE = p.toMLWE()
	}
}

// BenchmarkMLWE_fromMLWE isolates the narrow mlwe.Poly → [256]uint32 conversion.
func BenchmarkMLWE_fromMLWE(b *testing.B) {
	p := benchRingPoly(2)
	m := p.toMLWE()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkPoly = fromMLWE(m)
	}
}

// BenchmarkMLWE_RoundTrip isolates the PURE conversion tax per ring op:
// fromMLWE(toMLWE(p)) with no ring math. This is precisely the overhead the
// de-dup added to each ntt/invNTT (and twice over to each mulHat's operands).
func BenchmarkMLWE_RoundTrip(b *testing.B) {
	p := benchRingPoly(3)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkPoly = fromMLWE(p.toMLWE())
	}
}

// BenchmarkRing_NTT_viaMLWE measures one forward NTT through the mlwe path
// (toMLWE + ring NTT + fromMLWE). A fresh copy per iteration keeps the input a
// valid [0,q) ring element (NTT mutates in place); the [256]uint32 copy is a
// stack memmove, no heap alloc.
func BenchmarkRing_NTT_viaMLWE(b *testing.B) {
	base := benchRingPoly(4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := base
		q.ntt()
		sinkPoly = q
	}
}

// BenchmarkRing_INTT_viaMLWE measures one inverse NTT through the mlwe path.
func BenchmarkRing_INTT_viaMLWE(b *testing.B) {
	base := benchRingPoly(5)
	base.ntt() // a well-formed NTT-domain element to invert
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := base
		q.invNTT()
		sinkPoly = q
	}
}

// BenchmarkRing_MulNTT_viaMLWE measures one NTT-domain pointwise product through
// the mlwe path (mulHat = 2×toMLWE + ring MulNTT + fromMLWE). The operands are
// NTT-domain elements built in setup; mulHat does not mutate them.
func BenchmarkRing_MulNTT_viaMLWE(b *testing.B) {
	aHat := benchRingPoly(6)
	bHat := benchRingPoly(7)
	aHat.ntt()
	bHat.ntt()
	var p poly
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.mulHat(&aHat, &bHat)
		sinkPoly = p
	}
}
