// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// bench_rss_keygen_test.go — DECOMPLECTED benchmark, ONE concern: the cost of
// the dealerless Replicated-Secret-Sharing DKG keygen (MithrilRSSKeygen,
// mithril_rss.go). This is the keygen that walks past the trusted-dealer wall:
// no party ever holds the whole key; the composite secret is the sum of
// C(N, N−T+1) fresh χ_η subset secrets.
//
// What this isolates and why it matters: MithrilRSSKeygen enumerates
// rss.EnumerateSubsets(t,n) and samples ONE short secret (ExpandS over K+L
// polys) per subset, so its cost scales ~linearly with the subset count
// C = C(N, N−T+1) = rss.NumSubsets(t,n). The committee families the protocol
// admits therefore trace a visible combinatorial curve. This benchmark makes
// that curve measurable by sweeping the admitted families and reporting the
// GROUND-TRUTH subset count (rss.NumSubsets — never a hand calc) and the hint-
// budget usage τ·C·η against the γ2=261888 viability margin as custom metrics.
//
// Admitted families (rss.ValidateCommittee, dkg v0.3.5): n=8,t=8 (C=8) ·
// n=8,t=7 (C=28) · n=16,t=14 (C=560 — the family the v0.6.3 uint32 overflow
// fix unblocked; τ·C·η=109760, 2.4× under γ2). The low-threshold large-N family
// n=16,t=12 (C=4368, τ·C·η=856128 ≥ γ2) is REJECTED by ValidateCommittee — its
// hint budget is structurally blown — so it appears here as a skip carrying the
// real rejection reason, making the viability WALL itself part of the curve.
//
// Modes: MithrilRSSKeygen runs for ML-DSA-44/65/87 (modeShape supports all
// three; ValidateCommittee's norm bound is mode-independent — it is stated in
// fixed ML-DSA-65 boundary constants), so the keygen cost is swept across all
// three parameter sets.
//
// Run:
//
//	cd pulsar && export SDKROOT="$(xcrun --show-sdk-path)"; export GOWORK=off
//	go test -run='^$' -bench=BenchmarkRSSDealerlessKeygen -benchmem ./ref/go/pkg/pulsar/
package pulsar

import (
	"fmt"
	"testing"

	"github.com/luxfi/dkg/rss"
)

// committeeFamily is one (T,N) committee the dealerless line is parameterized by.
type committeeFamily struct{ t, n int }

// rssKeygenFamilies are the committee families that drive the RSS keygen cost.
// Ordered by ascending subset count so -bench output reads as the combinatorial
// curve C(N,M): 8 → 28 → 560 → [4368 = the rejected wall].
// Named fields throughout: the protocol writes committees as "n=8,t=7", so an
// unnamed {8,7} on a {t,n} struct is a silent T>N inversion — named fields make
// the (T,N) pair unambiguous.
var rssKeygenFamilies = []committeeFamily{
	{n: 8, t: 8},   // C(8,1)  =   8   high-threshold T=N
	{n: 8, t: 7},   // C(8,2)  =  28   owner default
	{n: 16, t: 14}, // C(16,3) = 560   v0.6.3 overflow-fix family (tight: 2.4× under γ2)
	{n: 16, t: 12}, // C(16,5) = 4368  REJECTED: τ·C·η=856128 ≥ γ2 — the viability wall
}

var rssKeygenModes = []Mode{ModeP44, ModeP65, ModeP87}

// rssKeygenCase is one flat (mode, family) point in the sweep.
type rssKeygenCase struct {
	mode Mode
	t, n int
}

// rssKeygenCases flattens modes × families into a single list so the benchmark
// runs ONE b.Run per case with no loop nesting (nested b.Run under the
// benchmark re-entry mechanism measures only the first inner case per outer).
func rssKeygenCases() []rssKeygenCase {
	out := make([]rssKeygenCase, 0, len(rssKeygenModes)*len(rssKeygenFamilies))
	for _, mode := range rssKeygenModes {
		for _, fam := range rssKeygenFamilies {
			out = append(out, rssKeygenCase{mode: mode, t: fam.t, n: fam.n})
		}
	}
	return out
}

// BenchmarkRSSDealerlessKeygen measures MithrilRSSKeygen per (mode, family).
// Seeds are derived in setup (not timed); the timed op is the dealerless DKG
// itself. Custom metrics expose the combinatorial cost: subsets=C(N,M),
// subsetM=N−T+1, tau_C_eta=τ·C·η (vs γ2=261888).
func BenchmarkRSSDealerlessKeygen(b *testing.B) {
	for _, tc := range rssKeygenCases() {
		mode, t, n := tc.mode, tc.t, tc.n
		c := rss.NumSubsets(t, n)
		tauCEta := 49 * c * 4 // τ·C·η in ML-DSA-65 boundary units (γ2 = 261888)
		b.Run(fmt.Sprintf("%s_N%d_T%d", mode, n, t), func(b *testing.B) {
			// Fail-closed admission gate is part of the protocol: a rejected
			// family must surface its REAL reason, not a fabricated number.
			if err := rss.ValidateCommittee(t, n); err != nil {
				b.Skipf("ValidateCommittee(T=%d,N=%d) REJECTS (C(N,%d)=%d, τ·C·η=%d ≥ γ2=261888): %v",
					t, n, rss.SubsetSize(t, n), c, tauCEta, err)
			}
			seeds := mithrilSeeds(n) // deterministic; setup, not timed
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := MithrilRSSKeygen(mode, t, n, seeds); err != nil {
					b.Fatalf("MithrilRSSKeygen(%s,T=%d,N=%d): %v", mode, t, n, err)
				}
			}
			// Metrics reported after the loop (ResetTimer clears earlier ones):
			// the combinatorial cost drivers, as ground truth from rss.
			b.ReportMetric(float64(c), "subsets")
			b.ReportMetric(float64(rss.SubsetSize(t, n)), "subsetM")
			b.ReportMetric(float64(tauCEta), "tau_C_eta")
		})
	}
}
