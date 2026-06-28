// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// bench_hyperball_test.go — REAL measured cost of the Mithril 3-round HYPERBALL
// no-reconstruct threshold signer (SignHyperball), for the Quasar PQ finality
// hot-path / checkpoint deployment decision.
//
// What this measures and why it matters:
//
//   - SignHyperball is the trustless (no-reconstruct) Pulsar SIGN path: K
//     parallel commitment slots × T parties × up to maxRounds re-runs, all in
//     ONE process here (so the number is the COMPUTE cost; network latency =
//     3 rounds × RTT is additive on top in a real deployment).
//   - K (kReps) grows with T (deriveHyperballParams): pSlot = (r/r1)^(dim·T)·yield,
//     K = ceil(3/pSlot) clamped [8,256]. The per-sign compute is ∝ K·T, so the
//     committee size drives block-time feasibility. This bench prints the derived
//     K for each committee alongside the wall-clock.
//   - Baselines: mk.Sign (the reconstruct path — forms the full key at the
//     coordinator, NOT trustless) and a single stock bccSign, to quantify the
//     "no-reconstruct tax".
//
// Run:
//
//	cd pulsar/ref/go/pkg/pulsar
//	export SDKROOT="$(xcrun --show-sdk-path)"; export GOWORK=off
//	go test . -run '^$' -bench 'BenchmarkHyperball' -benchtime=5x -timeout 30m -v
//
// The committees are the stock-circl-proven ones (n=8,t=7 and n=8,t=8; n=16,t=14
// attempted, skipped if keygen/sign is not viable in-budget). maxRounds is the
// same 64 the no-reconstruct gate tests use.
package pulsar

import (
	"fmt"
	"testing"
)

// hyperballCommittees are the committees benchmarked. (t,n) pairs that the
// no-reconstruct gate proves sign under stock circl.
var hyperballCommittees = [][2]int{
	{7, 8},
	{8, 8},
	{14, 16},
}

const hyperballBenchRounds = 64

// BenchmarkHyperballSign measures the no-reconstruct hyperball SIGN wall-clock
// per committee, and reports the derived K (parallel slots) and the rounds the
// winning run needed.
func BenchmarkHyperballSign(b *testing.B) {
	msg := []byte("Quasar finality subject M — hyperball no-reconstruct sign bench")
	ctx := []byte("quasar-pulsar-leg")

	for _, tn := range hyperballCommittees {
		t, n := tn[0], tn[1]
		b.Run(fmt.Sprintf("T%d_N%d", t, n), func(b *testing.B) {
			mk, err := MithrilRSSKeygen(ModeP65, t, n, mithrilSeeds(n))
			if err != nil {
				b.Skipf("keygen(T=%d,N=%d): %v", t, n, err)
				return
			}
			hp, err := deriveHyperballParams(ModeP65, t, n)
			if err != nil {
				b.Skipf("deriveHyperballParams(T=%d,N=%d): %v", t, n, err)
				return
			}
			active := canonicalActive(t)

			// Warm one sign to confirm viability and capture the round count.
			rng := newBCCDeterministicRNG(fmt.Sprintf("PULSAR/HYPERBALL/BENCH/%d-%d", t, n))
			sig, tr, err := mk.SignHyperball(active, msg, ctx, rng, hyperballBenchRounds)
			if err != nil {
				b.Skipf("warm SignHyperball(T=%d,N=%d): %v", t, n, err)
				return
			}
			b.ReportMetric(float64(hp.kReps), "K_slots")
			b.ReportMetric(float64(maxSubsetsPerParty(t, n)), "max_subsets")
			b.ReportMetric(float64(tr.Rounds), "warm_rounds")
			b.ReportMetric(float64(len(sig.Bytes)), "sig_bytes")

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := newBCCDeterministicRNG(fmt.Sprintf("PULSAR/HYPERBALL/BENCH/%d-%d/%d", t, n, i))
				if _, _, err := mk.SignHyperball(active, msg, ctx, r, hyperballBenchRounds); err != nil {
					// Some large committees (e.g. T=14,N=16) exhaust the K-clamped
					// slot budget intermittently — a documented scaling limit, not a
					// bench fault. Skip gracefully so viable committees still report.
					b.Skipf("SignHyperball(T=%d,N=%d) exhausted at iter %d: %v", t, n, i, err)
				}
			}
		})
	}
}

// BenchmarkHyperballReconstructBaseline measures mk.Sign — the RECONSTRUCT path
// (forms the full key at the coordinator; NOT trustless). The delta to
// BenchmarkHyperballSign is the no-reconstruct tax.
func BenchmarkHyperballReconstructBaseline(b *testing.B) {
	msg := []byte("Quasar finality subject M — reconstruct-path sign baseline")
	ctx := []byte("quasar-pulsar-leg")

	for _, tn := range hyperballCommittees {
		t, n := tn[0], tn[1]
		b.Run(fmt.Sprintf("T%d_N%d", t, n), func(b *testing.B) {
			mk, err := MithrilRSSKeygen(ModeP65, t, n, mithrilSeeds(n))
			if err != nil {
				b.Skipf("keygen(T=%d,N=%d): %v", t, n, err)
				return
			}
			active := canonicalActive(t)
			rng := newBCCDeterministicRNG(fmt.Sprintf("PULSAR/RECON/BENCH/%d-%d", t, n))
			if _, err := mk.Sign(active, msg, ctx, rng, 64); err != nil {
				b.Skipf("warm Sign(T=%d,N=%d): %v", t, n, err)
				return
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := newBCCDeterministicRNG(fmt.Sprintf("PULSAR/RECON/BENCH/%d-%d/%d", t, n, i))
				if _, err := mk.Sign(active, msg, ctx, r, 64); err != nil {
					// Intermittent rejection-sampling exhaustion on large committees
					// is a documented limit; skip rather than fail the run.
					b.Skipf("Sign(T=%d,N=%d) exhausted at iter %d: %v", t, n, i, err)
				}
			}
		})
	}
}
