// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// bench_bcc_sign_test.go — DECOMPLECTED benchmark, ONE concern: the cost of the
// BCC no-reconstruct DISTRIBUTED sign (distributed_bcc.go — the
// DistributedBCCSigner ceremony culminating in the free-function AggregateBCC
// combine). This is the Shamir-shared (DealAlgShares) no-reconstruct path: every
// node holds exactly ONE share, emits only a proof-carrying z-partial, and the
// aggregator combines z = Σ z_i and recovers the hint from the PUBLIC w' — no
// process ever forms ≥ t shares or the seed.
//
// Two isolated measurements, both with keygen (DealAlgShares) in setup:
//
//   - BenchmarkBCCDistributedSign times the FULL per-signature ceremony: fresh
//     signers + the NonceMPC-stand-in deal + Round1 (bind nonce) + Round2 (emit
//     proof-carrying z-partials) + Finalize, including the FIPS-204 rejection-
//     restart loop (a fresh boundary-clear nonce per hint-weight rejection). The
//     in-process number is pure compute; 3 network rounds × RTT is additive in a
//     real deployment.
//
//   - BenchmarkBCCAggregate isolates the AggregateBCC path itself: one full
//     ceremony runs in SETUP to capture a known-good (aggregator, winning R1,
//     winning partials); the timed op is the aggregator's Finalize on those
//     fixed inputs — the per-partial proof verify + flat z-sum + public-w' hint
//     recovery + signature assembly + fail-closed self-verify — with NO nonce
//     deal, round messaging, or keygen in the hot loop. Finalize is a pure
//     function of (R1, partials) over the aggregator's immutable fields, so
//     re-running it on the captured inputs is deterministic and side-effect-free.
//
// Scope: ML-DSA-65/87 (the BCC proven scope). The DealAlgShares committees are
// ordinary Shamir (n, threshold) sets — NOT subject to the RSS C(N,M) viability
// bound — so the families here are the distributed-validator sizes the
// no-reconstruct suite proves (5-of-3, 5-of-4, 7-of-5).
//
// Run:
//
//	cd pulsar && export SDKROOT="$(xcrun --show-sdk-path)"; export GOWORK=off
//	go test -run='^$' -bench=BenchmarkBCC -benchmem ./ref/go/pkg/pulsar/
package pulsar

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"testing"
)

// bccSignCase is one (mode, n, threshold) distributed-signing committee.
type bccSignCase struct {
	mode      Mode
	n, thresh int
}

var bccSignCases = []bccSignCase{
	{mode: ModeP65, n: 5, thresh: 3},
	{mode: ModeP65, n: 5, thresh: 4},
	{mode: ModeP65, n: 7, thresh: 5},
	{mode: ModeP87, n: 5, thresh: 3},
	{mode: ModeP87, n: 5, thresh: 4},
	{mode: ModeP87, n: 7, thresh: 5},
}

// newBCCFixtureB builds a DealAlgShares group key for a (mode, n, threshold)
// committee — the *testing.B twin of newBCCFixture. Keygen is setup, never timed.
func newBCCFixtureB(b *testing.B, mode Mode, n, threshold int) *bccFixture {
	b.Helper()
	params := MustParamsFor(mode)

	committee := make([]NodeID, n)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(committee[i][:]); err != nil {
			b.Fatalf("committee id entropy: %v", err)
		}
	}
	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		b.Fatalf("master seed entropy: %v", err)
	}
	setup, shares, err := DealAlgShares(params, committee, threshold, seed, rand.Reader)
	for i := range seed { // wipe the master seed immediately
		seed[i] = 0
	}
	if err != nil {
		b.Fatalf("DealAlgShares(%s,n=%d,t=%d): %v", mode, n, threshold, err)
	}
	sort.Slice(shares, func(i, j int) bool { return nodeIDLess(shares[i].NodeID, shares[j].NodeID) })
	committee = make([]NodeID, n)
	for i, s := range shares {
		committee[i] = s.NodeID
	}
	return &bccFixture{
		params: params, setup: setup, committee: committee, shares: shares, threshold: threshold,
		idset: newTestIdentitySet(committee...),
	}
}

// bccCeremonyResult captures a completed no-reconstruct ceremony so the
// AggregateBCC path can be re-timed in isolation.
type bccCeremonyResult struct {
	agg      *DistributedBCCSigner
	r1       SignRound1
	partials []Partial
	sig      *Signature
	attempts int // nonce restarts the ceremony consumed before a hint cleared
}

// driveBCCCeremonyB runs one full no-reconstruct ceremony over an in-memory bus
// — the *testing.B twin of runBCCCeremony — and returns the winning aggregator,
// R1, and partials. Fresh signers each call; only round messages (and the
// NonceMPC-delivered y-shares) cross between nodes.
func driveBCCCeremonyB(b *testing.B, f *bccFixture, q int, sid [32]byte, ctx, msg []byte) bccCeremonyResult {
	b.Helper()
	quorum, evalPoints, qshares := f.quorum(q)

	nodes := make([]*DistributedBCCSigner, q)
	for i := 0; i < q; i++ {
		nd, err := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, ctx, msg, rand.Reader)
		if err != nil {
			b.Fatalf("NewDistributedBCCSigner: %v", err)
		}
		// Trusted in-memory bus: opt OUT of origin-auth explicitly (bare nil is
		// refused fail-closed). Origin auth is exercised by the blame suite.
		nd.SetIdentity(nil, UnauthenticatedAggregation)
		nodes[i] = nd
	}

	var aggNode *DistributedBCCSigner
	for _, nd := range nodes {
		if nd.IsAggregator() {
			aggNode = nd
			break
		}
	}
	if aggNode == nil {
		b.Fatal("no designated aggregator")
	}

	for attempt := 0; attempt < int(f.params.MaxRestart); attempt++ {
		var nonceID [32]byte
		nonceID[0] = byte(attempt)
		nonceID[1] = byte(attempt >> 8)
		copy(nonceID[2:], sid[:30])
		deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, q, nonceID, rand.Reader)
		if err != nil {
			b.Fatalf("DealNonceMPCDebug: %v", err)
		}

		var aggR1 SignRound1
		for i, nd := range nodes {
			if err := nd.SetNonceShare(nonceID, deal.YShares[quorum[i]]); err != nil {
				b.Fatalf("SetNonceShare: %v", err)
			}
			r1, err := nd.Round1(sid, nonceID, deal.Cert)
			if err != nil {
				b.Fatalf("Round1: %v", err)
			}
			if nd.IsAggregator() {
				aggR1 = r1
			}
		}

		partials := make([]Partial, 0, q)
		for _, nd := range nodes {
			p, err := nd.Round2(aggR1, PartialInput{})
			if err != nil {
				b.Fatalf("Round2: %v", err)
			}
			partials = append(partials, p)
		}

		_, cert, err := aggNode.Finalize(aggR1, partials)
		if err == nil {
			sig := cert.Signature
			return bccCeremonyResult{agg: aggNode, r1: aggR1, partials: partials, sig: &sig, attempts: attempt + 1}
		}
		if errors.Is(err, ErrNoFIPSHint) || errors.Is(err, ErrBCCExhausted) {
			continue // consume this nonce, retry with a fresh one
		}
		b.Fatalf("Finalize: %v", err)
	}
	b.Fatal("no acceptance within MaxRestart nonces")
	return bccCeremonyResult{}
}

// BenchmarkBCCDistributedSign times the FULL no-reconstruct distributed sign
// (fresh signers + nonce deal + 3 rounds + finalize, incl. rejection restarts).
// Keygen is setup.
func BenchmarkBCCDistributedSign(b *testing.B) {
	msg := []byte("M-Chain finality: leaderless permissionless threshold ML-DSA")
	for _, tc := range bccSignCases {
		tc := tc
		b.Run(fmt.Sprintf("%s_N%d_T%d", tc.mode, tc.n, tc.thresh), func(b *testing.B) {
			f := newBCCFixtureB(b, tc.mode, tc.n, tc.thresh)
			var sid [32]byte
			copy(sid[:], []byte("pulsar-bench-bcc-distributed-sign"))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// vary sid per iter so nonce sequences differ across iterations
				sid[31] = byte(i)
				res := driveBCCCeremonyB(b, f, tc.thresh, sid, nil, msg)
				if res.sig == nil {
					b.Fatalf("nil signature at iter %d", i)
				}
			}
			b.ReportMetric(float64(tc.thresh), "quorum")
		})
	}
}

// BenchmarkBCCAggregate isolates the AggregateBCC path: one ceremony in setup
// captures a known-good (aggregator, R1, partials); the timed op is the
// aggregator's Finalize on those fixed inputs (per-partial proof verify + flat
// z-sum + public-w' hint recovery + assembly + self-verify), deterministic and
// reconstruct-free.
func BenchmarkBCCAggregate(b *testing.B) {
	msg := []byte("M-Chain finality: AggregateBCC combine path, isolated")
	for _, tc := range bccSignCases {
		tc := tc
		b.Run(fmt.Sprintf("%s_N%d_T%d", tc.mode, tc.n, tc.thresh), func(b *testing.B) {
			f := newBCCFixtureB(b, tc.mode, tc.n, tc.thresh)
			var sid [32]byte
			copy(sid[:], []byte("pulsar-bench-bcc-aggregate-path"))
			res := driveBCCCeremonyB(b, f, tc.thresh, sid, nil, msg) // setup, not timed

			// Sanity: the captured inputs must re-finalize before timing.
			if _, _, err := res.agg.Finalize(res.r1, res.partials); err != nil {
				b.Skipf("captured ceremony does not re-finalize deterministically: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := res.agg.Finalize(res.r1, res.partials); err != nil {
					b.Fatalf("Finalize at iter %d: %v", i, err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(tc.thresh), "quorum")
			b.ReportMetric(float64(res.attempts), "setup_attempts")
		})
	}
}
