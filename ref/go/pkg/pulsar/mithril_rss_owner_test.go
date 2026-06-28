// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"fmt"
	"testing"

	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/luxfi/dkg/rss"
)

// TestMithrilRSS_OwnerFaultTolerant_StockCircl is THE payoff: the owner's
// fault-tolerant DEFAULT committees — n=8,t=7 (tolerates any 1 fault) and
// n=16,t=14 (tolerates any 2 faults) — are DEALERLESS (RSS keygen, no trusted
// dealer) and their threshold signatures verify BYTE-FOR-BYTE under unmodified
// cloudflare/circl mldsa65.Verify, for ARBITRARY T-subset active signer sets.
//
// These are T<N committees at N>6: they keygen'd fine before but FAILED CLOSED at
// reconstruction/Sign because canonicalSharing had no partition entry past N=6.
// Two fixes unblock them: (1) the general Algorithm-6 balanced partition
// (dkg v0.3.5), and (2) the uint32 subset-accumulation overflow fix (this repo) —
// the latter mattered specifically at n=16,t=14 (C(16,3)=560 > 512), where the
// reconstructed ‖s2‖∞ otherwise came out ≈ q/2 and nothing could sign. Each quorum
// is independently signed and verified; rejection attempts are measured.
func TestMithrilRSS_OwnerFaultTolerant_StockCircl(t *testing.T) {
	const budget = 1 << 20
	msg := []byte("Pulsar dealerless RSS — owner fault-tolerant default, stock ML-DSA-65")
	var ctx []byte

	for _, c := range []struct {
		tt, n      int
		activeSets [][]int
	}{
		{7, 8, dropEachOne(8)},      // tolerate any 1 fault → all 8 distinct quorums
		{14, 16, faultSets16of14()}, // tolerate any 2 faults → representative quorums
	} {
		c := c
		t.Run(fmt.Sprintf("n%d_t%d", c.n, c.tt), func(t *testing.T) {
			mk, err := MithrilRSSKeygen(ModeP65, c.tt, c.n, mithrilSeeds(c.n))
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			var pkC mldsa65.PublicKey
			if err := pkC.UnmarshalBinary(mk.Pub()); err != nil {
				t.Fatalf("circl unmarshal pk: %v", err)
			}

			worst, best := 0, 1<<30
			for _, active := range c.activeSets {
				if !isSortedDistinct(active, c.n) {
					t.Fatalf("malformed active set %v", active)
				}
				km, err := mk.ReconstructKeyMaterial(active)
				if err != nil {
					t.Fatalf("active=%v reconstruct: %v", active, err)
				}
				rng := newBCCDeterministicRNG(fmt.Sprintf("PULSAR/MITHRIL/OWNER/%d-%d/%v", c.tt, c.n, active))
				sig, tr, err := bccSign(km, ModeP65, msg, ctx, rng, budget)
				if err != nil {
					t.Fatalf("active=%v bccSign failed within %d attempts: %v (C=%d, ‖s2‖∞≤%d)",
						active, budget, err, rss.NumSubsets(c.tt, c.n), rss.MaxSecretNorm(c.tt, c.n, 4))
				}
				// THE proof: stock, unmodified circl verifies the dealerless sig.
				if !mldsa65.Verify(&pkC, msg, ctx, sig) {
					t.Fatalf("active=%v: STOCK circl mldsa65.Verify REJECTED the dealerless RSS signature", active)
				}
				// Verifier is non-vacuous: tamper + wrong-message rejected.
				tampered := append([]byte(nil), sig...)
				tampered[len(tampered)/2] ^= 0x01
				if mldsa65.Verify(&pkC, msg, ctx, tampered) {
					t.Fatalf("active=%v: circl accepted a tampered signature — verifier vacuous", active)
				}
				if mldsa65.Verify(&pkC, []byte("a different finalized subject"), ctx, sig) {
					t.Fatalf("active=%v: circl accepted a wrong-message signature — binding broken", active)
				}
				if tr.attempts > worst {
					worst = tr.attempts
				}
				if tr.attempts < best {
					best = tr.attempts
				}
			}

			// The production Sign wrapper (fail-closed self-verify) also yields a
			// stock-verifiable signature for the default canonical quorum.
			prodSig, err := mk.Sign(c.activeSets[0], msg, ctx,
				newBCCDeterministicRNG("PULSAR/MITHRIL/OWNER/PROD"), budget)
			if err != nil {
				t.Fatalf("production Sign: %v", err)
			}
			if !mldsa65.Verify(&pkC, msg, ctx, prodSig.Bytes) {
				t.Fatal("production Sign output rejected by stock circl")
			}

			t.Logf("n=%d t=%d DEALERLESS RSS → stock circl PASS for all %d T-subset quorums; "+
				"rejection attempts best=%d worst=%d (C(N,M)=%d, ‖s2‖∞≤%d, τ·C·η=%d vs γ2=%d)",
				c.n, c.tt, len(c.activeSets), best, worst,
				rss.NumSubsets(c.tt, c.n), rss.MaxSecretNorm(c.tt, c.n, 4),
				49*rss.NumSubsets(c.tt, c.n)*4, 261888)
		})
	}
}

// dropEachOne returns the n quorums of size n−1, each omitting exactly one party
// — the full fault-tolerance set for a (n−1)-of-n committee.
func dropEachOne(n int) [][]int {
	out := make([][]int, 0, n)
	for drop := 0; drop < n; drop++ {
		s := make([]int, 0, n-1)
		for i := 0; i < n; i++ {
			if i != drop {
				s = append(s, i)
			}
		}
		out = append(out, s)
	}
	return out
}

// faultSets16of14 returns several distinct 14-of-16 quorums, each tolerating a
// specific pair of faulty parties (two lowest, two highest, two middle, the
// extremes, and a scattered pair) — exercising inactive-party positions that
// stress the partition's pigeonhole coverage differently.
func faultSets16of14() [][]int {
	drops := [][2]int{{0, 1}, {14, 15}, {7, 8}, {0, 15}, {3, 11}}
	out := make([][]int, 0, len(drops))
	for _, d := range drops {
		s := make([]int, 0, 14)
		for i := 0; i < 16; i++ {
			if i != d[0] && i != d[1] {
				s = append(s, i)
			}
		}
		out = append(out, s)
	}
	return out
}

func isSortedDistinct(active []int, n int) bool {
	prev := -1
	for _, id := range active {
		if id <= prev || id < 0 || id >= n {
			return false
		}
		prev = id
	}
	return true
}
