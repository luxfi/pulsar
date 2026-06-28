// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/luxfi/dkg/rss"
)

func mithrilSeeds(n int) [][]byte {
	ps := make([][]byte, n)
	for i := range ps {
		s := make([]byte, 32)
		for j := range s {
			s[j] = byte(31*i + 7*j + 5)
		}
		ps[i] = s
	}
	return ps
}

func canonicalActive(t int) []int {
	a := make([]int, t)
	for i := range a {
		a[i] = i
	}
	return a
}

// TestMithrilRSSStockCirclVerify is the headline wall-beaten proof: a DEALERLESS
// RSS-generated ML-DSA-65 key (no trusted dealer) signs under the BCC signer and
// the signature verifies BYTE-FOR-BYTE under unmodified cloudflare/circl
// mldsa65.Verify. Tamper and wrong-message are rejected (verifier non-vacuous).
func TestMithrilRSSStockCirclVerify(t *testing.T) {
	// EVERY admissible Mithril committee (all 15 pairs, 2 ≤ T ≤ N ≤ 6). All
	// verify under stock circl within a small attempt budget — the dealerless
	// key is stock-FIPS-204-signable across the entire viability range.
	committees := [][2]int{
		{2, 2}, {2, 3}, {3, 3}, {2, 4}, {3, 4}, {4, 4},
		{2, 5}, {3, 5}, {4, 5}, {5, 5},
		{2, 6}, {3, 6}, {4, 6}, {5, 6}, {6, 6},
	}
	msg := []byte("Pulsar dealerless RSS (Mithril) — stock circl ML-DSA-65 round-trip")
	var ctx []byte
	for _, tn := range committees {
		tt, n := tn[0], tn[1]
		t.Run(fmt.Sprintf("T%d_N%d", tt, n), func(t *testing.T) {
			mk, err := MithrilRSSKeygen(ModeP65, tt, n, mithrilSeeds(n))
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			km, err := mk.ReconstructKeyMaterial(canonicalActive(tt))
			if err != nil {
				t.Fatalf("reconstruct: %v", err)
			}
			rng := newBCCDeterministicRNG(fmt.Sprintf("PULSAR/MITHRIL/%d-%d", tt, n))
			sig, tr, err := bccSign(km, ModeP65, msg, ctx, rng, 1<<20)
			if err != nil {
				t.Fatalf("(T=%d,N=%d) bccSign: %v", tt, n, err)
			}

			var pkC mldsa65.PublicKey
			if err := pkC.UnmarshalBinary(mk.pub); err != nil {
				t.Fatalf("circl unmarshal pk: %v", err)
			}
			if !mldsa65.Verify(&pkC, msg, ctx, sig) {
				t.Fatalf("(T=%d,N=%d): STOCK circl mldsa65.Verify REJECTED the dealerless RSS signature", tt, n)
			}
			// Non-vacuous: tamper and wrong message rejected.
			tampered := append([]byte(nil), sig...)
			tampered[len(tampered)/2] ^= 0x01
			if mldsa65.Verify(&pkC, msg, ctx, tampered) {
				t.Fatal("circl accepted a tampered signature — verifier vacuous")
			}
			if mldsa65.Verify(&pkC, []byte("a different message"), ctx, sig) {
				t.Fatal("circl accepted signature under wrong message — binding broken")
			}
			t.Logf("(T=%d,N=%d) C(N,M)=%d ‖s2‖∞≤%d: circl-verified in %d attempt(s)",
				tt, n, rss.NumSubsets(tt, n), rss.MaxSecretNorm(tt, n, 4), tr.attempts)
		})
	}
}

// TestMithrilRSSDealerless proves the structural dealerless guarantee at the
// pulsar layer: no single party holds all subsets, and no (T−1)-coalition
// covers all subsets (so fewer than T cannot reconstruct the key).
func TestMithrilRSSDealerless(t *testing.T) {
	for n := 2; n <= rss.MaxParties; n++ {
		for tt := 2; tt <= n; tt++ {
			mk, err := MithrilRSSKeygen(ModeP65, tt, n, mithrilSeeds(n))
			if err != nil {
				t.Fatalf("(T=%d,N=%d) keygen: %v", tt, n, err)
			}
			full := len(rss.EnumerateSubsets(tt, n))
			for id := 0; id < n; id++ {
				if len(mk.holdings[id]) == full {
					t.Fatalf("(T=%d,N=%d): party %d holds ALL subsets — not dealerless", tt, n, id)
				}
			}
			for _, coalition := range combos(n, tt-1) {
				covered := map[uint64]bool{}
				for _, id := range coalition {
					for m := range mk.holdings[id] {
						covered[m] = true
					}
				}
				if len(covered) == full {
					t.Fatalf("(T=%d,N=%d): T-1 coalition %v covers all subsets — threshold broken", tt, n, coalition)
				}
			}
		}
	}
}

// TestMithrilRSSAnyQuorumSameKey proves any T-quorum reconstructs the identical
// key material, so any qualifying signer set produces a signature under the same
// public key.
func TestMithrilRSSAnyQuorumSameKey(t *testing.T) {
	mk, err := MithrilRSSKeygen(ModeP65, 3, 5, mithrilSeeds(5))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := mk.ReconstructKeyMaterial([]int{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, active := range combos(5, 3) {
		km, err := mk.ReconstructKeyMaterial(active)
		if err != nil {
			t.Fatalf("active=%v: %v", active, err)
		}
		for i := range km.s1 {
			if km.s1[i] != ref.s1[i] {
				t.Fatalf("quorum %v reconstructed a different s1", active)
			}
		}
		for i := range km.s2 {
			if km.s2[i] != ref.s2[i] {
				t.Fatalf("quorum %v reconstructed a different s2", active)
			}
		}
	}
}

// TestMithrilRSSSignAPI exercises the production-facing dealerless FIPS-leg
// signer: MithrilKey.Sign reconstructs from a quorum, BCC-signs, fail-closed
// self-verifies, and the result verifies under stock circl mldsa65.Verify.
func TestMithrilRSSSignAPI(t *testing.T) {
	mk, err := MithrilRSSKeygen(ModeP65, 3, 5, mithrilSeeds(5))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("dealerless RSS FIPS leg — Sign API")
	ctx := []byte("quasar-pulsar-leg")
	// Two different qualifying quorums both sign valid signatures under the
	// same public key.
	for _, active := range [][]int{{0, 1, 2}, {2, 3, 4}, {0, 2, 4}} {
		rng := newBCCDeterministicRNG(fmt.Sprintf("sign/%v", active))
		sig, err := mk.Sign(active, msg, ctx, rng, 1<<20)
		if err != nil {
			t.Fatalf("quorum %v Sign: %v", active, err)
		}
		var pkC mldsa65.PublicKey
		if err := pkC.UnmarshalBinary(mk.pub); err != nil {
			t.Fatal(err)
		}
		if !mldsa65.Verify(&pkC, msg, ctx, sig.Bytes) {
			t.Fatalf("quorum %v: stock circl rejected the Sign output", active)
		}
	}
}

func TestMithrilRSSRejectsBadCommittee(t *testing.T) {
	for _, tn := range [][2]int{{1, 2}, {3, 2}, {2, 7}} {
		if _, err := MithrilRSSKeygen(ModeP65, tn[0], tn[1], mithrilSeeds(maxI(tn[1], 7))); err == nil {
			t.Fatalf("admitted non-viable committee (T=%d,N=%d)", tn[0], tn[1])
		}
	}
}

func combos(n, k int) [][]int {
	if k <= 0 {
		return [][]int{{}}
	}
	var out [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(0, nil)
	return out
}

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}
