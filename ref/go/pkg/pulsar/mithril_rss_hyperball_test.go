// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/luxfi/dkg/rss"
)

// mithril_rss_hyperball_test.go — GATE 5 (no reconstruction) and GATE 6
// (fail-closed) for the Mithril 3-round hyperball no-reconstruct signer.
//
// GATE 5: a hyperball signature verifies byte-for-byte under unmodified
// cloudflare/circl mldsa65.Verify at n=8,t=8 and across the N≤6 committees, AND
// the signing path forms NO full s1/s2/y/w0/sk in any party (structural + source
// + transcript scans), and never calls ReconstructKeyMaterial.
//
// GATE 6: sub-threshold signing fails closed; a malformed/biased partial fails
// closed and is blamed; nonce reuse is structurally prevented (and demonstrably
// catastrophic if violated); the FindHint + self-verify release gate rejects any
// biased z_i.

// ---------------------------------------------------------------------------
// GATE 5 (a): stock circl round-trip, no reconstruction
// ---------------------------------------------------------------------------

// TestHyperballStockCirclVerify is the headline no-reconstruct proof: the
// dealerless RSS ML-DSA-65 key signs via the 3-round hyperball protocol (no key
// reconstruction) and the signature verifies under unmodified circl
// mldsa65.Verify, for n=8,t=8 and every N≤6 committee. Tamper / wrong-message /
// wrong-context are rejected (verifier non-vacuous).
func TestHyperballStockCirclVerify(t *testing.T) {
	committees := [][2]int{
		{2, 2}, {2, 3}, {3, 3}, {2, 4}, {3, 4}, {4, 4},
		{2, 5}, {3, 5}, {4, 5}, {5, 5},
		{2, 6}, {3, 6}, {4, 6}, {5, 6}, {6, 6},
		{8, 8}, // T=N singleton beyond the partition table
	}
	msg := []byte("Pulsar Mithril hyperball — no-reconstruct ML-DSA-65 under stock circl")
	ctx := []byte("quasar-pulsar-leg")
	for _, tn := range committees {
		tt, n := tn[0], tn[1]
		t.Run(fmt.Sprintf("T%d_N%d", tt, n), func(t *testing.T) {
			mk, err := MithrilRSSKeygen(ModeP65, tt, n, mithrilSeeds(n))
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			active := canonicalActive(tt)
			rng := newBCCDeterministicRNG(fmt.Sprintf("PULSAR/HYPERBALL/%d-%d", tt, n))
			sig, tr, err := mk.SignHyperball(active, msg, ctx, rng, 64)
			if err != nil {
				t.Fatalf("(T=%d,N=%d) SignHyperball: %v", tt, n, err)
			}

			var pkC mldsa65.PublicKey
			if err := pkC.UnmarshalBinary(mk.pub); err != nil {
				t.Fatalf("circl unmarshal pk: %v", err)
			}
			if !mldsa65.Verify(&pkC, msg, ctx, sig.Bytes) {
				t.Fatalf("(T=%d,N=%d): STOCK circl mldsa65.Verify REJECTED the no-reconstruct hyperball signature", tt, n)
			}
			// Non-vacuous: tamper, wrong message, wrong context all rejected.
			tampered := append([]byte(nil), sig.Bytes...)
			tampered[len(tampered)/2] ^= 0x01
			if mldsa65.Verify(&pkC, msg, ctx, tampered) {
				t.Fatal("circl accepted a tampered signature — verifier vacuous")
			}
			if mldsa65.Verify(&pkC, []byte("a different message"), ctx, sig.Bytes) {
				t.Fatal("circl accepted signature under wrong message — binding broken")
			}
			if mldsa65.Verify(&pkC, msg, []byte("wrong-ctx"), sig.Bytes) {
				t.Fatal("circl accepted signature under wrong context — ctx binding broken")
			}
			hp, _ := deriveHyperballParams(ModeP65, tt, n)
			t.Logf("(T=%d,N=%d) m=%d K=%d rounds=%d slot=%d r1=%.0f Δ=%.0f: stock-circl verified",
				tt, n, maxSubsetsPerParty(tt, n), hp.kReps, tr.Rounds, tr.WinningSlot, hp.r1, hp.r1-hp.r)
		})
	}
}

// ---------------------------------------------------------------------------
// GATE 5 (b): structural / source / transcript no-reconstruct scan
// ---------------------------------------------------------------------------

// TestHyperballNoReconstructStructural proves the no-reconstruct property three
// ways: (1) the hyperball source never calls ReconstructKeyMaterial; (2) the
// round-message types carry no secret material — the public transcript contains
// none of any party's share s1_(j), nor the full reconstructed s1/s2; (3) the
// per-party object holds only its own share (any T−1 parties' shares miss at
// least one subset, so no party set below T even *could* reconstruct).
func TestHyperballNoReconstructStructural(t *testing.T) {
	// (1) AST scan: the hyperball signing path must contain NO call expression
	// invoking ReconstructKeyMaterial. (Parsing the AST ignores the doc comment
	// that names it for contrast — only real CallExprs count.)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mithril_rss_hyperball.go", nil, 0)
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ReconstructKeyMaterial" {
			t.Fatal("mithril_rss_hyperball.go CALLS ReconstructKeyMaterial — NOT no-reconstruct")
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "ReconstructKeyMaterial" {
			t.Fatal("mithril_rss_hyperball.go CALLS ReconstructKeyMaterial — NOT no-reconstruct")
		}
		return true
	})
	// Defensive byte scan: the source must not pack a party's secret share or
	// mask onto any wire buffer. The only packPolyVec arguments in the round path
	// are w, z, w1, tjS1 (all public); s1Share / yInt must never be serialized.
	src, err := os.ReadFile("mithril_rss_hyperball.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	for _, forbidden := range []string{"packPolyVec(p.s1Share", "packPolyVec(s1Share", "packPolyVec(p.yInt", "packPolyVec(yInt"} {
		if bytes.Contains(src, []byte(forbidden)) {
			t.Fatalf("source serializes secret material: %q", forbidden)
		}
	}

	// (2) Runtime transcript oracle: sign, then assert the PUBLIC transcript
	// bytes contain neither any party's share nor the full reconstructed secret.
	tt, n := 8, 8
	mk, err := MithrilRSSKeygen(ModeP65, tt, n, mithrilSeeds(n))
	if err != nil {
		t.Fatal(err)
	}
	active := canonicalActive(tt)
	msg := []byte("no-reconstruct transcript oracle")
	rng := newBCCDeterministicRNG("PULSAR/HYPERBALL/no-leak")
	sig, tr, err := mk.SignHyperball(active, msg, nil, rng, 64)
	if err != nil {
		t.Fatal(err)
	}
	pub := tr.publicBytes()

	// Each active party's share s1_(j) (packed) must NOT appear in the transcript.
	part, _ := rss.RSSRecover(active, tt, n)
	for j, id := range active {
		share, err := mk.partyShareS1(id, part[j])
		if err != nil {
			t.Fatal(err)
		}
		// Normalize for a faithful byte comparison against what a leak would emit.
		ns := make(polyVec, len(share))
		for i := range share {
			ns[i] = share[i]
			ns[i].reduceLe2Q()
			ns[i].normalize()
		}
		if bytes.Contains(pub, packPolyVec(ns)) {
			t.Fatalf("party %d share s1_(j) bytes appear in the public transcript — LEAK", id)
		}
	}
	// The full reconstructed s1 and s2 must NOT appear either.
	km, _ := mk.ReconstructKeyMaterial(active)
	for _, secret := range []polyVec{km.s1, km.s2} {
		ns := make(polyVec, len(secret))
		for i := range secret {
			ns[i] = secret[i]
			ns[i].normalize()
		}
		if bytes.Contains(pub, packPolyVec(ns)) {
			t.Fatal("full reconstructed s1/s2 bytes appear in the public transcript — LEAK")
		}
	}

	// Sanity: the signature is real (stock circl accepts it) — the scan above is
	// not vacuously passing on a degenerate transcript.
	var pkC mldsa65.PublicKey
	_ = pkC.UnmarshalBinary(mk.pub)
	if !mldsa65.Verify(&pkC, msg, nil, sig.Bytes) {
		t.Fatal("transcript-oracle signature does not verify — scan would be vacuous")
	}

	// (3) Below-threshold parties cannot even cover all subsets (proven for the
	// full viability range in TestMithrilRSSDealerless; re-assert for this set).
	full := len(rss.EnumerateSubsets(tt, n))
	for _, coalition := range combos(n, tt-1) {
		covered := map[uint64]bool{}
		for _, id := range coalition {
			for m := range mk.holdings[id] {
				covered[m] = true
			}
		}
		if len(covered) == full {
			t.Fatalf("T-1 coalition %v covers all subsets", coalition)
		}
	}
}
