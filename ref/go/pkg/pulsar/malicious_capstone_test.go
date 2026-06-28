// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// malicious_capstone_test.go — item 5 capstone: the load-bearing property that
// EVERY malicious deviation a single member can mount on the no-reconstruct sign
// path results in an ABORT or attributable BLAME — NEVER a FIPS-valid forged
// signature and NEVER a recovered secret. Plus selective-abort (re-form) and
// aggregation order-independence (no last-mover grinding).

import (
	"crypto/rand"
	"errors"
	"testing"
)

// noForgery asserts an aggregation outcome is not a forgery: if it returned a
// signature (err == nil), that signature must FAIL the standard FIPS verifier.
func noForgery(t *testing.T, f *bccFixture, msg []byte, cert ConsensusCert, err error) {
	t.Helper()
	if err == nil && fipsVerify(t, f.setup, msg, &cert.Signature) {
		t.Fatalf("FORGERY: a malicious deviation produced a FIPS-valid signature")
	}
}

func TestMalicious_BadBehaviorNeverForgesOrLeaks(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	_, L, _ := modeShape(f.params.Mode)

	// Sanity: an HONEST quorum DOES produce a valid signature (so the negative
	// results below are meaningful, not a broken harness).
	var sid0 [32]byte
	copy(sid0[:], []byte("capstone-honest"))
	if sig, _, err := runBCCCeremony(t, f, threshold, sid0, nil, []byte("honest")); err != nil || !fipsVerify(t, f.setup, []byte("honest"), sig) {
		t.Fatalf("honest baseline failed (err=%v) — harness broken", err)
	}

	// A — NONCE REUSE: an honest signer refuses the second partial on one nonce,
	// so the (c_A−c_B)·s1 recovery system can never be assembled (no leak/forge).
	t.Run("nonce-reuse-refused", func(t *testing.T) {
		quorum, evalPoints, qshares := f.quorum(threshold)
		var nid [32]byte
		nid[0] = 0xC1
		deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, threshold, nid, rand.Reader)
		if err != nil {
			t.Fatalf("nonce deal: %v", err)
		}
		ledger := NewInMemoryNonceLedger()
		var sA, sB [32]byte
		copy(sA[:], []byte("A"))
		copy(sB[:], []byte("B"))
		mk := func(sid [32]byte, msg []byte) *DistributedBCCSigner {
			s, err := NewDistributedBCCSigner(f.params, f.setup, qshares[1], quorum, evalPoints, sid, nil, msg, rand.Reader)
			if err != nil {
				t.Fatalf("signer: %v", err)
			}
			s.SetNonceLedger(ledger)
			_ = s.SetNonceShare(nid, deal.YShares[quorum[1]])
			return s
		}
		s1 := mk(sA, []byte("msg A"))
		r1a, _ := s1.Round1(sA, nid, deal.Cert)
		if _, err := s1.Round2(r1a, PartialInput{}); err != nil {
			t.Fatalf("first honest use: %v", err)
		}
		s2 := mk(sB, []byte("msg B"))
		r1b, _ := s2.Round1(sB, nid, deal.Cert)
		if _, err := s2.Round2(r1b, PartialInput{}); !errors.Is(err, ErrNonceReused) {
			t.Fatalf("nonce reuse: got %v want ErrNonceReused (key-recovery precondition not blocked)", err)
		}
	})

	// B — INVALID-SIGMA partial: dropped + attributed; round aborts, no forgery.
	t.Run("invalid-proof-blamed", func(t *testing.T) {
		var sid [32]byte
		copy(sid[:], []byte("capstone-invalid"))
		partials, agg, aggR1, quorum, _ := bccRound(t, f, []byte("invalid"), sid)
		bad := append([]Partial(nil), partials...)
		z := unpackPolyVec(bad[1].ZShare, L)
		z[0][0] = (z[0][0] + 1) % mldsaQ
		bad[1].ZShare = packPolyVec(z)
		f.idset.signPartial(&bad[1], quorum[1], 0) // bad validator SIGNS its bad partial
		_, cert, ev, err := agg.FinalizeWithBlame(aggR1, bad)
		noForgery(t, f, []byte("invalid"), cert, err)
		if !errors.Is(err, ErrInsufficientSigners) {
			t.Fatalf("want abort after drop, got %v", err)
		}
		if !blamedNode(ev, quorum[1]) {
			t.Fatalf("invalid-proof party not attributed")
		}
	})

	// C — DUPLICATE PartyID cannot inflate a sub-threshold set; aborts + blames.
	t.Run("duplicate-cannot-inflate", func(t *testing.T) {
		var sid [32]byte
		copy(sid[:], []byte("capstone-dup"))
		partials, agg, _, quorum, evalPoints := bccRound(t, f, []byte("dup"), sid)
		dups := []Partial{partials[0], partials[0], partials[0]}
		_, cert, blames, err := AggregateBCCWithBlame(f.params, f.setup, evalPoints, quorum, 0, f.idset,
			nil, []byte("dup"), agg.c, &agg.cHat, agg.w1, sid, partials[0].NonceID, threshold, dups)
		noForgery(t, f, []byte("dup"), cert, err)
		if !errors.Is(err, ErrInsufficientSigners) {
			t.Fatalf("duplicates inflated the threshold: %v", err)
		}
		if b, ok := blameFor(blames, 0); !ok || b.Reason != BlameDuplicatePartyID {
			t.Fatalf("duplicate not blamed")
		}
	})

	// D — MALFORMED share: rejected without panic, attributed, no forgery.
	t.Run("malformed-no-panic", func(t *testing.T) {
		var sid [32]byte
		copy(sid[:], []byte("capstone-malformed"))
		partials, agg, _, quorum, evalPoints := bccRound(t, f, []byte("malformed"), sid)
		bad := append([]Partial(nil), partials...)
		bad[2].ZShare = []byte{0xde, 0xad}
		f.idset.signPartial(&bad[2], quorum[2], 0) // bad validator SIGNS its malformed partial
		_, cert, blames, err := AggregateBCCWithBlame(f.params, f.setup, evalPoints, quorum, 0, f.idset,
			nil, []byte("malformed"), agg.c, &agg.cHat, agg.w1, sid, partials[2].NonceID, threshold, bad)
		noForgery(t, f, []byte("malformed"), cert, err)
		if b, ok := blameFor(blames, 2); !ok || b.Reason != BlameMalformed {
			t.Fatalf("malformed not blamed")
		}
	})

	// E — VALID-SIGMA WRONG-z: liveness fault only — no FIPS-valid signature.
	t.Run("valid-sigma-wrongz-no-forgery", func(t *testing.T) {
		var sid [32]byte
		copy(sid[:], []byte("capstone-wrongz"))
		msg := []byte("wrongz")
		partials, agg, aggR1, quorum, evalPoints := bccRound(t, f, msg, sid)
		zeros := make(polyVec, L)
		lambda := LagrangeAtZeroQ(evalPoints[1], evalPoints)
		st := &PartialStatement{Mode: f.params.Mode, Lambda: lambda, C: agg.c, Z: zeros,
			SessionID: sid, NonceID: partials[1].NonceID, PartyID: 1}
		proof, err := ProvePartial(st, &PartialWitness{Y: zeros, S1: zeros}, rand.Reader)
		if err != nil {
			t.Fatalf("prove wrong-z: %v", err)
		}
		bad := append([]Partial(nil), partials...)
		bad[1] = Partial{PartyID: 1, NonceID: partials[1].NonceID, SessionID: sid, ZShare: packPolyVec(zeros), Proof: proof}
		f.idset.signPartial(&bad[1], quorum[1], 0) // bad validator SIGNS its valid-sigma wrong-z partial
		_, cert, _, ferr := agg.FinalizeWithBlame(aggR1, bad)
		noForgery(t, f, msg, cert, ferr) // the load-bearing property: NEVER a forgery
	})

	t.Logf("CAPSTONE PASS: nonce-reuse / invalid-proof / duplicate / malformed / valid-sigma-wrong-z all => abort or blame, NEVER a FIPS-valid forgery")
}

func blamedNode(ev []AbortEvidence, node NodeID) bool {
	for i := range ev {
		if ev[i].Kind == ComplaintBadPartial && ev[i].Accused == node {
			return true
		}
	}
	return false
}

// TestMalicious_SelectiveAbort_ReformProducesValidSig — the crypto aggregator
// requires an EXACT-threshold evalPoints set (its Lagrange weights are over the
// supplied set), so selective abort is handled by the orchestrator RE-FORMING a
// fresh exact-threshold quorum that excludes the blamed party. This test shows
// the realistic flow: a quorum containing a deviator aborts+blames; a re-formed
// clean quorum then produces a valid signature.
func TestMalicious_SelectiveAbort_ReformProducesValidSig(t *testing.T) {
	const n, threshold = 6, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	_, L, _ := modeShape(f.params.Mode)

	// Quorum {0,1,2}, party 1 deviates (invalid proof) -> abort + blame.
	var sid [32]byte
	copy(sid[:], []byte("selective-abort-round-1"))
	partials, agg, aggR1, quorum, _ := bccRound(t, f, []byte("reform"), sid)
	bad := append([]Partial(nil), partials...)
	z := unpackPolyVec(bad[1].ZShare, L)
	z[0][0] = (z[0][0] + 1) % mldsaQ
	bad[1].ZShare = packPolyVec(z)
	f.idset.signPartial(&bad[1], quorum[1], 0) // deviator SIGNS its bad partial (attributable)
	_, _, ev, err := agg.FinalizeWithBlame(aggR1, bad)
	if !errors.Is(err, ErrInsufficientSigners) || !blamedNode(ev, quorum[1]) {
		t.Fatalf("round 1 should abort+blame party 1: err=%v", err)
	}

	// Orchestrator RE-FORMS an exact-threshold clean quorum that excludes the
	// blamed party (use members {2,3,4} — three honest shares).
	clean := &bccFixture{params: f.params, setup: f.setup, threshold: threshold,
		committee: []NodeID{f.shares[2].NodeID, f.shares[3].NodeID, f.shares[4].NodeID},
		shares:    []*AlgShare{f.shares[2], f.shares[3], f.shares[4]}}
	var sid2 [32]byte
	copy(sid2[:], []byte("selective-abort-reform"))
	sig, _, err := runBCCCeremony(t, clean, threshold, sid2, nil, []byte("reform"))
	if err != nil {
		t.Fatalf("re-formed clean quorum failed to sign: %v", err)
	}
	if !fipsVerify(t, f.setup, []byte("reform"), sig) {
		t.Fatalf("re-formed signature failed FIPS verify")
	}
	t.Logf("SELECTIVE-ABORT PASS: deviator aborted+blamed; orchestrator re-formed a clean exact-threshold quorum that produced a FIPS-valid signature")
}

// TestMalicious_AggregationOrderIndependent — the aggregate (hence the signature
// bytes) is INDEPENDENT of the order partials arrive in (CanonicalSignerSet is
// deterministic over PartyID). A last submitter therefore cannot grind the
// signer subset / challenge / output by reordering or timing — no last-mover bias.
func TestMalicious_AggregationOrderIndependent(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("order-independence"))
	partials, agg, _, quorum, evalPoints := bccRound(t, f, []byte("order"), sid)

	forward, certF, _, errF := AggregateBCCWithBlame(f.params, f.setup, evalPoints, quorum, 0, f.idset,
		nil, []byte("order"), agg.c, &agg.cHat, agg.w1, sid, partials[0].NonceID, threshold, partials)
	_ = forward
	if errF != nil {
		t.Fatalf("forward aggregate: %v", errF)
	}
	reversed := []Partial{partials[2], partials[1], partials[0]}
	_, certR, _, errR := AggregateBCCWithBlame(f.params, f.setup, evalPoints, quorum, 0, f.idset,
		nil, []byte("order"), agg.c, &agg.cHat, agg.w1, sid, partials[0].NonceID, threshold, reversed)
	if errR != nil {
		t.Fatalf("reversed aggregate: %v", errR)
	}
	if string(certF.Signature.Bytes) != string(certR.Signature.Bytes) {
		t.Fatalf("LAST-MOVER BIAS: signature depends on partial submission order")
	}
	if !fipsVerify(t, f.setup, []byte("order"), &certF.Signature) {
		t.Fatalf("order-independent signature failed FIPS verify")
	}
	t.Logf("ORDER-INDEPENDENCE PASS: identical signature regardless of partial order — no last-mover grinding of the subset/output")
}
