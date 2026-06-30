// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// origin_auth_gate_test.go — GATE (RED MEDIUM, post-merge nit #1): origin
// authentication is SAFE BY DEFAULT. The aggregation surface no longer silently
// aggregates unauthenticated partials when the verifier is missing — a caller
// that FORGOT to wire it is refused FAIL-CLOSED (ErrOriginAuthRequired), so it
// cannot revert to the exclude-honest-victim footgun. The unauthenticated path
// is reachable ONLY by the EXPLICIT UnauthenticatedAggregation opt-out (test /
// trusted-channel). This is the same no-fail-open posture the nonce ledger has.
//
// Two faces, one gate:
//   - the free function AggregateBCC / AggregateBCCWithBlame, and
//   - the DistributedBCCSigner.Finalize / FinalizeWithBlame entrypoint.

import (
	"crypto/rand"
	"errors"
	"testing"
)

// GATE (free fn) — nil verifier REFUSES; explicit opt-out and a real verifier
// both aggregate to a FIPS-valid signature. Driven on real (bccRound-signed)
// partials over a boundary-clear nonce, so the success directions are
// deterministic.
func TestGATE_OriginAuth_FreeFn_DefaultRefuses(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("origin-auth-freefn"))
	msg := []byte("safe-by-default origin authentication")
	partials, agg, _, quorum, evalPoints := bccRound(t, f, msg, sid)
	nonceID := partials[0].NonceID

	// (1) DEFAULT (nil verifier) is REFUSED FAIL-CLOSED — both the blame surface
	//     and the back-compat wrapper.
	if _, _, _, err := AggregateBCCWithBlame(f.params, f.setup, evalPoints, quorum, 0, nil,
		nil, msg, agg.c, &agg.cHat, agg.w1, sid, nonceID, threshold, partials); !errors.Is(err, ErrOriginAuthRequired) {
		t.Fatalf("GATE FAILED: nil-verifier AggregateBCCWithBlame returned %v, want ErrOriginAuthRequired (must fail closed)", err)
	}
	if _, _, err := AggregateBCC(f.params, f.setup, evalPoints, quorum, 0, nil,
		nil, msg, agg.c, &agg.cHat, agg.w1, sid, nonceID, threshold, partials); !errors.Is(err, ErrOriginAuthRequired) {
		t.Fatalf("GATE FAILED: nil-verifier AggregateBCC returned %v, want ErrOriginAuthRequired", err)
	}

	// (2) EXPLICIT opt-out (UnauthenticatedAggregation) aggregates and yields a
	//     FIPS-valid signature — the deliberate trusted-channel path.
	_, certOptOut, _, err := AggregateBCCWithBlame(f.params, f.setup, evalPoints, quorum, 0, UnauthenticatedAggregation,
		nil, msg, agg.c, &agg.cHat, agg.w1, sid, nonceID, threshold, partials)
	if err != nil {
		t.Fatalf("explicit UnauthenticatedAggregation opt-out must aggregate, got %v", err)
	}
	if !fipsVerify(t, f.setup, msg, &certOptOut.Signature) {
		t.Fatalf("opt-out aggregate failed unmodified FIPS 204 verify")
	}

	// (3) A REAL verifier authenticates the (bccRound-signed) partials and yields a
	//     FIPS-valid signature too — the production path.
	_, certAuth, _, err := AggregateBCCWithBlame(f.params, f.setup, evalPoints, quorum, 0, f.idset,
		nil, msg, agg.c, &agg.cHat, agg.w1, sid, nonceID, threshold, partials)
	if err != nil {
		t.Fatalf("authenticated aggregation must succeed on signed partials, got %v", err)
	}
	if !fipsVerify(t, f.setup, msg, &certAuth.Signature) {
		t.Fatalf("authenticated aggregate failed unmodified FIPS 204 verify")
	}
	t.Logf("GATE PASS (origin-auth safe-by-default, free fn): nil verifier => ErrOriginAuthRequired (fail-closed); UnauthenticatedAggregation opt-out AND a real verifier both aggregate to a FIPS-valid signature")
}

// GATE (signer) — a DistributedBCCSigner that never called SetIdentity (idVerify
// == nil, the forgot-to-wire path) refuses Finalize / FinalizeWithBlame
// FAIL-CLOSED; the explicit opt-out SetIdentity(nil, UnauthenticatedAggregation)
// is the only lever that lifts the refusal.
func TestGATE_OriginAuth_Signer_DefaultRefuses(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	quorum, evalPoints, qshares := f.quorum(threshold)
	var sid [32]byte
	copy(sid[:], []byte("origin-auth-signer"))
	msg := []byte("signer fails closed without identity")
	var nonceID [32]byte
	nonceID[0] = 0x4d
	deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, threshold, nonceID, rand.Reader)
	if err != nil {
		t.Fatalf("nonce deal: %v", err)
	}

	// Drive a full-threshold ceremony with NO SetIdentity (the forgot-to-wire path).
	nodes := make([]*DistributedBCCSigner, threshold)
	partials := make([]Partial, 0, threshold)
	var aggR1 SignRound1
	for i := 0; i < threshold; i++ {
		nd, e := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, nil, msg, rand.Reader)
		if e != nil {
			t.Fatalf("signer %d: %v", i, e)
		}
		nodes[i] = nd
		if e := nd.SetNonceShare(nonceID, deal.YShares[quorum[i]]); e != nil {
			t.Fatalf("set nonce share %d: %v", i, e)
		}
		r1, e := nd.Round1(sid, nonceID, deal.Cert)
		if e != nil {
			t.Fatalf("round1 %d: %v", i, e)
		}
		if nd.IsAggregator() {
			aggR1 = r1
		}
		p, e := nd.Round2(r1, PartialInput{})
		if e != nil {
			t.Fatalf("round2 %d: %v", i, e)
		}
		partials = append(partials, p)
	}
	var agg *DistributedBCCSigner
	for _, nd := range nodes {
		if nd.IsAggregator() {
			agg = nd
		}
	}
	if agg == nil {
		t.Fatal("no aggregator")
	}

	// DEFAULT (no SetIdentity): both entrypoints refuse FAIL-CLOSED.
	if _, _, _, ferr := agg.FinalizeWithBlame(aggR1, partials); !errors.Is(ferr, ErrOriginAuthRequired) {
		t.Fatalf("GATE FAILED: default signer FinalizeWithBlame returned %v, want ErrOriginAuthRequired", ferr)
	}
	if _, _, ferr := agg.Finalize(aggR1, partials); !errors.Is(ferr, ErrOriginAuthRequired) {
		t.Fatalf("GATE FAILED: default signer Finalize returned %v, want ErrOriginAuthRequired", ferr)
	}

	// EXPLICIT opt-out lifts the refusal (the auth gate no longer fires). The FIPS
	// hint outcome is orthogonal here; assert only that the origin-auth refusal is
	// gone — the free-fn gate above proves the opt-out actually produces a valid sig.
	agg.SetIdentity(nil, UnauthenticatedAggregation)
	if _, _, _, ferr := agg.FinalizeWithBlame(aggR1, partials); errors.Is(ferr, ErrOriginAuthRequired) {
		t.Fatalf("GATE FAILED: explicit UnauthenticatedAggregation opt-out still refused with ErrOriginAuthRequired")
	}
	t.Logf("GATE PASS (origin-auth safe-by-default, signer): a signer with no SetIdentity refuses Finalize/FinalizeWithBlame FAIL-CLOSED (ErrOriginAuthRequired); SetIdentity(nil, UnauthenticatedAggregation) is the explicit lever that lifts it")
}

// Sentinel hygiene — the UnauthenticatedAggregation opt-out must NEVER be used as
// a real verifier (it has no key material); if mistaken for one it must fail LOUD
// (panic), never silently accept/drop. The gate branches on identity before any
// method call, so this path is unreachable in correct flow — assert it stays loud.
func TestGATE_OriginAuth_SentinelIsNotAVerifier(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("GATE FAILED: UnauthenticatedAggregation.VerifyAbortSignature did not panic — a sentinel must not silently act as a verifier")
		}
	}()
	_ = UnauthenticatedAggregation.VerifyAbortSignature(NodeID{}, nil, nil)
}
