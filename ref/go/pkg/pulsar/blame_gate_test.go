// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// blame_gate_test.go — GATE B (RED MEDIUM: identifiable abort). A deviating
// partial must be ATTRIBUTED to its PartyID (blame), never an anonymous DoS,
// and duplicate PartyIDs must be rejected.
//
// Implemented + gated here (sound, complete):
//   - duplicate PartyID -> BlameDuplicatePartyID; duplicates can NOT inflate a
//     sub-threshold set to threshold.
//   - invalid-sigma partial -> BlameProofInvalid attributed to the exact PartyID
//     and elevated to a signed-complaint AbortEvidence.
//   - malformed ZShare -> BlameMalformed (no panic).
//
// FLAGGED RESIDUAL (share_commit.go, BDLOP): a VALID-sigma WRONG-z partial is
// NOT yet attributed; the test asserts the honest current assurance — it is a
// liveness fault that produces NO valid FIPS signature (never a forgery/leak).

import (
	"crypto/rand"
	"errors"
	"testing"
)

// bccRound drives a fixture's quorum through SetNonceShare+Round1+Round2 and
// returns the honest partials, the aggregator node, and its bound round1.
func bccRound(t *testing.T, f *bccFixture, msg []byte, sid [32]byte) (partials []Partial, agg *DistributedBCCSigner, aggR1 SignRound1, quorum []NodeID, evalPoints []uint32) {
	t.Helper()
	quorum, evalPoints, qshares := f.quorum(f.threshold)
	var nonceID [32]byte
	nonceID[0] = 0x7e
	deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, f.threshold, nonceID, rand.Reader)
	if err != nil {
		t.Fatalf("nonce deal: %v", err)
	}
	nodes := make([]*DistributedBCCSigner, f.threshold)
	partials = make([]Partial, 0, f.threshold)
	for i := 0; i < f.threshold; i++ {
		nd, err := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, nil, msg, rand.Reader)
		if err != nil {
			t.Fatalf("signer %d: %v", i, err)
		}
		// Wire the identity layer so partials are authenticated and the aggregator
		// can attribute blame soundly (RED MEDIUM). Producer = this node's key;
		// verifier = the shared per-validator set.
		nd.SetIdentity(f.idset.signerFor(quorum[i]), f.idset)
		nodes[i] = nd
		if err := nd.SetNonceShare(nonceID, deal.YShares[quorum[i]]); err != nil {
			t.Fatalf("set nonce share %d: %v", i, err)
		}
		r1, err := nd.Round1(sid, nonceID, deal.Cert)
		if err != nil {
			t.Fatalf("round1 %d: %v", i, err)
		}
		if nd.IsAggregator() {
			aggR1 = r1
			agg = nd
		}
		p, err := nd.Round2(r1, PartialInput{})
		if err != nil {
			t.Fatalf("round2 %d: %v", i, err)
		}
		partials = append(partials, p)
	}
	if agg == nil {
		t.Fatal("no aggregator")
	}
	return partials, agg, aggR1, quorum, evalPoints
}

func blameFor(blames []PartialBlame, party uint32) (PartialBlame, bool) {
	for _, b := range blames {
		if b.PartyID == party {
			return b, true
		}
	}
	return PartialBlame{}, false
}

// GATE B.1 — duplicate PartyID is attributed and cannot inflate the threshold.
func TestGATE_B_DuplicatePartyID(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("gate-b-duplicate"))
	partials, agg, aggR1, _, _ := bccRound(t, f, []byte("dup test"), sid)

	// (a) honest + one DUPLICATE of party 1 (a non-aggregator, so the
	//     aggregator's evidence is not self-accusation): round still succeeds
	//     (the dup is dropped) but the duplicate is BLAMED + attributed.
	withDup := append(append([]Partial(nil), partials...), partials[1])
	_, cert, ev, err := agg.FinalizeWithBlame(aggR1, withDup)
	if err != nil {
		t.Fatalf("round with one extra duplicate should still finalize: %v", err)
	}
	if !fipsVerify(t, f.setup, []byte("dup test"), &cert.Signature) {
		t.Fatalf("signature with a dropped duplicate failed FIPS verify")
	}
	foundDup := false
	for i := range ev {
		e := ev[i]
		if e.Kind == ComplaintBadPartial && e.Accused == f.shares[1].NodeID {
			if vErr := ValidateAbortEvidence(&e); vErr != nil {
				t.Fatalf("duplicate AbortEvidence malformed: %v", vErr)
			}
			foundDup = true
		}
	}
	if !foundDup {
		t.Fatalf("GATE B FAILED: duplicate PartyID 1 was not attributed (anonymous DoS)")
	}

	// (b) duplicates of ONE party can NOT reach threshold: t copies of party 0
	//     => 1 distinct signer => ErrInsufficientSigners + every extra blamed.
	onlyDups := []Partial{partials[0], partials[0], partials[0]}
	_, _, blames, err := AggregateBCCWithBlame(f.params, f.setup,
		[]uint32{f.shares[0].EvalPoint, f.shares[1].EvalPoint, f.shares[2].EvalPoint},
		[]NodeID{f.shares[0].NodeID, f.shares[1].NodeID, f.shares[2].NodeID}, 0, f.idset,
		nil, []byte("dup test"), agg.c, &agg.cHat, agg.w1, sid, partials[0].NonceID, threshold, onlyDups)
	if !errors.Is(err, ErrInsufficientSigners) {
		t.Fatalf("GATE B FAILED: %d duplicates of one party produced err=%v, want ErrInsufficientSigners (duplicates inflated the threshold!)", len(onlyDups), err)
	}
	if b, ok := blameFor(blames, 0); !ok || b.Reason != BlameDuplicatePartyID {
		t.Fatalf("GATE B FAILED: duplicate copies not blamed BlameDuplicatePartyID (got %+v)", blames)
	}
	t.Logf("GATE B.1 PASS: duplicate PartyID attributed (BlameDuplicatePartyID) and cannot inflate a sub-threshold set")
}

// GATE B.2 — an invalid-sigma partial is attributed to the exact PartyID and
// elevated to a signed-complaint AbortEvidence (not an anonymous round death).
func TestGATE_B_InvalidProofAttributed(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("gate-b-invalid-proof"))
	partials, agg, aggR1, quorum, _ := bccRound(t, f, []byte("invalid proof test"), sid)

	const badParty = 1
	// Tamper party 1's z WITHOUT updating its proof => sigma equation breaks.
	// The malicious validator SIGNS the bad partial (authenticated misbehavior),
	// so it passes origin-auth and is attributed BlameProofInvalid — vs a
	// transport-tampered partial (stale sig) which would be dropped unattributed.
	tampered := append([]Partial(nil), partials...)
	z := unpackPolyVec(tampered[badParty].ZShare, mldsaL(f.params.Mode))
	z[0][0] = (z[0][0] + 1) % mldsaQ
	tampered[badParty].ZShare = packPolyVec(z)
	f.idset.signPartial(&tampered[badParty], quorum[badParty], 0)

	_, _, ev, err := agg.FinalizeWithBlame(aggR1, tampered)
	if !errors.Is(err, ErrInsufficientSigners) {
		t.Fatalf("dropping the invalid partial should leave t-1 valid => ErrInsufficientSigners, got %v", err)
	}
	var got *AbortEvidence
	for i := range ev {
		if ev[i].Kind == ComplaintBadPartial && ev[i].Accused == quorum[badParty] {
			got = &ev[i]
		}
	}
	if got == nil {
		t.Fatalf("GATE B FAILED: invalid-proof partial from party %d not attributed", badParty)
	}
	aggID := agg.NodeID()
	if got.Accuser != aggID {
		t.Fatalf("blame accuser %x, want aggregator %x", got.Accuser[:4], aggID[:4])
	}
	if vErr := ValidateAbortEvidence(got); vErr != nil {
		t.Fatalf("attributed AbortEvidence malformed: %v", vErr)
	}
	// Confirm the raw reason is proof-invalid.
	_, _, blames, _ := AggregateBCCWithBlame(f.params, f.setup, agg.evalPoints, quorum, 0, f.idset,
		nil, []byte("invalid proof test"), agg.c, &agg.cHat, agg.w1, sid, partials[badParty].NonceID, threshold, tampered)
	if b, ok := blameFor(blames, badParty); !ok || b.Reason != BlameProofInvalid {
		t.Fatalf("GATE B FAILED: party %d not blamed BlameProofInvalid (got %+v)", badParty, blames)
	}
	t.Logf("GATE B.2 PASS: invalid-sigma partial attributed to PartyID %d (NodeID %x) as a signed AbortEvidence", badParty, quorum[badParty][:4])
}

// GATE B.3 — a malformed (truncated) ZShare is rejected WITHOUT panicking and
// attributed BlameMalformed.
func TestGATE_B_MalformedShareNoPanic(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("gate-b-malformed"))
	partials, agg, _, quorum, _ := bccRound(t, f, []byte("malformed test"), sid)

	const badParty = 2
	mangled := append([]Partial(nil), partials...)
	mangled[badParty].ZShare = []byte{0x00, 0x01} // truncated — would panic unpackPolyVec
	// Malicious validator SIGNS the malformed partial so it passes origin-auth
	// and is attributed BlameMalformed (not dropped as transport corruption).
	f.idset.signPartial(&mangled[badParty], quorum[badParty], 0)

	_, _, blames, err := AggregateBCCWithBlame(f.params, f.setup, agg.evalPoints, quorum, 0, f.idset,
		nil, []byte("malformed test"), agg.c, &agg.cHat, agg.w1, sid, partials[badParty].NonceID, threshold, mangled)
	if !errors.Is(err, ErrInsufficientSigners) {
		t.Fatalf("malformed share should drop to t-1 => ErrInsufficientSigners, got %v", err)
	}
	if b, ok := blameFor(blames, badParty); !ok || b.Reason != BlameMalformed {
		t.Fatalf("GATE B FAILED: malformed share not blamed BlameMalformed (got %+v)", blames)
	}
	t.Logf("GATE B.3 PASS: malformed ZShare rejected without panic and attributed BlameMalformed")
}

// GATE B.4 — HONEST RESIDUAL: a VALID-sigma WRONG-z partial is bounded to a
// liveness fault (produces NO valid FIPS signature — never a forgery/leak), but
// is NOT yet individually attributed. This is the BDLOP share-commitment
// residual (share_commit.go / ErrIdentifiableAbortResidual).
func TestGATE_B_ValidSigmaWrongZ_ResidualNoForgery(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("gate-b-wrongz-residual"))
	msg := []byte("valid-sigma wrong-z residual")
	partials, agg, aggR1, quorum, evalPoints := bccRound(t, f, msg, sid)

	const badParty = 1
	_, L, _ := modeShape(f.params.Mode)
	// Malicious party proves a VALID statement for the WRONG z' = φ(0,0) = 0.
	zeros := make(polyVec, L)
	lambda := LagrangeAtZeroQ(evalPoints[badParty], evalPoints)
	st := &PartialStatement{
		Mode: f.params.Mode, Lambda: lambda, C: agg.c, Z: zeros,
		SessionID: sid, NonceID: partials[badParty].NonceID, PartyID: badParty,
	}
	proof, err := ProvePartial(st, &PartialWitness{Y: zeros, S1: zeros}, rand.Reader)
	if err != nil {
		t.Fatalf("ProvePartial(wrong-z): %v", err)
	}
	// Sanity: the wrong-z proof is genuinely VALID (so the sigma cannot catch it).
	if err := VerifyPartialProof(st, proof); err != nil {
		t.Fatalf("wrong-z proof unexpectedly invalid: %v", err)
	}
	wrong := append([]Partial(nil), partials...)
	wrong[badParty] = Partial{PartyID: badParty, NonceID: partials[badParty].NonceID, SessionID: sid, ZShare: packPolyVec(zeros), Proof: proof}
	// The malicious validator SIGNS its valid-sigma wrong-z partial (authenticated),
	// so origin-auth passes and the partial reaches the sigma check — which it
	// passes (valid statement for a wrong z). This is the residual: not attributed.
	f.idset.signPartial(&wrong[badParty], quorum[badParty], 0)

	agg2, cert, ev, ferr := agg.FinalizeWithBlame(aggR1, wrong)
	_ = agg2
	// (1) NO FORGERY: either the round errors, or it returns a signature that
	//     FAILS the standard FIPS verifier.
	if ferr == nil {
		if fipsVerify(t, f.setup, msg, &cert.Signature) {
			t.Fatalf("GATE B FAILED (FORGERY!): valid-sigma wrong-z produced a FIPS-valid signature")
		}
	}
	// (2) RESIDUAL: the wrong-z party is NOT attributed (the sigma passed; only
	//     BDLOP dealt-share binding could catch it). Document, don't fake.
	if _, attributed := func() (PartialBlame, bool) {
		for _, e := range ev {
			_ = e
		}
		_, _, blames, _ := AggregateBCCWithBlame(f.params, f.setup, agg.evalPoints, quorum, 0, f.idset,
			nil, msg, agg.c, &agg.cHat, agg.w1, sid, partials[badParty].NonceID, threshold, wrong)
		return blameFor(blames, badParty)
	}(); attributed {
		t.Fatalf("unexpected: valid-sigma wrong-z was attributed — update the residual claim (now SOUND)")
	}
	if ErrIdentifiableAbortResidual == nil {
		t.Fatal("residual marker missing")
	}
	t.Logf("GATE B.4 PASS (honest residual): valid-sigma wrong-z yields NO FIPS-valid signature (no forgery/leak) but is NOT yet attributed — BDLOP share-commitment residual (ErrIdentifiableAbortResidual)")
}

// TestRED_PoC_MEDIUM_CannotFrameOrExcludeHonestVictim is RED's MEDIUM PoCs
// (UnauthenticatedPartyID_BlameShift / MalformedFrontRun_ExcludesAndBlamesHonest)
// FLIPPED. An attacker front-runs an honest victim's slot with a forged,
// malformed partial STAMPED with the victim's PartyID. Pre-fix this got the
// victim BLAMED (BlameMalformed/Duplicate) and EXCLUDED off a raw unauthenticated
// PartyID. Post-fix:
//   - origin-auth drops the forgery (the attacker cannot sign as the victim), so
//     the victim's real partial stands -> NOT excluded, the round still signs;
//   - blame is gated on signature validity, so the victim is NEVER blamed.
func TestRED_PoC_MEDIUM_CannotFrameOrExcludeHonestVictim(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("red-medium-frame"))
	msg := []byte("attacker tries to frame an honest victim")
	partials, agg, aggR1, quorum, _ := bccRound(t, f, msg, sid)

	const victim = 1 // a non-aggregator slot
	// The attacker is NOT in the quorum; it holds its OWN identity key, never the
	// victim's. So it cannot produce the victim's signature.
	var attacker NodeID
	attacker[0] = 0xEE
	attackerSet := newTestIdentitySet(attacker)

	// (1) Forged partial: victim's PartyID, malformed content, signed with the
	//     ATTACKER's key (author = attacker). Front-run: placed BEFORE the real one.
	forged := Partial{PartyID: victim, SessionID: sid, NonceID: partials[victim].NonceID, ZShare: []byte{0xde, 0xad}}
	attackerSet.signPartial(&forged, attacker, 0)
	input := []Partial{partials[0], forged, partials[1], partials[2]}

	_, cert, ev, err := agg.FinalizeWithBlame(aggR1, input)
	if err != nil {
		t.Fatalf("RED MEDIUM: honest victim EXCLUDED — round failed with the victim's real partial present: %v", err)
	}
	if !fipsVerify(t, f.setup, msg, &cert.Signature) {
		t.Fatalf("RED MEDIUM: round did not produce a FIPS-valid signature with the victim included")
	}
	if blamedNode(ev, quorum[victim]) {
		t.Fatalf("RED MEDIUM: honest victim %x was BLAMED off an unauthenticated forged PartyID", quorum[victim][:4])
	}

	// (2) Impersonation variant: author CLAIMS to be the victim but signs with the
	//     wrong key (attacker lacks the victim's key) -> signature invalid -> dropped.
	forged2 := Partial{PartyID: victim, SessionID: sid, NonceID: partials[victim].NonceID, ZShare: []byte{0xba, 0xad}}
	forged2.Author = quorum[victim]
	forged2.AuthSig = idMAC(attackerSet.keys[attacker], partialAuthTBS(forged2, 0)) // wrong key
	input2 := []Partial{partials[0], forged2, partials[1], partials[2]}
	_, cert2, ev2, err2 := agg.FinalizeWithBlame(aggR1, input2)
	if err2 != nil || !fipsVerify(t, f.setup, msg, &cert2.Signature) {
		t.Fatalf("RED MEDIUM (impersonation): victim excluded (err=%v)", err2)
	}
	if blamedNode(ev2, quorum[victim]) {
		t.Fatalf("RED MEDIUM (impersonation): honest victim blamed off a forged victim-authored partial")
	}

	// (3) CONTRAST — the verifier is load-bearing. With NO identity verifier the
	//     same front-run EXCLUDES the victim (the forged malformed partial occupies
	//     the slot; the real one is dropped as a duplicate) -> t-1 valid ->
	//     ErrInsufficientSigners. No blame is emitted either way (blame is gated on
	//     auth), but exclusion-resistance REQUIRES the verifier.
	_, _, blamesNoAuth, errNoAuth := AggregateBCCWithBlame(f.params, f.setup, agg.evalPoints, quorum, 0, nil,
		nil, msg, agg.c, &agg.cHat, agg.w1, sid, partials[victim].NonceID, threshold, input)
	if !errors.Is(errNoAuth, ErrInsufficientSigners) {
		t.Fatalf("contrast: expected the un-authenticated path to drop to t-1 (front-run exclusion), got %v", errNoAuth)
	}
	if len(blamesNoAuth) != 0 {
		t.Fatalf("contrast: blame MUST NOT be emitted off raw unauthenticated PartyIDs, got %+v", blamesNoAuth)
	}
	t.Logf("RED MEDIUM FLIPPED: origin-auth drops the forged victim-slot partial (attacker cannot sign as the victim) -> victim NOT excluded, round still signs, victim NEVER blamed; the un-authenticated path neither blames nor (alone) resists exclusion — the verifier is load-bearing")
}
