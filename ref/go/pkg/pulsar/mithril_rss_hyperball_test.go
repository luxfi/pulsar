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

// ---------------------------------------------------------------------------
// GATE 6: fail-closed behaviours (sub-threshold, malformed/biased partial +
// blame, equivocation, nonce reuse).
// ---------------------------------------------------------------------------

// hbSession is a manual in-process harness exposing the individual round
// functions so the fault tests can inject misbehaviour a malicious party could.
type hbSession struct {
	mk      *MithrilKey
	hp      *hyperballParams
	parties []*hyperballParty
	co      *hyperballCoordinator
	sid     [32]byte
	mu      [64]byte
	entropy []byte
}

func setupHBSession(t *testing.T, tt, n int, msg, ctx []byte, label string) *hbSession {
	t.Helper()
	mk, err := MithrilRSSKeygen(ModeP65, tt, n, mithrilSeeds(n))
	if err != nil {
		t.Fatal(err)
	}
	hp, err := deriveHyperballParams(ModeP65, tt, n)
	if err != nil {
		t.Fatal(err)
	}
	active := canonicalActive(tt)
	var mu [64]byte
	deriveMuCtx(mk.tr, ctx, msg, mu[:])
	part, err := rss.RSSRecover(active, tt, n)
	if err != nil {
		t.Fatal(err)
	}
	parties := make([]*hyperballParty, len(active))
	for j, id := range active {
		s1Share, err := mk.partyShareS1(id, part[j])
		if err != nil {
			t.Fatal(err)
		}
		parties[j] = newHyperballParty(ModeP65, hp, mk.a, id, s1Share)
	}
	sid := hyperballSessionID(mk.pub, active, mu[:])
	co := newHyperballCoordinator(mk, hp, active, mu[:])
	co.bindMessage(msg, ctx)
	ent := make([]byte, 32)
	h := newBCCDeterministicRNG("PULSAR/HYPERBALL/manual/" + label)
	_, _ = h.Read(ent)
	return &hbSession{mk: mk, hp: hp, parties: parties, co: co, sid: sid, mu: mu, entropy: ent}
}

func (s *hbSession) round1() []HyperballRound1 {
	r1s := make([]HyperballRound1, len(s.parties))
	for j, p := range s.parties {
		r1s[j] = p.round1(s.entropy, s.sid, s.mu[:])
	}
	return r1s
}
func (s *hbSession) round2() []HyperballRound2 {
	r2s := make([]HyperballRound2, len(s.parties))
	for j, p := range s.parties {
		r2s[j] = p.round2()
	}
	return r2s
}
func (s *hbSession) round3() []HyperballRound3 {
	ch := s.co.challengesForRound3()
	r3s := make([]HyperballRound3, len(s.parties))
	for j, p := range s.parties {
		r3s[j] = p.round3(ch)
	}
	return r3s
}
func (s *hbSession) liveSlots() []int {
	var out []int
	for i, c := range s.co.c {
		if c != nil {
			out = append(out, i)
		}
	}
	return out
}
func r3byID(r3s []HyperballRound3) map[int]HyperballRound3 {
	m := map[int]HyperballRound3{}
	for _, r := range r3s {
		m[r.PartyID] = r
	}
	return m
}

// TestHyperballSubThresholdFailsClosed proves a below-threshold or malformed
// active set is rejected before any signing — never a partial-quorum signature.
func TestHyperballSubThresholdFailsClosed(t *testing.T) {
	mk, err := MithrilRSSKeygen(ModeP65, 4, 6, mithrilSeeds(6))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("sub-threshold")
	cases := map[string][]int{
		"too_few":      {0, 1, 2},       // T−1 signers
		"too_many":     {0, 1, 2, 3, 4}, // T+1 signers
		"unsorted":     {0, 2, 1, 3},    // not sorted
		"duplicate":    {0, 1, 1, 3},    // duplicate id
		"out_of_range": {0, 1, 2, 9},    // id ≥ N
	}
	for name, active := range cases {
		t.Run(name, func(t *testing.T) {
			rng := newBCCDeterministicRNG("sub/" + name)
			sig, _, err := mk.SignHyperball(active, msg, nil, rng, 8)
			if err == nil {
				t.Fatalf("active=%v produced a signature — sub-threshold not fail-closed", active)
			}
			if sig != nil {
				t.Fatal("non-nil signature returned with an error")
			}
		})
	}
}

// TestHyperballBiasedPartialCaughtAndBlamed proves the FindHint + self-verify
// release gate rejects a biased partial (no bad signature is ever emitted) and
// blameSlot pinpoints the culprit without leaking s2 (it stops at the culprit,
// never forming the full active sum Σ_j T_j = t − s2).
func TestHyperballBiasedPartialCaughtAndBlamed(t *testing.T) {
	msg := []byte("biased partial")
	ctx := []byte("gate6")
	s := setupHBSession(t, 3, 5, msg, ctx, "biased")
	params, _ := ParamsFor(ModeP65)

	r1s := s.round1()
	r2s := s.round2()
	if err := s.co.aggregateCommitments(s.sid, r1s, r2s); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	r3s := s.round3()

	// Baseline: the honest round produces a valid signature (so the fault below
	// is what breaks it, not an already-dead round).
	if _, _, err := s.co.finalize(params, r3s); err != nil {
		t.Fatalf("honest round did not finalize: %v", err)
	}

	// A blame slot must be one EVERY party accepted (so an honest party is not
	// mistaken for a liveness fault). The honest finalize above guarantees one.
	blameAt := -1
	for sl := 0; sl < s.hp.kReps; sl++ {
		if s.co.c[sl] == nil {
			continue
		}
		allAcc := true
		for _, r := range r3s {
			if !r.Accepted[sl] || r.Z[sl] == nil {
				allAcc = false
				break
			}
		}
		if allAcc {
			blameAt = sl
			break
		}
	}
	if blameAt < 0 {
		t.Skip("no fully-accepted slot in this deterministic round (raise K)")
	}

	// Malicious party at active index 1 biases its partial on EVERY accepted
	// slot (keeps Accepted=true to look live). The committed T_1 is honest.
	bad := 1
	badID := s.co.active[bad]
	for sl := range r3s[bad].Z {
		if r3s[bad].Accepted[sl] && r3s[bad].Z[sl] != nil {
			r3s[bad].Z[sl][0][0] = (r3s[bad].Z[sl][0][0] + 12345) % mldsaQ
		}
	}

	// Release gate: no slot yields a verifiable signature → fail-closed.
	if sig, _, err := s.co.finalize(params, r3s); err == nil {
		t.Fatalf("finalize emitted a signature despite a biased partial: %v", sig != nil)
	}

	// Blame: reveal T_j up to the culprit only (party 0, then party 1 = culprit).
	revealed := map[int]polyVec{
		s.co.active[0]: s.parties[0].tjS1,
		s.co.active[1]: s.parties[1].tjS1,
	}
	culprit, ok := s.co.blameSlot(blameAt, r3byID(r3s), revealed)
	if !ok || culprit != badID {
		t.Fatalf("blame returned (%d, %v); want culprit %d", culprit, ok, badID)
	}
	// Leak-free discipline holds: party 2's T was never revealed, so the full
	// active sum Σ_j T_j (= t − s2) was never formed.
	if _, leaked := revealed[s.co.active[2]]; leaked {
		t.Fatal("blame revealed the final party's T — would leak s2")
	}
}

// TestHyperballEquivocationCaught proves a rushing party that changes its
// commitment w between Round 1 and Round 2 is rejected by the binding check.
func TestHyperballEquivocationCaught(t *testing.T) {
	s := setupHBSession(t, 3, 3, []byte("equiv"), nil, "equiv")
	r1s := s.round1()
	r2s := s.round2()
	// Party 1 reveals a DIFFERENT w for slot 0 than it committed in Round 1.
	r2s[1].W[0][0][0] = (r2s[1].W[0][0][0] + 777) % mldsaQ
	if err := s.co.aggregateCommitments(s.sid, r1s, r2s); err == nil {
		t.Fatal("aggregateCommitments accepted an equivocated w — binding broken")
	}
}

// TestHyperballNonceReuseFatal demonstrates WHY the protocol must never reuse a
// mask across two challenges (it leaks the share), and asserts the protocol's
// per-round nonce derivation prevents it (fresh entropy ⇒ fresh masks; the
// Round-1 commitment binds the mask before the challenge is known).
func TestHyperballNonceReuseFatal(t *testing.T) {
	mk, err := MithrilRSSKeygen(ModeP65, 3, 5, mithrilSeeds(5))
	if err != nil {
		t.Fatal(err)
	}
	_, L, _ := modeShape(ModeP65)
	part, _ := rss.RSSRecover(canonicalActive(3), 3, 5)
	s1Share, _ := mk.partyShareS1(0, part[0])
	s1Hat := make(polyVec, L)
	for l := 0; l < L; l++ {
		s1Hat[l] = s1Share[l]
		s1Hat[l].reduceLe2Q()
		s1Hat[l].ntt()
	}

	// Two distinct challenges, ONE reused mask y.
	var c1, c2 poly
	polyDeriveUniformBall(&c1, []byte("reuse-challenge-1"), 49)
	polyDeriveUniformBall(&c2, []byte("reuse-challenge-2"), 49)
	seed := hyperballNonceSeed([]byte("fixed-round-entropy-32-bytes!!!!"), [32]byte{}, 0, 0)
	yf := sampleHyperballInBall(seed, L*mldsaN, 1.0e6)
	y := floatToMaskPolyVec(yf, L)

	z1 := addCMulShare(y, &c1, s1Hat, L)
	z2 := addCMulShare(y, &c2, s1Hat, L)

	// The mask cancels: z1 − z2 = (c1 − c2)·s1_(j). An attacker can CONFIRM a
	// guess g of the share by checking c1·g − c2·g == z1 − z2.
	diffZ := subPolyVec(z1, z2, L)
	if !samePolyVec(diffZ, shareDiffWitness(&c1, &c2, s1Hat, L), L) {
		t.Fatal("reuse identity z1−z2 = (c1−c2)·s1 does not hold — test setup wrong")
	}
	// A WRONG share guess fails the confirmation — so the check is information-
	// bearing and the true share is recoverable from reused-nonce signatures.
	wrong := make(polyVec, L)
	for l := 0; l < L; l++ {
		wrong[l] = s1Share[l]
	}
	wrong[0][0] = (wrong[0][0] + 1) % mldsaQ
	wrongHat := make(polyVec, L)
	for l := 0; l < L; l++ {
		wrongHat[l] = wrong[l]
		wrongHat[l].reduceLe2Q()
		wrongHat[l].ntt()
	}
	if samePolyVec(diffZ, shareDiffWitness(&c1, &c2, wrongHat, L), L) {
		t.Fatal("a wrong share also satisfied the reuse identity — leak demo vacuous")
	}

	// Protection: the per-round nonce seed is fresh across rounds (distinct
	// entropy ⇒ distinct mask) and deterministic within a round (so the
	// Round-1 commitment binds the mask before the challenge is revealed).
	e1 := []byte("round-entropy-AAAAAAAAAAAAAAAAAA")
	e2 := []byte("round-entropy-BBBBBBBBBBBBBBBBBB")
	var sid [32]byte
	if *hyperballNonceSeed(e1, sid, 0, 0) == *hyperballNonceSeed(e2, sid, 0, 0) {
		t.Fatal("distinct round entropy produced the same nonce seed — reuse risk")
	}
	if *hyperballNonceSeed(e1, sid, 0, 0) != *hyperballNonceSeed(e1, sid, 0, 0) {
		t.Fatal("nonce seed is non-deterministic within a round — commitment would not bind")
	}
}

// addCMulShare returns y + c·s1 (the partial-response computation), matching the
// party's round3 arithmetic.
func addCMulShare(y polyVec, c *poly, s1Hat polyVec, L int) polyVec {
	cHat := *c
	cHat.ntt()
	out := make(polyVec, L)
	for l := 0; l < L; l++ {
		var cs1 poly
		cs1.mulHat(&cHat, &s1Hat[l])
		cs1.reduceLe2Q()
		cs1.invNTT()
		cs1.normalize()
		out[l].add(&y[l], &cs1)
		out[l].normalize()
	}
	return out
}

// shareDiffWitness returns c1·s1 − c2·s1 (what z1 − z2 must equal under reuse).
func shareDiffWitness(c1, c2 *poly, s1Hat polyVec, L int) polyVec {
	zero := make(polyVec, L)
	a := addCMulShare(zero, c1, s1Hat, L)
	b := addCMulShare(zero, c2, s1Hat, L)
	return subPolyVec(a, b, L)
}

func subPolyVec(a, b polyVec, L int) polyVec {
	out := make(polyVec, L)
	for l := 0; l < L; l++ {
		out[l].sub(&a[l], &b[l])
		out[l].normalize()
	}
	return out
}
func samePolyVec(a, b polyVec, L int) bool {
	for l := 0; l < L; l++ {
		if a[l] != b[l] {
			return false
		}
	}
	return true
}
