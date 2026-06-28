// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// distributed_bcc_test.go — multi-node proof harness for the no-reconstruct
// single-share threshold ML-DSA signer (distributed_bcc.go).
//
// Each validator is a SEPARATE *DistributedBCCSigner holding exactly one
// AlgShare; round messages move between them over an in-memory bus. No
// process co-locates the shares and none reconstructs s1 or the seed. The
// aggregated signature verifies under the UNMODIFIED FIPS 204 verifier
// (VerifyBytes → cloudflare/circl mldsa{65,87}.Verify).

import (
	"bytes"
	"crypto/rand"
	"errors"
	"reflect"
	"sort"
	"testing"

	"golang.org/x/crypto/sha3"
)

// ── per-validator identity layer for authenticated-partial tests (RED MEDIUM) ──
//
// testIdentitySet models an identity layer with PER-VALIDATOR keys: each NodeID
// owns a random secret, so an attacker lacking a victim's key cannot forge the
// victim's signature. It is BOTH faces of the one identity layer — the verifier
// (VerifyAbortSignature) and, via signerFor, the producer (IdentitySigner).
// MAC = SHAKE256(key ‖ tbs)[:64] stands in for a real Ed25519/PQ identity key.
type testIdentitySet struct{ keys map[NodeID][]byte }

func newTestIdentitySet(ids ...NodeID) *testIdentitySet {
	s := &testIdentitySet{keys: make(map[NodeID][]byte, len(ids))}
	for _, id := range ids {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic(err)
		}
		s.keys[id] = k
	}
	return s
}

func idMAC(key, tbs []byte) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write(key)
	_, _ = h.Write(tbs)
	out := make([]byte, 64)
	_, _ = h.Read(out)
	return out
}

// VerifyAbortSignature is the verifier face (AbortSignatureVerifier).
func (s *testIdentitySet) VerifyAbortSignature(author NodeID, transcript, signature []byte) bool {
	k, ok := s.keys[author]
	if !ok || len(signature) == 0 {
		return false
	}
	return bytes.Equal(signature, idMAC(k, transcript))
}

// signerFor returns an IdentitySigner holding ONLY id's key (producer face).
func (s *testIdentitySet) signerFor(id NodeID) IdentitySigner {
	return keyedSigner{key: append([]byte(nil), s.keys[id]...)}
}

type keyedSigner struct{ key []byte }

func (k keyedSigner) SignProtocolMessage(tbs []byte) []byte { return idMAC(k.key, tbs) }

// signPartial stamps p with author + a valid identity signature over its
// (possibly tampered) content — models a validator that SIGNS a bad partial
// (authenticated misbehavior, attributable) as opposed to a transport-tampered
// partial (signature breaks, dropped, not attributed). Requires keys[author].
func (s *testIdentitySet) signPartial(p *Partial, author NodeID, epoch uint64) {
	p.Author = author
	p.AuthSig = idMAC(s.keys[author], partialAuthTBS(*p, epoch))
}

// bccFixture is a dealt (t, n) committee: the public setup plus one AlgShare
// per member. The shares come from the Part-1 trusted dealer; the GATE under
// test is that AFTER dealing, each share lives in a SEPARATE signer and the
// SIGNING ceremony never co-locates them or reconstructs s1/the seed.
type bccFixture struct {
	params    *Params
	setup     *AlgSetup
	committee []NodeID
	shares    []*AlgShare // sorted ascending by NodeID
	threshold int
	idset     *testIdentitySet // per-validator identity layer (authenticated partials)
}

func newBCCFixture(t *testing.T, mode Mode, n, threshold int) *bccFixture {
	t.Helper()
	params := MustParamsFor(mode)

	committee := make([]NodeID, n)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(committee[i][:]); err != nil {
			t.Fatalf("committee id entropy: %v", err)
		}
	}

	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("master seed entropy: %v", err)
	}
	setup, shares, err := DealAlgShares(params, committee, threshold, seed, rand.Reader)
	for i := range seed { // wipe our copy of the master seed immediately
		seed[i] = 0
	}
	if err != nil {
		t.Fatalf("DealAlgShares: %v", err)
	}

	// Sort shares ascending by NodeID so quorum[0] (the aggregator) is
	// deterministic.
	sort.Slice(shares, func(i, j int) bool { return nodeIDLess(shares[i].NodeID, shares[j].NodeID) })
	committee = make([]NodeID, n)
	for i, s := range shares {
		committee[i] = s.NodeID
	}
	return &bccFixture{
		params: params, setup: setup, committee: committee, shares: shares, threshold: threshold,
		idset: newTestIdentitySet(committee...), // one identity key per committee member
	}
}

// quorum returns the first q shares (sorted) and their eval points.
func (f *bccFixture) quorum(q int) (quorum []NodeID, evalPoints []uint32, shares []*AlgShare) {
	quorum = make([]NodeID, q)
	evalPoints = make([]uint32, q)
	shares = make([]*AlgShare, q)
	for i := 0; i < q; i++ {
		quorum[i] = f.shares[i].NodeID
		evalPoints[i] = f.shares[i].EvalPoint
		shares[i] = f.shares[i]
	}
	return quorum, evalPoints, shares
}

// runBCCCeremony drives the full distributed ceremony over an in-memory bus
// and returns the aggregated signature. Each node is a SEPARATE object;
// only round messages (and the NonceMPC-delivered y-shares) cross between
// them. The ceremony retries with a fresh NonceMPC nonce on a hint-weight
// rejection (the FIPS 204 rejection-restart, driven leaderlessly).
func runBCCCeremony(t *testing.T, f *bccFixture, q int, sid [32]byte, ctx, msg []byte) (*Signature, []*DistributedBCCSigner, error) {
	t.Helper()
	quorum, evalPoints, qshares := f.quorum(q)

	// Build q SEPARATE signers, one share each.
	nodes := make([]*DistributedBCCSigner, q)
	for i := 0; i < q; i++ {
		nd, err := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, ctx, msg, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		// This helper exercises the no-reconstruct FIPS-validity math over a trusted
		// in-memory bus; origin authentication is orthogonal and is exercised by the
		// blame/capstone suite (bccRound wires a REAL identity set). Opt OUT of the
		// origin-auth gate EXPLICITLY so aggregation is allowed (a bare nil verifier
		// is now refused FAIL-CLOSED — ErrOriginAuthRequired).
		nd.SetIdentity(nil, UnauthenticatedAggregation)
		nodes[i] = nd
	}

	for attempt := 0; attempt < int(f.params.MaxRestart); attempt++ {
		// NonceMPC stand-in: a fresh boundary-clear joint nonce + per-party
		// shares. (Production: the validator NonceMPC; here a dealer-modelled
		// stand-in — PULSAR-V13-W-LEAK.)
		var nonceID [32]byte
		nonceID[0] = byte(attempt)
		nonceID[1] = byte(attempt >> 8)
		copy(nonceID[2:], sid[:30])
		deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, q, nonceID, rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		// Deliver each node its own nonce share, then Round1 (bind nonce).
		var aggR1 SignRound1
		for i, nd := range nodes {
			if err := nd.SetNonceShare(nonceID, deal.YShares[quorum[i]]); err != nil {
				return nil, nil, err
			}
			r1, err := nd.Round1(sid, nonceID, deal.Cert)
			if err != nil {
				return nil, nil, err
			}
			if nd.IsAggregator() {
				aggR1 = r1
			}
		}

		// Round2 (emit proof-carrying z-partials) over the bus.
		partials := make([]Partial, 0, q)
		for _, nd := range nodes {
			p, err := nd.Round2(aggR1, PartialInput{})
			if err != nil {
				return nil, nil, err
			}
			partials = append(partials, p)
		}

		// Finalize on the designated aggregator (quorum[0]).
		var agg *DistributedBCCSigner
		for _, nd := range nodes {
			if nd.IsAggregator() {
				agg = nd
				break
			}
		}
		if agg == nil {
			return nil, nil, errors.New("no designated aggregator")
		}
		_, cert, err := agg.Finalize(aggR1, partials)
		if err == nil {
			return &cert.Signature, nodes, nil
		}
		// A hint-weight / norm rejection means "consume this nonce, retry".
		if errors.Is(err, ErrNoFIPSHint) || errors.Is(err, ErrBCCExhausted) {
			continue
		}
		return nil, nil, err
	}
	return nil, nil, errors.New("no acceptance within MaxRestart nonces")
}

// fipsVerify checks the signature under the UNMODIFIED FIPS 204 verifier via
// the stateless wire surface (VerifyBytes → mldsa{65,87}.Verify). When ctx
// is non-empty the canonical convention is to bind it into the message
// (ctx || 0x00 || msg) — the same μ derivation the signer used.
func fipsVerify(t *testing.T, setup *AlgSetup, msg []byte, sig *Signature) bool {
	t.Helper()
	gpk, err := setup.Pub.MarshalBinary()
	if err != nil {
		t.Fatalf("group pk marshal: %v", err)
	}
	sigW, err := sig.MarshalBinary()
	if err != nil {
		t.Fatalf("sig marshal: %v", err)
	}
	return VerifyBytes(gpk, msg, sigW)
}

// TestDistributedBCC_NoReconstructSign is the headline proof:
//   - t SEPARATE node objects, ONE share each (asserted), all distinct;
//   - a full distributed ceremony over a message bus (no orchestrator);
//   - the aggregated signature verifies under unmodified FIPS 204 ML-DSA;
//   - no process ever holds ≥ t shares or the seed.
func TestDistributedBCC_NoReconstructSign(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)

	var sid [32]byte
	copy(sid[:], []byte("pulsar-dealerless-v12-no-reconstruct"))
	msg := []byte("M-Chain finality: leaderless permissionless threshold ML-DSA")

	sig, nodes, err := runBCCCeremony(t, f, threshold, sid, nil, msg)
	if err != nil {
		t.Fatalf("distributed BCC ceremony: %v", err)
	}

	// CUSTODY INVARIANT: every node holds exactly one share; NodeIDs distinct.
	seen := make(map[NodeID]bool, len(nodes))
	for i, nd := range nodes {
		if got := nd.ShareCount(); got != 1 {
			t.Fatalf("node %d ShareCount=%d, want exactly 1 (single-share custody violated)", i, got)
		}
		id := nd.NodeID()
		if seen[id] {
			t.Fatalf("node %d shares NodeID %x with another node — co-location!", i, id[:4])
		}
		seen[id] = true
	}
	// The aggregator is itself one validator with one share.
	for _, nd := range nodes {
		if nd.IsAggregator() && nd.ShareCount() != 1 {
			t.Fatalf("aggregator holds %d shares, want 1", nd.ShareCount())
		}
	}

	// VERIFY under the UNMODIFIED FIPS 204 verifier (Class N1 byte-validity).
	if !fipsVerify(t, f.setup, msg, sig) {
		t.Fatalf("distributed no-reconstruct signature failed unmodified FIPS 204 VerifyBytes")
	}
}

// TestDistributedBCC_VerifiesUnderCloudflareCircl re-verifies the aggregated
// signature directly against cloudflare/circl's stock mldsa65.Verify — the
// independent reference verifier — by going through the package's Verify
// (which dispatches to circl). Belt-and-suspenders on byte-validity.
func TestDistributedBCC_VerifiesUnderStockVerifier(t *testing.T) {
	const n, threshold = 4, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("pulsar-v12-stock-verify"))
	msg := []byte("stock FIPS 204 verifier accepts the threshold signature")

	sig, _, err := runBCCCeremony(t, f, threshold, sid, nil, msg)
	if err != nil {
		t.Fatalf("ceremony: %v", err)
	}
	if err := Verify(f.params, f.setup.Pub, msg, sig); err != nil {
		t.Fatalf("aggregated signature rejected by stock FIPS 204 Verify: %v", err)
	}
	// Tamper one byte of the message ⇒ must reject.
	bad := append([]byte(nil), msg...)
	bad[0] ^= 0x01
	if fipsVerify(t, f.setup, bad, sig) {
		t.Fatalf("signature verified under a tampered message — binding broken")
	}
}

// TestDistributedBCC_Mode87 exercises ML-DSA-87 (the other in-BCC-scope set).
func TestDistributedBCC_Mode87(t *testing.T) {
	const n, threshold = 5, 4
	f := newBCCFixture(t, ModeP87, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("pulsar-v12-mldsa87"))
	msg := []byte("category-5 threshold finality")
	sig, _, err := runBCCCeremony(t, f, threshold, sid, nil, msg)
	if err != nil {
		t.Fatalf("ML-DSA-87 ceremony: %v", err)
	}
	if !fipsVerify(t, f.setup, msg, sig) {
		t.Fatalf("ML-DSA-87 distributed signature failed unmodified FIPS 204 VerifyBytes")
	}
}

// TestDistributedBCC_SubQuorumCannotSign proves the threshold bound: an
// aggregator handed fewer than t valid partials cannot produce a signature.
func TestDistributedBCC_SubQuorumCannotSign(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("pulsar-v12-subquorum"))
	msg := []byte("a sub-threshold coalition must not sign")

	quorum, evalPoints, qshares := f.quorum(threshold)
	var nonceID [32]byte
	nonceID[0] = 0x5a
	deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, threshold, nonceID, rand.Reader)
	if err != nil {
		t.Fatalf("nonce deal: %v", err)
	}

	nodes := make([]*DistributedBCCSigner, threshold)
	partials := make([]Partial, 0, threshold)
	var aggR1 SignRound1
	for i := 0; i < threshold; i++ {
		nd, err := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, nil, msg, rand.Reader)
		if err != nil {
			t.Fatalf("signer %d: %v", i, err)
		}
		// Trusted in-memory bus: opt OUT of origin-auth explicitly (a bare nil
		// verifier is now refused FAIL-CLOSED). The threshold bound under test is
		// orthogonal to origin authentication.
		nd.SetIdentity(nil, UnauthenticatedAggregation)
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
		}
		p, err := nd.Round2(r1, PartialInput{})
		if err != nil {
			t.Fatalf("round2 %d: %v", i, err)
		}
		partials = append(partials, p)
	}
	var agg *DistributedBCCSigner
	for _, nd := range nodes {
		if nd.IsAggregator() {
			agg = nd
		}
	}
	// Hand the aggregator only t-1 partials — CanonicalSignerSet must refuse.
	if _, _, err := agg.Finalize(aggR1, partials[:threshold-1]); !errors.Is(err, ErrInsufficientSigners) {
		t.Fatalf("aggregating t-1 partials: got err=%v, want ErrInsufficientSigners", err)
	}
}

// TestDistributedBCC_SoundPartialZProofRejectsForgery proves PULSAR-V13-
// PARTIAL-Z-PROOF is a REAL, sound proof in the signing path: a partial
// whose z-share is tampered (so the sigma equation no longer holds) is
// rejected at aggregation, and the aggregate carries only the honest
// partials. This is the clean blame path that keeps one bad partial from
// silently poisoning the aggregate.
func TestDistributedBCC_SoundPartialZProofRejectsForgery(t *testing.T) {
	const n, threshold = 4, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("pulsar-v12-partialz"))
	msg := []byte("a forged z-partial is caught by the sound sigma proof")

	quorum, evalPoints, qshares := f.quorum(threshold)
	var nonceID [32]byte
	nonceID[0] = 0x33
	deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, threshold, nonceID, rand.Reader)
	if err != nil {
		t.Fatalf("nonce deal: %v", err)
	}

	nodes := make([]*DistributedBCCSigner, threshold)
	honest := make([]Partial, 0, threshold)
	var aggR1 SignRound1
	for i := 0; i < threshold; i++ {
		nd, err := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, nil, msg, rand.Reader)
		if err != nil {
			t.Fatalf("signer %d: %v", i, err)
		}
		// Trusted in-memory bus: opt OUT of origin-auth explicitly (a bare nil
		// verifier is refused FAIL-CLOSED). This test probes the SOUND sigma proof
		// catching a forged z, orthogonal to origin authentication.
		nd.SetIdentity(nil, UnauthenticatedAggregation)
		nodes[i] = nd
		_ = nd.SetNonceShare(nonceID, deal.YShares[quorum[i]])
		r1, _ := nd.Round1(sid, nonceID, deal.Cert)
		if nd.IsAggregator() {
			aggR1 = r1
		}
		p, _ := nd.Round2(r1, PartialInput{})
		honest = append(honest, p)
	}

	// Verify each honest partial's proof passes directly (sound + complete).
	for _, p := range honest {
		z := unpackPolyVec(p.ZShare, mldsaL(f.params.Mode))
		lambda := LagrangeAtZeroQ(evalPoints[p.PartyID], evalPoints)
		c := nodes[0].c // every node derived the same challenge
		st := &PartialStatement{Mode: f.params.Mode, Lambda: lambda, C: c, Z: z,
			SessionID: sid, NonceID: nonceID, PartyID: p.PartyID}
		if err := VerifyPartialProof(st, p.Proof); err != nil {
			t.Fatalf("honest partial-z proof rejected (completeness broken): %v", err)
		}
	}

	// Forge one partial's z-share: bump a coefficient so the sigma equation
	// φ(u,v) == T + e·z no longer holds. The aggregator must drop it and then
	// have too few partials for the canonical set.
	forged := make([]Partial, len(honest))
	copy(forged, honest)
	z := unpackPolyVec(forged[1].ZShare, mldsaL(f.params.Mode))
	z[0][0] = (z[0][0] + 1) % mldsaQ
	forged[1].ZShare = packPolyVec(z)

	var agg *DistributedBCCSigner
	for _, nd := range nodes {
		if nd.IsAggregator() {
			agg = nd
		}
	}
	if _, _, err := agg.Finalize(aggR1, forged); !errors.Is(err, ErrInsufficientSigners) {
		t.Fatalf("forged z-partial not caught by the sound proof: got err=%v (want too-few-after-drop)", err)
	}
}

// TestDistributedBCC_Ctx exercises the FIPS 204 §5.4 context-bound path.
func TestDistributedBCC_Ctx(t *testing.T) {
	const n, threshold = 4, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("pulsar-v12-ctx"))
	ctx := []byte("lux-evm-precompile-mldsa-v1")
	msg := []byte("ctx-bound M-Chain certificate")

	sig, _, err := runBCCCeremony(t, f, threshold, sid, ctx, msg)
	if err != nil {
		t.Fatalf("ctx ceremony: %v", err)
	}
	// Verifies under the bound ctx, NOT under empty ctx (binding is real).
	if err := VerifyCtx(f.params, f.setup.Pub, msg, ctx, sig); err != nil {
		t.Fatalf("ctx-bound signature failed VerifyCtx(ctx): %v", err)
	}
	if err := VerifyCtx(f.params, f.setup.Pub, msg, nil, sig); err == nil {
		t.Fatalf("ctx-bound signature wrongly verified under empty ctx (binding broken)")
	}
}

// TestDistributedBCC_NoSeedNoS2NoT0InShare is the structural no-reconstruct
// witness: the share type carries s1 ONLY — no seed, no s2, no t0, no full
// secret — so a captured share (or even all shares short of t) cannot
// reconstruct the leaking residual. Complements the runtime ShareCount==1.
func TestDistributedBCC_NoSeedNoS2NoT0InShare(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(AlgShare{}),
		reflect.TypeOf(AlgSetup{}),
	} {
		for _, banned := range []string{"Seed", "S2", "T0", "Master", "FullT", "PrivateKey", "Sk"} {
			if hasFieldNamed(typ, banned) {
				t.Fatalf("%s carries forbidden secret field %q (no-reconstruct invariant violated)", typ.Name(), banned)
			}
		}
	}
	// The signer holds a single *AlgShare pointer, never a slice of shares.
	st := reflect.TypeOf(DistributedBCCSigner{})
	for i := 0; i < st.NumField(); i++ {
		fld := st.Field(i)
		if fld.Type.Kind() == reflect.Slice && fld.Type.Elem() == reflect.TypeOf(&AlgShare{}) {
			t.Fatalf("DistributedBCCSigner.%s is a slice of shares — single-share custody violated", fld.Name)
		}
		if fld.Type == reflect.TypeOf([SeedSize]byte{}) && fld.Name == "Seed" {
			t.Fatalf("DistributedBCCSigner carries a Seed field — reconstruct vector")
		}
	}
}

// mldsaL is the FIPS 204 secret dimension L for the mode (test helper).
func mldsaL(mode Mode) int { _, l, _ := modeShape(mode); return l }
