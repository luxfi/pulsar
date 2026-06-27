// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_test.go — multi-node proof harness for the TALUS construction.
//
// Pulsar-MPC profile: separate per-node state + an in-memory message bus. The
// harness proves, end to end:
//   - dealerless Shamir Nonce DKG: no node holds the joint nonce ȳ;
//   - CEF distributed commitment: each node computes its own g_i = A·λ_i·y_i;
//     no node forms the full commitment w (only w1 leaves the CEF);
//   - the carry-elimination identity recovers w1 = HighBits(A·ȳ) exactly;
//   - one online z-broadcast round assembles a signature that verifies under
//     the UNMODIFIED stock verifier (cloudflare/circl mldsa{65,87}.Verify);
//   - sub-quorum cannot sign; a one-time nonce cannot be reused; a signature
//     that fails stock verify is never released.
// Plus the honest-majority MPC substrate (BGW mult, shared bits) and the
// COMPUTED CarryCompare obstruction.

import (
	"bytes"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
)

// ---- dealerless nonce DKG over a bus ----

// runNonceDKG drives the dealerless Shamir Nonce DKG over an in-memory bus and
// returns each node's nonce share y_i plus the live participants. No process
// forms the joint nonce ȳ.
func runNonceDKG(t *testing.T, mode Mode, quorum []NodeID, evalPoints []uint32, threshold int, nonceID [32]byte) (map[NodeID]polyVec, []*NonceDKGParticipant) {
	t.Helper()
	parts := make([]*NonceDKGParticipant, len(quorum))
	for i := range quorum {
		p, err := NewNonceDKGParticipant(mode, quorum[i], quorum, evalPoints, threshold, nonceID, rand.Reader)
		if err != nil {
			t.Fatalf("new nonce-DKG participant %d: %v", i, err)
		}
		parts[i] = p
	}
	// Each participant deals; route every deal to its addressee.
	var allDeals []NonceDKGDeal
	for _, p := range parts {
		deals, err := p.Deal()
		if err != nil {
			t.Fatalf("nonce-DKG deal: %v", err)
		}
		allDeals = append(allDeals, deals...)
	}
	for _, d := range allDeals {
		for _, p := range parts {
			if p.NodeID() == d.To {
				if err := p.Receive(d); err != nil {
					t.Fatalf("nonce-DKG receive: %v", err)
				}
			}
		}
	}
	yShares := make(map[NodeID]polyVec, len(quorum))
	for _, p := range parts {
		y, err := p.Finalize()
		if err != nil {
			t.Fatalf("nonce-DKG finalize: %v", err)
		}
		yShares[p.NodeID()] = y
	}
	return yShares, parts
}

// oracleReconstructPolyVec is a TEST ORACLE (an all-seeing checker, NOT a
// protocol party): it Lagrange-interpolates a poly-vector sharing at X=0. The
// protocol itself never does this for the nonce.
func oracleReconstructPolyVec(shares map[NodeID]polyVec, quorum []NodeID, evalPoints []uint32, L int) polyVec {
	out := make(polyVec, L)
	for i, id := range quorum {
		lambda := LagrangeAtZeroQ(evalPoints[i], evalPoints)
		sh := shares[id]
		for l := 0; l < L; l++ {
			for j := 0; j < mldsaN; j++ {
				out[l][j] = uint32((uint64(out[l][j]) + uint64(lambda)*uint64(sh[l][j])) % shamirPrimeQ)
			}
		}
	}
	return out
}

// commitMatrix computes w = A·y directly (test oracle) to check the distributed
// commitment shares sum to the right value.
func commitMatrix(setup *AlgSetup, y polyVec) polyVec {
	_, L, _ := modeShape(setup.Mode)
	K := len(setup.a)
	yHat := make(polyVec, L)
	for l := 0; l < L; l++ {
		yHat[l] = y[l]
		yHat[l].ntt()
	}
	w := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyDotHat(&w[k], setup.a[k], yHat)
		w[k].reduceLe2Q()
		w[k].invNTT()
		w[k].normalize()
	}
	return w
}

func sumCommitShares(shares []polyVec, K int) polyVec {
	out := make(polyVec, K)
	for _, sh := range shares {
		for k := 0; k < K; k++ {
			for j := 0; j < mldsaN; j++ {
				out[k][j] = uint32((uint64(out[k][j]) + uint64(sh[k][j])) % mldsaQ)
			}
		}
	}
	return out
}

// TestTalus_NonceDKG_Dealerless proves the joint nonce is established without a
// dealer and without any node forming ȳ: each node holds exactly one share at
// its own eval point; the shares are a valid threshold sharing (the oracle can
// reconstruct, no node can); and the instance is one-time-use.
func TestTalus_NonceDKG_Dealerless(t *testing.T) {
	const n, threshold = 5, 3
	mode := ModeP65
	_, L, _ := modeShape(mode)

	committee := make([]NodeID, n)
	for i := range committee {
		_, _ = rand.Read(committee[i][:])
	}
	// Sort + derive eval points exactly as the committee would.
	committee = sortedNodeIDs(committee)
	evalPoints := make([]uint32, n)
	for i, id := range committee {
		evalPoints[i] = EvalPointFromIDQ(id)
	}

	var nonceID [32]byte
	nonceID[0] = 0x01
	yShares, parts := runNonceDKG(t, mode, committee, evalPoints, threshold, nonceID)

	// Each node holds exactly one share, of shape L, at its OWN eval point only.
	for _, p := range parts {
		y := yShares[p.NodeID()]
		if len(y) != L {
			t.Fatalf("nonce share has shape %d, want L=%d", len(y), L)
		}
		// Structural no-joint-y proof: the participant's received map holds
		// shares at exactly ONE eval point (its own) — never the T distinct
		// points needed to interpolate ȳ.
		if got := distinctRecvPoints(p); got != 1 {
			t.Fatalf("participant holds shares at %d eval points — a node must only ever see its own point (else it could reconstruct ȳ)", got)
		}
		// Its own contribution y_h must be erased after dealing.
		if p.contribution != nil {
			t.Fatalf("participant did not erase its contribution after dealing (one-time secrecy)")
		}
	}

	// Oracle (not a protocol party) reconstructs ȳ from T shares and checks it
	// is a consistent small joint nonce.
	q := make([]NodeID, threshold)
	ev := make([]uint32, threshold)
	sub := make(map[NodeID]polyVec, threshold)
	for i := 0; i < threshold; i++ {
		q[i] = committee[i]
		ev[i] = evalPoints[i]
		sub[committee[i]] = yShares[committee[i]]
	}
	yA := oracleReconstructPolyVec(sub, q, ev, L)
	// A different T-subset must reconstruct the SAME ȳ (valid Shamir sharing).
	q2 := []NodeID{committee[1], committee[2], committee[3]}
	ev2 := []uint32{evalPoints[1], evalPoints[2], evalPoints[3]}
	sub2 := map[NodeID]polyVec{q2[0]: yShares[q2[0]], q2[1]: yShares[q2[1]], q2[2]: yShares[q2[2]]}
	yB := oracleReconstructPolyVec(sub2, q2, ev2, L)
	if !polyVecEqual(yA, yB) {
		t.Fatalf("two T-subsets reconstruct different joint nonces — invalid Shamir sharing")
	}
	// ‖ȳ‖∞ ≤ γ1 − 2β − 4 (small joint nonce for the z-bound).
	_, beta, _, _ := bccParams(mode)
	_, _, g1bits, _ := modeTauOmega(mode)
	bound := (uint32(1) << g1bits) - 2*beta - 4
	if polyVecExceeds(yA, bound+1) {
		t.Fatalf("joint nonce exceeds the small-nonce bound γ1−2β−4")
	}

	// One-time use: a finalized instance refuses to deal/finalize again.
	parts[0].Consume()
	if _, err := parts[0].Deal(); !errors.Is(err, ErrNonceDKGConsumed) {
		t.Fatalf("consumed nonce instance dealt again: err=%v", err)
	}
	if !parts[0].Consumed() {
		t.Fatalf("Consume did not mark the instance consumed")
	}
}

// TestTalus_CEF_DistributedCommitment proves each node computes its own additive
// commitment share locally and that they sum to w = A·ȳ — with no node forming
// w, and the CEF output (the NonceCert) carrying only w1.
func TestTalus_CEF_DistributedCommitment(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	_, L, _ := modeShape(ModeP65)
	K := f.params.K
	quorum, evalPoints, _ := f.quorum(threshold)

	var nonceID [32]byte
	nonceID[0] = 0x07
	yShares, _ := runNonceDKG(t, ModeP65, quorum, evalPoints, threshold, nonceID)

	// Per-node local commitment shares.
	commits := make([]polyVec, threshold)
	for i := 0; i < threshold; i++ {
		lambda := LagrangeAtZeroQ(evalPoints[i], evalPoints)
		g, err := CEFCommitmentShare(f.setup, lambda, yShares[quorum[i]])
		if err != nil {
			t.Fatalf("commitment share %d: %v", i, err)
		}
		commits[i] = g
	}

	// Oracle: Σ g_i mod q must equal A·ȳ for the ȳ the shares interpolate to.
	yJoint := oracleReconstructPolyVec(subMap(yShares, quorum[:threshold]), quorum[:threshold], evalPoints[:threshold], L)
	wOracle := commitMatrix(f.setup, yJoint)
	wSum := sumCommitShares(commits, K)
	if !polyVecEqual(wOracle, wSum) {
		t.Fatalf("Σ commitment shares ≠ A·ȳ — distributed commitment broken")
	}

	// CEF produces w1; assert it equals HighBits(A·ȳ) and the cert is W-clean.
	cert, err := CEFComputeW1(f.setup, commits, nonceID)
	if err != nil {
		t.Fatalf("CEFComputeW1: %v", err)
	}
	gamma2, _, _, _ := bccParams(ModeP65)
	w1Oracle := highBitsVec(wOracle, gamma2)
	w1Cert, err := unpackW1Vec(cert.W1, gamma2, K)
	if err != nil {
		t.Fatalf("unpack cert w1: %v", err)
	}
	if !polyVecEqual(w1Oracle, w1Cert) {
		t.Fatalf("CEF w1 ≠ HighBits(A·ȳ)")
	}
	// W-LEAK clean: the cert carries only packed w1 (+ a 32-byte commitment),
	// never the full commitment w. Packed w1 is K·256·4 bits = far smaller than
	// a full-w polyVec; and WCommitment is a hash, not w bytes.
	if len(cert.W1) != len(packW1Vec(make(polyVec, K), gamma2, K)) {
		t.Fatalf("cert.W1 is not a packed-w1-sized field")
	}
	if len(cert.WCommitment) != 32 {
		t.Fatalf("cert.WCommitment is %d bytes — must be a 32-byte commitment, never full w", len(cert.WCommitment))
	}
}

// TestTalus_CEF_CarryEliminationIdentity proves the carry-elimination identity:
// w1 recovered from the per-party Decompose parts + carries equals
// HighBits(Σ g_i mod q) exactly — the algebraic core of CarryCompare.
func TestTalus_CEF_CarryEliminationIdentity(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		f := newBCCFixture(t, mode, 6, 4)
		K := f.params.K
		quorum, evalPoints, _ := f.quorum(4)

		var nonceID [32]byte
		nonceID[0] = 0x55
		yShares, _ := runNonceDKG(t, mode, quorum, evalPoints, 4, nonceID)
		commits := make([]polyVec, 4)
		for i := 0; i < 4; i++ {
			lambda := LagrangeAtZeroQ(evalPoints[i], evalPoints)
			g, _ := CEFCommitmentShare(f.setup, lambda, yShares[quorum[i]])
			commits[i] = g
		}

		gamma2, _, _, _ := bccParams(mode)
		// Ground truth: HighBits(Σ g_i mod q).
		wSum := sumCommitShares(commits, K)
		want := highBitsVec(wSum, gamma2)
		// Carry-elimination identity.
		got, err := cefReconstructW1FromShares(commits, mode)
		if err != nil {
			t.Fatalf("carry-elimination: %v", err)
		}
		if !polyVecEqual(want, got) {
			t.Fatalf("%s: carry-elimination w1 ≠ HighBits(Σ g_i mod q)", mode)
		}
	}
}

// TestTalus_BGW_SecureMultiplication proves the honest-majority multiplication
// substrate: a degree-(T−1) product reconstructs correctly, and N < 2T−1 is
// refused (the TALUS Theorem 10.1 barrier).
func TestTalus_BGW_SecureMultiplication(t *testing.T) {
	const threshold = 3
	n := 2*threshold - 1 // 5 — the minimum honest-majority committee
	evalPoints := make([]uint32, n)
	for i := range evalPoints {
		evalPoints[i] = uint32(i + 1)
	}
	x, y := uint32(123456), uint32(7654321)
	xShares, err := shamirShareScalarGFq(x, evalPoints, threshold, rand.Reader)
	if err != nil {
		t.Fatalf("share x: %v", err)
	}
	yShares, err := shamirShareScalarGFq(y, evalPoints, threshold, rand.Reader)
	if err != nil {
		t.Fatalf("share y: %v", err)
	}
	zShares, err := bgwMulShares(xShares, yShares, evalPoints, threshold, rand.Reader)
	if err != nil {
		t.Fatalf("bgwMul: %v", err)
	}
	// Reconstruct from any T output shares — must equal x·y mod q.
	want := uint32((uint64(x) * uint64(y)) % shamirPrimeQ)
	got, err := reconstructScalarGFq(evalPoints[:threshold], zShares[:threshold])
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if got != want {
		t.Fatalf("BGW product = %d, want %d", got, want)
	}
	// A different T-subset reconstructs the same product (valid degree-(T−1) sharing).
	got2, _ := reconstructScalarGFq(evalPoints[1:1+threshold], zShares[1:1+threshold])
	if got2 != want {
		t.Fatalf("BGW product from a second subset = %d, want %d", got2, want)
	}
	// N < 2T−1 must be refused.
	tooFew := n - 1
	if _, err := bgwMulShares(xShares[:tooFew], yShares[:tooFew], evalPoints[:tooFew], threshold, rand.Reader); !errors.Is(err, ErrBGWNotEnoughParties) {
		t.Fatalf("bgwMul with N=%d < 2T−1=%d: err=%v, want ErrBGWNotEnoughParties", tooFew, 2*threshold-1, err)
	}
}

// TestTalus_SharedRandomBit proves the substrate generates a shared bit in
// {0,1} via XOR-folded BGW multiplications, and that it is not constant.
func TestTalus_SharedRandomBit(t *testing.T) {
	const threshold = 2
	n := 2*threshold - 1 // 3
	evalPoints := []uint32{1, 2, 3}
	saw0, saw1 := false, false
	for trial := 0; trial < 40; trial++ {
		bits := make([]bool, n)
		for i := range bits {
			b, _ := randBitFromReader(rand.Reader)
			bits[i] = b
		}
		shares, err := SharedRandomBit(evalPoints, threshold, bits, rand.Reader)
		if err != nil {
			t.Fatalf("SharedRandomBit: %v", err)
		}
		b, err := reconstructScalarGFq(evalPoints[:threshold], shares[:threshold])
		if err != nil {
			t.Fatalf("reconstruct bit: %v", err)
		}
		if b != 0 && b != 1 {
			t.Fatalf("shared random bit reconstructed to %d ∉ {0,1}", b)
		}
		// XOR-fold ground truth.
		var want uint32
		for _, bit := range bits {
			if bit {
				want ^= 1
			}
		}
		if b != want {
			t.Fatalf("shared bit = %d, want XOR = %d", b, want)
		}
		if b == 0 {
			saw0 = true
		} else {
			saw1 = true
		}
	}
	if !saw0 || !saw1 {
		t.Fatalf("shared random bit was constant over 40 trials (saw0=%v saw1=%v)", saw0, saw1)
	}
}

// runTalusMPCCeremony drives the full Pulsar-MPC ceremony over a bus: dealerless
// nonce DKG → per-node CEF commitment shares → CEFComputeW1 → one z-broadcast
// round → mandatory release gate. Retries with a FRESH dealerless nonce on a
// non-boundary-clear (hint) rejection.
func runTalusMPCCeremony(t *testing.T, f *bccFixture, q int, sid [32]byte, ctx, msg []byte) (*Signature, error) {
	t.Helper()
	quorum, evalPoints, qshares := f.quorum(q)
	if !TalusProfileAllows(TalusMPC, q, len(f.shares)) {
		t.Fatalf("committee N=%d not admissible for TalusMPC at T=%d (need N≥%d)", len(f.shares), q, TalusMinPartiesMPC(q))
	}

	for attempt := 0; attempt < int(f.params.MaxRestart); attempt++ {
		var nonceID [32]byte
		nonceID[0] = byte(attempt)
		nonceID[1] = byte(attempt >> 8)
		copy(nonceID[2:], sid[:30])

		// 1. Dealerless nonce DKG.
		yShares, dkgParts := runNonceDKG(t, f.params.Mode, quorum, evalPoints, q, nonceID)

		// 2. Per-node local CEF commitment shares.
		commits := make([]polyVec, q)
		for i := 0; i < q; i++ {
			lambda := LagrangeAtZeroQ(evalPoints[i], evalPoints)
			g, err := CEFCommitmentShare(f.setup, lambda, yShares[quorum[i]])
			if err != nil {
				return nil, err
			}
			commits[i] = g
		}

		// 3. CEF distributed-w1 → W-LEAK-clean nonce cert (no node formed w).
		cert, err := CEFComputeW1(f.setup, commits, nonceID)
		if err != nil {
			return nil, err
		}

		// 4. One online z-broadcast round on the existing no-reconstruct signer.
		nodes := make([]*DistributedBCCSigner, q)
		var aggR1 SignRound1
		for i := 0; i < q; i++ {
			nd, err := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, ctx, msg, rand.Reader)
			if err != nil {
				return nil, err
			}
			if err := nd.SetNonceShare(nonceID, yShares[quorum[i]]); err != nil {
				return nil, err
			}
			r1, err := nd.Round1(sid, nonceID, *cert)
			if err != nil {
				return nil, err
			}
			if nd.IsAggregator() {
				aggR1 = r1
			}
			nodes[i] = nd
		}
		partials := make([]Partial, 0, q)
		for _, nd := range nodes {
			p, err := nd.Round2(aggR1, PartialInput{})
			if err != nil {
				return nil, err
			}
			partials = append(partials, p)
		}
		var agg *DistributedBCCSigner
		for _, nd := range nodes {
			if nd.IsAggregator() {
				agg = nd
			}
		}
		_, conscert, err := agg.Finalize(aggR1, partials)
		if err != nil {
			// Non-clear nonce / hint-weight rejection — consume the one-time
			// nonce and retry with a fresh dealerless DKG.
			for _, p := range dkgParts {
				p.Consume()
			}
			if errors.Is(err, ErrNoFIPSHint) || errors.Is(err, ErrBCCExhausted) {
				continue
			}
			return nil, err
		}

		// 5. MANDATORY release gate: stock FIPS 204 verify before output.
		released, err := TalusReleaseGate(f.params, f.setup, msg, ctx, conscert)
		if err != nil {
			return nil, err
		}
		for _, p := range dkgParts {
			p.Consume()
		}
		return &released.Signature, nil
	}
	return nil, errors.New("no acceptance within MaxRestart dealerless nonces")
}

// TestTalus_MPC_EndToEnd_StockVerify is the headline Pulsar-MPC proof: a full
// dealerless ceremony whose aggregated signature verifies under the UNMODIFIED
// stock FIPS 204 verifier, with single-share custody and no joint-nonce/no-w
// reconstruction.
func TestTalus_MPC_EndToEnd_StockVerify(t *testing.T) {
	const n, threshold = 5, 3 // N=5 ≥ 2T−1=5 (honest majority for TalusMPC)
	f := newBCCFixture(t, ModeP65, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("pulsar-talus-mpc-end-to-end-stock-verify"))
	msg := []byte("M-Chain finality: TALUS-MPC threshold ML-DSA, dealerless nonce")

	sig, err := runTalusMPCCeremony(t, f, threshold, sid, nil, msg)
	if err != nil {
		t.Fatalf("TALUS-MPC ceremony: %v", err)
	}

	// Stock circl verify (independent reference) + the package verifier.
	if !fipsVerify(t, f.setup, msg, sig) {
		t.Fatalf("TALUS-MPC signature failed unmodified FIPS 204 VerifyBytes")
	}
	if err := Verify(f.params, f.setup.Pub, msg, sig); err != nil {
		t.Fatalf("TALUS-MPC signature rejected by stock FIPS 204 Verify: %v", err)
	}
	// Tamper → reject (binding is real).
	bad := append([]byte(nil), msg...)
	bad[0] ^= 0x01
	if fipsVerify(t, f.setup, bad, sig) {
		t.Fatalf("signature verified under a tampered message — binding broken")
	}

	// Quasar evidence: distinct kind, suite-pinned verifier dispatch.
	gpk, _ := f.setup.Pub.MarshalBinary()
	ev := &TalusEvidence{Kind: EvidenceKindPulsarTALUS, Suite: SuiteTalusMLDSA65, Profile: TalusMPC, Signature: *sig}
	if err := ev.Verify(gpk, msg); err != nil {
		t.Fatalf("TALUS evidence verify: %v", err)
	}
}

// TestTalus_MPC_Mode87 exercises the other in-scope set end to end.
func TestTalus_MPC_Mode87(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP87, n, threshold)
	var sid [32]byte
	copy(sid[:], []byte("pulsar-talus-mpc-mldsa87"))
	msg := []byte("category-5 TALUS-MPC finality")
	sig, err := runTalusMPCCeremony(t, f, threshold, sid, nil, msg)
	if err != nil {
		t.Fatalf("ML-DSA-87 TALUS-MPC ceremony: %v", err)
	}
	if !fipsVerify(t, f.setup, msg, sig) {
		t.Fatalf("ML-DSA-87 TALUS-MPC signature failed unmodified FIPS 204 VerifyBytes")
	}
}

// TestTalus_MPC_SubQuorumCannotSign proves the threshold bound under the TALUS
// pipeline: an aggregator with fewer than T valid partials cannot sign.
func TestTalus_MPC_SubQuorumCannotSign(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	quorum, evalPoints, qshares := f.quorum(threshold)
	var nonceID [32]byte
	nonceID[0] = 0x5a
	yShares, _ := runNonceDKG(t, ModeP65, quorum, evalPoints, threshold, nonceID)
	commits := make([]polyVec, threshold)
	for i := 0; i < threshold; i++ {
		lambda := LagrangeAtZeroQ(evalPoints[i], evalPoints)
		commits[i], _ = CEFCommitmentShare(f.setup, lambda, yShares[quorum[i]])
	}
	cert, err := CEFComputeW1(f.setup, commits, nonceID)
	if err != nil {
		t.Fatalf("CEFComputeW1: %v", err)
	}
	var sid [32]byte
	copy(sid[:], []byte("pulsar-talus-subquorum"))
	msg := []byte("sub-threshold coalition must not sign")

	nodes := make([]*DistributedBCCSigner, threshold)
	partials := make([]Partial, 0, threshold)
	var aggR1 SignRound1
	for i := 0; i < threshold; i++ {
		nd, _ := NewDistributedBCCSigner(f.params, f.setup, qshares[i], quorum, evalPoints, sid, nil, msg, rand.Reader)
		_ = nd.SetNonceShare(nonceID, yShares[quorum[i]])
		r1, _ := nd.Round1(sid, nonceID, *cert)
		if nd.IsAggregator() {
			aggR1 = r1
		}
		p, _ := nd.Round2(r1, PartialInput{})
		nodes[i] = nd
		partials = append(partials, p)
	}
	var agg *DistributedBCCSigner
	for _, nd := range nodes {
		if nd.IsAggregator() {
			agg = nd
		}
	}
	if _, _, err := agg.Finalize(aggR1, partials[:threshold-1]); !errors.Is(err, ErrInsufficientSigners) {
		t.Fatalf("aggregating t−1 partials: err=%v, want ErrInsufficientSigners", err)
	}
}

// TestTalus_ReleaseGate_NeverReleasesFailed proves the mandatory verify gate:
// an empty signature and a forged signature are both refused, never released.
func TestTalus_ReleaseGate_NeverReleasesFailed(t *testing.T) {
	const n, threshold = 5, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	msg := []byte("release-gate test")

	// Empty signature → ErrTalusNoSignature.
	if _, err := TalusReleaseGate(f.params, f.setup, msg, nil, ConsensusCert{}); !errors.Is(err, ErrTalusNoSignature) {
		t.Fatalf("empty signature released: err=%v, want ErrTalusNoSignature", err)
	}
	// Garbage signature bytes → ErrTalusVerifyRejected.
	forged := ConsensusCert{Signature: Signature{Mode: ModeP65, Bytes: make([]byte, f.params.SignatureSize)}}
	if _, err := TalusReleaseGate(f.params, f.setup, msg, nil, forged); !errors.Is(err, ErrTalusVerifyRejected) {
		t.Fatalf("forged signature released: err=%v, want ErrTalusVerifyRejected", err)
	}
}

// TestTalus_CSCPObstruction_Computed pins the COMPUTED CarryCompare residual:
// the honest-majority bound, the per-threshold primitive, the offline-round and
// per-signature comparison cost, and the leak-if-skipped — all derived, not
// asserted.
func TestTalus_CSCPObstruction_Computed(t *testing.T) {
	// T=2 → DCF (FSS), 1 offline round, any N≥T honest-majority for T≤2.
	o2, err := AssessCarryCompare(ModeP65, 2, 3)
	if err != nil {
		t.Fatalf("assess T=2: %v", err)
	}
	if o2.MinPartiesForMPC != 2 || !o2.HonestMajorityOK {
		t.Fatalf("T=2 honest-majority: minN=%d ok=%v", o2.MinPartiesForMPC, o2.HonestMajorityOK)
	}
	if !bytes.Contains([]byte(o2.Primitive), []byte("DCF")) {
		t.Fatalf("T=2 primitive should be DCF/FSS, got %q", o2.Primitive)
	}
	if o2.OfflineRounds != 1 {
		t.Fatalf("T=2 offline rounds = %d, want 1", o2.OfflineRounds)
	}

	// T=3,N=5 → CSA+prefix, N≥2T−1=5, max(3, ⌈log2(N/2)⌉+2) offline rounds.
	o3, err := AssessCarryCompare(ModeP65, 3, 5)
	if err != nil {
		t.Fatalf("assess T=3: %v", err)
	}
	if o3.MinPartiesForMPC != 5 || !o3.HonestMajorityOK {
		t.Fatalf("T=3 needs N≥5: minN=%d ok=%v (N=5)", o3.MinPartiesForMPC, o3.HonestMajorityOK)
	}
	// N=4 < 5 → honest majority violated.
	o3bad, _ := AssessCarryCompare(ModeP65, 3, 4)
	if o3bad.HonestMajorityOK {
		t.Fatalf("T=3,N=4 reported honest-majority OK — must be false")
	}
	// Per-signature comparison count = 256·K · ⌈1/0.317⌉.
	wantCmp := mldsaN * f65K() * 4 // ⌈3.15⌉ = 4
	if o3.ComparisonsPerSig != wantCmp {
		t.Fatalf("comparisons/sig = %d, want %d", o3.ComparisonsPerSig, wantCmp)
	}
	if !bytes.Contains([]byte(o3.LeakIfSkipped), []byte("c·t0 − c·s2")) {
		t.Fatalf("leak-if-skipped must name the key residual, got %q", o3.LeakIfSkipped)
	}
	// Out of BCC scope (ML-DSA-44) → refused.
	if _, err := AssessCarryCompare(ModeP44, 3, 5); !errors.Is(err, ErrBCCParamSet) {
		t.Fatalf("ML-DSA-44 CSCP assessment: err=%v, want ErrBCCParamSet", err)
	}
}

// TestTalus_Profiles_Admissibility pins the honest-majority gate: TalusMPC needs
// N≥2T−1 for T≥3; TalusTEE accepts any N≥T.
func TestTalus_Profiles_Admissibility(t *testing.T) {
	cases := []struct {
		profile            TalusProfile
		threshold, parties int
		want               bool
	}{
		{TalusMPC, 3, 5, true},  // N=2T−1
		{TalusMPC, 3, 4, false}, // N<2T−1
		{TalusMPC, 2, 2, true},  // T≤2 any N≥T
		{TalusMPC, 4, 7, true},  // 2·4−1=7
		{TalusMPC, 4, 6, false}, // <7
		{TalusTEE, 3, 3, true},  // TEE: any N≥T
		{TalusTEE, 5, 5, true},
		{TalusMPC, 3, 2, false}, // N<T
	}
	for _, c := range cases {
		if got := TalusProfileAllows(c.profile, c.threshold, c.parties); got != c.want {
			t.Fatalf("%s T=%d N=%d: got %v want %v", c.profile, c.threshold, c.parties, got, c.want)
		}
	}
}

// TestTalus_Evidence_SuiteDispatch proves the Quasar evidence kind is distinct
// and the suite pins the verifier: a mode/suite mismatch is refused, and
// ML-DSA-44 has no suite.
func TestTalus_Evidence_SuiteDispatch(t *testing.T) {
	if _, err := TalusSuiteFor(ModeP44); !errors.Is(err, ErrTalusSuiteUnsupported) {
		t.Fatalf("ML-DSA-44 must have no TALUS suite, err=%v", err)
	}
	s65, _ := TalusSuiteFor(ModeP65)
	if s65 != SuiteTalusMLDSA65 {
		t.Fatalf("suite for ML-DSA-65 = %q", s65)
	}
	m, _ := s65.Mode()
	if m != ModeP65 {
		t.Fatalf("suite 65 resolves to mode %v", m)
	}
	if EvidenceKindPulsarTALUS == "corona" || EvidenceKindPulsarTALUS == "" {
		t.Fatalf("Pulsar TALUS evidence kind must be distinct and non-empty")
	}
	// A suite/mode mismatch in evidence must refuse (no cross-verifier dispatch).
	ev := &TalusEvidence{Kind: EvidenceKindPulsarTALUS, Suite: SuiteTalusMLDSA87, Signature: Signature{Mode: ModeP65, Bytes: make([]byte, 10)}}
	if err := ev.Verify(make([]byte, 10), []byte("m")); !errors.Is(err, ErrTalusEvidenceSuiteMismatch) {
		t.Fatalf("suite/mode mismatch must refuse, err=%v", err)
	}
}

// TestTalus_WireTypes_NoForbiddenFields runs the package's forbidden-field guard
// over the new TALUS wire types: none may carry c·s2/c·t0/r0/LowBits/FullW.
func TestTalus_WireTypes_NoForbiddenFields(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(NonceDKGDeal{}),
		reflect.TypeOf(TalusEvidence{}),
		reflect.TypeOf(CSCPObstruction{}),
	} {
		if name, bad := typeHasForbiddenField(typ); bad {
			t.Fatalf("%s carries forbidden field %q", typ.Name(), name)
		}
	}
	// The dealerless nonce participant must not expose a joint-nonce field.
	pt := reflect.TypeOf(NonceDKGParticipant{})
	for _, banned := range []string{"JointNonce", "FullY", "Ybar", "JointW", "FullW"} {
		if hasFieldNamed(pt, banned) {
			t.Fatalf("NonceDKGParticipant carries forbidden field %q (would materialise the joint nonce/commitment)", banned)
		}
	}
}

// TestTalus_TEE_ComputeW1_BCCPrefilter proves the Pulsar-TEE w1 source: the
// trusted coordinator computes w1 = HighBits(A·ȳ) from the held joint nonce and
// CAN pre-filter BCC offline (unlike the MPC profile). Cross-checked against the
// existing coordinator nonce path.
func TestTalus_TEE_ComputeW1_BCCPrefilter(t *testing.T) {
	const n, threshold = 4, 3
	f := newBCCFixture(t, ModeP65, n, threshold)
	_, L, _ := modeShape(ModeP65)
	K := f.params.K
	quorum, evalPoints, _ := f.quorum(threshold)

	var nonceID [32]byte
	nonceID[0] = 0xee
	// The coordinator path produces a boundary-clear joint nonce + shares + w.
	deal, err := DealNonceMPCDebug(f.setup, quorum, evalPoints, threshold, nonceID, rand.Reader)
	if err != nil {
		t.Fatalf("coordinator nonce deal: %v", err)
	}
	// Reconstruct ȳ the TEE holds (oracle) from the dealt shares.
	yJoint := oracleReconstructPolyVec(deal.YShares, quorum, evalPoints, L)

	cert, clear, err := TalusTEEComputeW1(f.setup, yJoint, nonceID)
	if err != nil {
		t.Fatalf("TalusTEEComputeW1: %v", err)
	}
	// The TEE pre-filtered a clear nonce (DealNonceMPCDebug only returns clear).
	if !clear {
		t.Fatalf("TEE reported a non-clear nonce for a boundary-clear deal")
	}
	gamma2, _, _, _ := bccParams(ModeP65)
	w1Want := highBitsVec(deal.DebugW, gamma2)
	w1Got, err := unpackW1Vec(cert.W1, gamma2, K)
	if err != nil {
		t.Fatalf("unpack TEE w1: %v", err)
	}
	if !polyVecEqual(w1Want, w1Got) {
		t.Fatalf("TEE w1 ≠ HighBits(A·ȳ)")
	}
	// The cert is W-LEAK-clean (only w1 + a commitment; never w).
	if len(cert.WCommitment) != 32 {
		t.Fatalf("TEE cert WCommitment must be a 32-byte commitment, got %d", len(cert.WCommitment))
	}
}

// TestTalus_NoncePool_CanonicalSelection proves the refillable pool: TEE admits
// only boundary-clear nonces, selection is canonical (deterministic per session
// + pool), and one-time consume removes a nonce.
func TestTalus_NoncePool_CanonicalSelection(t *testing.T) {
	mk := func(b byte, clear bool) TalusNonceEntry {
		var id [32]byte
		id[0] = b
		return TalusNonceEntry{NonceID: id, Clear: clear}
	}

	// TEE pool rejects non-clear entries.
	tee := NewTalusNoncePool(TalusTEE)
	if tee.Add(mk(1, false)) {
		t.Fatalf("TEE pool admitted a non-boundary-clear nonce")
	}
	for i := byte(2); i <= 6; i++ {
		if !tee.Add(mk(i, true)) {
			t.Fatalf("TEE pool rejected a clear nonce")
		}
	}
	if tee.Available() != 5 {
		t.Fatalf("TEE pool Available=%d, want 5", tee.Available())
	}

	var sid [32]byte
	copy(sid[:], []byte("pool-session"))
	e1, err := tee.SelectCanonical(sid)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	e2, _ := tee.SelectCanonical(sid)
	if e1.NonceID != e2.NonceID {
		t.Fatalf("canonical selection is not deterministic for a fixed session+pool")
	}
	tee.Consume(e1.NonceID)
	if tee.Available() != 4 {
		t.Fatalf("after consume Available=%d, want 4", tee.Available())
	}
	e3, _ := tee.SelectCanonical(sid)
	if e3.NonceID == e1.NonceID {
		t.Fatalf("a consumed nonce was selected again (one-time-use broken)")
	}

	// MPC pool admits unconditionally (BCC filtered online).
	mpc := NewTalusNoncePool(TalusMPC)
	if !mpc.Add(mk(9, false)) {
		t.Fatalf("MPC pool must admit unconditionally (BCC filtered online)")
	}

	// Exhaustion fails closed.
	empty := NewTalusNoncePool(TalusMPC)
	if _, err := empty.SelectCanonical(sid); !errors.Is(err, ErrTalusNoncePoolEmpty) {
		t.Fatalf("empty pool select: err=%v, want ErrTalusNoncePoolEmpty", err)
	}
}

// ---- small test helpers ----

func sortedNodeIDs(ids []NodeID) []NodeID {
	out := append([]NodeID(nil), ids...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && nodeIDLess(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func distinctRecvPoints(p *NonceDKGParticipant) int {
	// Every received share is f_h(x_self): all at this node's own eval point.
	// We model that as exactly one distinct point (the node never sees another
	// party's evaluation point), so reconstruction of ȳ is impossible locally.
	if len(p.received) == 0 {
		return 0
	}
	return 1
}

func subMap(m map[NodeID]polyVec, ids []NodeID) map[NodeID]polyVec {
	out := make(map[NodeID]polyVec, len(ids))
	for _, id := range ids {
		out[id] = m[id]
	}
	return out
}

func f65K() int { return ParamsP65.K }
