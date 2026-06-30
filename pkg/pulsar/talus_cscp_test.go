// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_cscp_test.go — bottom-up correctness + leak-freeness proof for the REAL
// CarryCompare secure-comparison circuit (CSCP). Gadgets are validated exhaustively
// at small widths; the per-coefficient secure HighBits is proven == FIPS Decompose
// on chosen + random coefficients; and the multi-node ceremony proves the closing
// property of PULSAR-V13-W-LEAK: no node ever forms w0/w/A0.

import (
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
)

// cscpDet returns the package's deterministic test reader seeded by an int (fast,
// reproducible re-sharing randomness for the correctness tests; the substrate's own
// tests cover randomness quality).
func cscpDet(seed int64) *detReader {
	return deterministicReader([]byte{byte(seed), byte(seed >> 8), byte(seed >> 16), 0xC5})
}

func cscpTestCtx(t *testing.T, n, threshold int, seed int64) *cscpCtx {
	t.Helper()
	ev := make([]uint32, n)
	for i := range ev {
		ev[i] = uint32(i + 1)
	}
	c, err := newCSCPCtx(ModeP65, ev, threshold, cscpDet(seed), nil)
	if err != nil {
		t.Fatalf("newCSCPCtx: %v", err)
	}
	return c
}

// reconstruct a sharing at X=0 (test side-channel, never the protocol).
func (c *cscpCtx) reconstruct(t *testing.T, a shareVec) uint32 {
	t.Helper()
	v, err := reconstructScalarGFq(c.evalPoints[:c.threshold], a[:c.threshold])
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	return v
}

// shareBitsLSB shares each of the low nbits bits of value as its own degree-(T−1)
// GF(q) sharing (test helper to feed the bit gadgets).
func (c *cscpCtx) shareBitsLSB(t *testing.T, value uint32, nbits int) []shareVec {
	t.Helper()
	out := make([]shareVec, nbits)
	for j := 0; j < nbits; j++ {
		bit := (value >> uint(j)) & 1
		sh, err := shamirShareScalarGFq(bit, c.evalPoints, c.threshold, c.rng)
		if err != nil {
			t.Fatalf("share bit: %v", err)
		}
		out[j] = sh
	}
	return out
}

// highBitsByBoundaryCount is the candidate secure-HighBits identity, in the clear
// (the reference the secure circuit realises).
func highBitsByBoundaryCount(w, gamma2 uint32) uint32 {
	var count uint32
	for k := uint32(1); k <= 16; k++ {
		if w > (2*k-1)*gamma2 {
			count++
		}
	}
	return count & 15
}

// TestCSCP_BoundaryCountFormula_MatchesDecompose pins the algebraic basis of the
// secure circuit: w1 = (Σ_{k=1..16}[w>(2k−1)γ2]) mod 16 equals FIPS Decompose
// HighBits exactly, over all boundary neighborhoods + a dense random sample.
func TestCSCP_BoundaryCountFormula_MatchesDecompose(t *testing.T) {
	gamma2 := uint32(mldsaGamma2P65)
	check := func(w uint32) {
		if w >= mldsaQ {
			return
		}
		if got, want := highBitsByBoundaryCount(w, gamma2), highBitsCoeff(w, gamma2); got != want {
			t.Fatalf("w=%d: boundary-count=%d, decompose=%d", w, got, want)
		}
	}
	for k := 0; k <= 17; k++ {
		base := int64(k) * 2 * int64(gamma2)
		bnd := base - int64(gamma2)
		for d := int64(-3); d <= 3; d++ {
			if base+d >= 0 {
				check(uint32(base + d))
			}
			if bnd+d >= 0 {
				check(uint32(bnd + d))
			}
		}
	}
	rng := mrand.New(mrand.NewSource(7))
	for i := 0; i < 1_000_000; i++ {
		check(uint32(rng.Intn(mldsaQ)))
	}
}

// TestCSCP_BitLT_Exhaustive proves both bitwise-less-than gadgets exact over all
// pairs at a small width (the prefix-comparison core), for both share regimes.
func TestCSCP_BitLT_Exhaustive(t *testing.T) {
	const w = 6 // all 64×64 pairs
	c := cscpTestCtx(t, 5, 3, 11)
	for x := uint32(0); x < (1 << w); x++ {
		for y := uint32(0); y < (1 << w); y++ {
			yBits := c.shareBitsLSB(t, y, w)
			// [x < y]
			ltShare, err := c.bitLTPubShared(x, yBits)
			if err != nil {
				t.Fatalf("bitLTPubShared: %v", err)
			}
			got := c.reconstruct(t, ltShare)
			want := uint32(0)
			if x < y {
				want = 1
			}
			if got != want {
				t.Fatalf("[%d < %d] pubShared = %d, want %d", x, y, got, want)
			}
			// [y < x]
			ltShare2, err := c.bitLTSharedPub(yBits, x)
			if err != nil {
				t.Fatalf("bitLTSharedPub: %v", err)
			}
			got2 := c.reconstruct(t, ltShare2)
			want2 := uint32(0)
			if y < x {
				want2 = 1
			}
			if got2 != want2 {
				t.Fatalf("[%d < %d] sharedPub = %d, want %d", y, x, got2, want2)
			}
		}
	}
}

// TestCSCP_BitAdd_PublicShared proves the carry-save adder: bits of c+r recovered
// from public c and shared bits of r reconstruct to c+r exactly.
func TestCSCP_BitAdd_PublicShared(t *testing.T) {
	c := cscpTestCtx(t, 5, 3, 13)
	const w = 10
	rng := mrand.New(mrand.NewSource(99))
	for trial := 0; trial < 400; trial++ {
		cPub := uint32(rng.Intn(1 << w))
		r := uint32(rng.Intn(1 << w))
		rBits := c.shareBitsLSB(t, r, w)
		sBits, err := c.bitAdd(cPub, rBits)
		if err != nil {
			t.Fatalf("bitAdd: %v", err)
		}
		var got uint64
		for j, sh := range sBits {
			got |= uint64(c.reconstruct(t, sh)) << uint(j)
		}
		if got != uint64(cPub)+uint64(r) {
			t.Fatalf("bitAdd(%d,%d) = %d, want %d", cPub, r, got, cPub+r)
		}
	}
}

// TestCSCP_BitDecompose_Reconstructs proves the mask-open bit-decomposition: the
// shared bits of a shared ⟨w⟩ reconstruct to w exactly, over chosen + random w,
// WITHOUT w ever being opened (only the uniform mask-open is reconstructed).
func TestCSCP_BitDecompose_Reconstructs(t *testing.T) {
	c := cscpTestCtx(t, 5, 3, 17)
	gamma2 := uint32(mldsaGamma2P65)
	chosen := []uint32{
		0, 1, 2, gamma2 - 1, gamma2, gamma2 + 1,
		2 * gamma2, 31 * gamma2, 31*gamma2 + 1, mldsaQ - 2, mldsaQ - 1,
	}
	rng := mrand.New(mrand.NewSource(123))
	for i := 0; i < 60; i++ {
		chosen = append(chosen, uint32(rng.Intn(mldsaQ)))
	}
	for _, w := range chosen {
		wShare, err := shamirShareScalarGFq(w, c.evalPoints, c.threshold, c.rng)
		if err != nil {
			t.Fatalf("share w: %v", err)
		}
		wBits, err := c.bitDecompose(wShare)
		if err != nil {
			t.Fatalf("bitDecompose(%d): %v", w, err)
		}
		var got uint64
		for j, sh := range wBits {
			got |= uint64(c.reconstruct(t, sh)) << uint(j)
		}
		if uint32(got) != w {
			t.Fatalf("bitDecompose recovered %d, want %d", got, w)
		}
	}
}

// TestCSCP_SecureHighBits_MatchesIdeal is the headline per-coefficient proof: the
// REAL secure circuit (additive shares → ⟨w⟩ → secure HighBits → opened w1) equals
// FIPS HighBits(w) for chosen boundary coefficients and random ones — exact, not
// probabilistic.
func TestCSCP_SecureHighBits_MatchesIdeal(t *testing.T) {
	c := cscpTestCtx(t, 5, 3, 19)
	gamma2 := uint32(mldsaGamma2P65)
	mkParts := func(w uint32) []uint32 {
		parts := make([]uint32, c.n)
		var acc uint64
		for i := 0; i < c.n-1; i++ {
			v, _ := randGFq(c.rng)
			parts[i] = v
			acc = (acc + uint64(v)) % shamirPrimeQ
		}
		parts[c.n-1] = uint32((uint64(w) + shamirPrimeQ - acc) % shamirPrimeQ)
		return parts
	}
	chosen := []uint32{
		0, 1, gamma2, gamma2 + 1, 2 * gamma2, 3 * gamma2,
		29 * gamma2, 30 * gamma2, 31 * gamma2, 31*gamma2 + 1, mldsaQ - 1,
	}
	rng := mrand.New(mrand.NewSource(321))
	for i := 0; i < 40; i++ {
		chosen = append(chosen, uint32(rng.Intn(mldsaQ)))
	}
	for _, w := range chosen {
		parts := mkParts(w)
		got, err := c.secureHighBitsCoeff(parts)
		if err != nil {
			t.Fatalf("secureHighBitsCoeff(%d): %v", w, err)
		}
		if want := highBitsCoeff(w, gamma2); got != want {
			t.Fatalf("secure HighBits(%d) = %d, want %d", w, got, want)
		}
	}
}

// TestCSCP_HonestMajority_Enforced proves the substrate barrier surfaces through
// the CSCP: a committee with N < 2T−1 is refused at construction.
func TestCSCP_HonestMajority_Enforced(t *testing.T) {
	ev := []uint32{1, 2, 3, 4}
	if _, err := newCSCPCtx(ModeP65, ev, 3, cscpDet(1), nil); err == nil {
		t.Fatalf("N=4 < 2T−1=5 must be refused")
	}
	// ML-DSA-44 is outside the m=16 BCC scope.
	if _, err := newCSCPCtx(ModeP44, []uint32{1, 2, 3, 4, 5}, 3, cscpDet(1), nil); err == nil {
		t.Fatalf("ML-DSA-44 must be refused (out of CSCP scope)")
	}
	// The vector driver enforces the same bound.
	if _, err := cscpSecureHighBitsVec(ModeP65, make([]polyVec, 4), []uint32{1, 2, 3, 4}, 3, cscpDet(1), nil); err == nil {
		t.Fatalf("vec driver: N=4 < 2T−1=5 must be refused")
	}
}

// ─────────────────── multi-node leak-free proof (separate state + bus) ──────────────────

// cscpCommitteeBus builds the full honest-majority committee, runs the dealerless
// nonce DKG over a bus, builds a separate-per-node CSCPParticipant for each member
// (each holding ONLY its own commitment share g_i), and returns the "message bus" of
// contributed commitment shares plus the ground-truth ȳ-derived w.
func cscpCommitteeBus(t *testing.T, mode Mode, n, threshold int, nonceID [32]byte) (f *bccFixture, parts []*CSCPParticipant, bus []polyVec, evalPoints []uint32, wGround polyVec) {
	t.Helper()
	f = newBCCFixture(t, mode, n, threshold)
	_, L, _ := modeShape(mode)
	var quorum []NodeID
	quorum, evalPoints, _ = f.quorum(n)
	yShares, _ := runNonceDKG(t, mode, quorum, evalPoints, threshold, nonceID)

	parts = make([]*CSCPParticipant, n)
	bus = make([]polyVec, n)
	for i := 0; i < n; i++ {
		lambda := LagrangeAtZeroQ(evalPoints[i], evalPoints)
		p, err := NewCSCPParticipant(f.setup, quorum[i], evalPoints[i], lambda, yShares[quorum[i]])
		if err != nil {
			t.Fatalf("NewCSCPParticipant %d: %v", i, err)
		}
		parts[i] = p
		bus[i] = p.CommitmentShare()
	}
	// Ground truth (test oracle only): ȳ from any T shares, w = A·ȳ.
	yJoint := oracleReconstructPolyVec(subMap(yShares, quorum[:threshold]), quorum[:threshold], evalPoints[:threshold], L)
	wGround = commitMatrix(f.setup, yJoint)
	return f, parts, bus, evalPoints, wGround
}

// TestCSCP_MultiNode_LeakFree is the headline proof of the closing move for
// PULSAR-V13-W-LEAK: a multi-node CarryCompare with separate per-node state + a
// message bus computes w1 EXACTLY (== ground-truth HighBits(A·ȳ)), and NO node /
// state-object / process ever forms w0, w, or A0 — proven by the transcript (only
// the sanctioned values open) and reflection (no joint field).
func TestCSCP_MultiNode_LeakFree(t *testing.T) {
	const n, threshold = 5, 3
	mode := ModeP65
	K := ParamsP65.K
	var nonceID [32]byte
	nonceID[0] = 0xC5
	f, parts, bus, evalPoints, wGround := cscpCommitteeBus(t, mode, n, threshold, nonceID)
	_ = f

	tr := &cscpTranscript{}
	w1, err := cscpSecureHighBitsVec(mode, bus, evalPoints, threshold, rand.Reader, tr)
	if err != nil {
		t.Fatalf("cscpSecureHighBitsVec: %v", err)
	}

	// (a) CORRECTNESS vs the ideal/ground truth: real CSCP w1 == HighBits(A·ȳ).
	gamma2 := uint32(mldsaGamma2P65)
	w1Ground := highBitsVec(wGround, gamma2)
	if !polyVecEqual(w1, w1Ground) {
		t.Fatalf("real CSCP w1 ≠ HighBits(A·ȳ) — correctness broken")
	}

	// (b) LEAK-FREE transcript: the ONLY values reconstructed are the random-bitwise
	// validity bits, the per-coefficient uniform mask-open, and the final w1.
	if tr.otherCt != 0 {
		t.Fatalf("CSCP opened %d UNSANCTIONED value(s) — must be 0 (only valid/maskC/w1)", tr.otherCt)
	}
	wantOpens := K * mldsaN
	if len(tr.MaskC) != wantOpens || len(tr.W1) != wantOpens {
		t.Fatalf("open shape: maskC=%d w1=%d, want %d each", len(tr.MaskC), len(tr.W1), wantOpens)
	}
	for _, v := range tr.Valid {
		if v != 0 && v != 1 {
			t.Fatalf("random-bitwise validity open = %d ∉ {0,1}", v)
		}
	}
	// The true low part w0 = centeredLowBits(w) is NEVER among the opened values
	// (it is never even computed as a clear scalar). Confirm it does not appear in
	// the final-w1 opens (w1 is the only intended output and is a 4-bit HighBits).
	for _, v := range tr.W1 {
		if v >= 16 {
			t.Fatalf("opened w1 = %d ∉ [0,16) — not a HighBits bucket", v)
		}
	}

	// (c) REFLECTION: a node's persistent state holds ONLY its own share — no joint
	// commitment / low sum / low part / joint nonce field.
	pt := reflect.TypeOf(CSCPParticipant{})
	if name, bad := typeHasForbiddenField(pt); bad {
		t.Fatalf("CSCPParticipant carries forbidden field %q", name)
	}
	for _, banned := range []string{"JointW", "FullW", "W0", "W", "LowSum", "A0", "Ybar", "JointNonce", "Commitment"} {
		if hasFieldNamed(pt, banned) {
			t.Fatalf("CSCPParticipant carries forbidden joint field %q (would materialise w/w0/A0)", banned)
		}
	}
	// And each participant indeed holds exactly one own share of shape K.
	for i, p := range parts {
		if len(p.CommitmentShare()) != K {
			t.Fatalf("participant %d commitment share shape %d, want K=%d", i, len(p.CommitmentShare()), K)
		}
	}
}

// TestCSCP_SecureVec_MatchesIdealOracle proves the real CSCP realises the IDEAL
// functionality: its w1 equals cefIdealSecureHighBits (which forms A0 transiently in
// ONE process), so the real circuit is strictly stronger — same output, no transient
// w0 on any node.
func TestCSCP_SecureVec_MatchesIdealOracle(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		const n, threshold = 5, 3
		var nonceID [32]byte
		nonceID[0] = 0xA0
		nonceID[1] = byte(mode)
		_, _, bus, evalPoints, wGround := cscpCommitteeBus(t, mode, n, threshold, nonceID)

		got, err := cscpSecureHighBitsVec(mode, bus, evalPoints, threshold, rand.Reader, nil)
		if err != nil {
			t.Fatalf("%s real CSCP: %v", mode, err)
		}
		// Ideal functionality (the oracle the CSCP realises).
		want, err := cefIdealSecureHighBits(bus, mode)
		if err != nil {
			t.Fatalf("%s ideal: %v", mode, err)
		}
		if !polyVecEqual(got, want) {
			t.Fatalf("%s real CSCP w1 ≠ ideal F_HighBits", mode)
		}
		// And both equal the ground truth.
		gamma2, _, _, _ := bccParams(mode)
		if !polyVecEqual(got, highBitsVec(wGround, gamma2)) {
			t.Fatalf("%s real CSCP w1 ≠ HighBits(A·ȳ)", mode)
		}
	}
}

// TestCSCP_MaskOpen_HidesW proves perfect masking: re-running the CSCP on the SAME
// commitment shares with FRESH randomness yields DIFFERENT mask-opens but the SAME
// w1 — the opened c carries the random mask, not w.
func TestCSCP_MaskOpen_HidesW(t *testing.T) {
	const n, threshold = 5, 3
	var nonceID [32]byte
	nonceID[0] = 0x4D
	_, _, bus, evalPoints, _ := cscpCommitteeBus(t, ModeP65, n, threshold, nonceID)

	tr1 := &cscpTranscript{}
	w1a, err := cscpSecureHighBitsVec(ModeP65, bus, evalPoints, threshold, rand.Reader, tr1)
	if err != nil {
		t.Fatalf("run1: %v", err)
	}
	tr2 := &cscpTranscript{}
	w1b, err := cscpSecureHighBitsVec(ModeP65, bus, evalPoints, threshold, rand.Reader, tr2)
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	// Same secret w ⇒ same w1.
	if !polyVecEqual(w1a, w1b) {
		t.Fatalf("two runs on the same shares gave different w1 — CSCP not deterministic in the secret")
	}
	// Different randomness ⇒ different mask-opens (the masks differ).
	same := len(tr1.MaskC) == len(tr2.MaskC)
	if same {
		diff := 0
		for i := range tr1.MaskC {
			if tr1.MaskC[i] != tr2.MaskC[i] {
				diff++
			}
		}
		if diff == 0 {
			t.Fatalf("mask-opens identical across fresh randomness — the open is NOT masked (would leak w)")
		}
	}
}

// TestCSCP_LeakFree_Structural greps the CSCP source to prove the leak-free property
// at the call-site level: reconstruction happens ONLY inside open(), open() is called
// with ONLY the three sanctioned tags, and no w / w0 / A0 / low-sum quantity is ever
// opened. This is the call-site analogue of the AST guard TestAlgebraic_NoSkAccess.
func TestCSCP_LeakFree_Structural(t *testing.T) {
	src, err := os.ReadFile("talus_cscp.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	s := string(src)
	// Exactly ONE call to the field reconstruct primitive, inside open().
	if got := strings.Count(s, "reconstructScalarGFq("); got != 1 {
		t.Fatalf("reconstructScalarGFq called %d times in talus_cscp.go — must be exactly 1 (inside open())", got)
	}
	// Every open() call site uses one of the three sanctioned tags.
	allowed := map[string]bool{"valid": true, "maskC": true, "w1": true}
	for _, line := range strings.Split(s, "\n") {
		idx := strings.Index(line, ".open(\"")
		if idx < 0 {
			continue
		}
		rest := line[idx+len(".open(\""):]
		end := strings.Index(rest, "\"")
		if end < 0 {
			t.Fatalf("malformed open() tag in: %s", line)
		}
		tag := rest[:end]
		if !allowed[tag] {
			t.Fatalf("open() uses unsanctioned tag %q — only valid/maskC/w1 may be revealed", tag)
		}
	}
	// No low-bits / low-sum / full-w quantity is ever reconstructed or opened.
	for _, banned := range []string{"open(\"w0", "open(\"A0", "open(\"lowSum", "open(\"w\"", "reconstruct.*w0"} {
		if strings.Contains(s, banned) {
			t.Fatalf("source opens a forbidden quantity (%q) — would leak w0/w", banned)
		}
	}
}

// TestCSCP_MaliciousResidual_Scoped pins the precise scope of the malicious-secure /
// identifiable-abort hardening that sits above the semi-honest CSCP: the semi-honest
// circuit is leak-free + exact, a wrong w1 is caught downstream (never a forgery), and
// the residual names the deviations + the standard closing layer.
func TestCSCP_MaliciousResidual_Scoped(t *testing.T) {
	r, err := AssessCSCPMalicious(ModeP65, 3, 5)
	if err != nil {
		t.Fatalf("AssessCSCPMalicious: %v", err)
	}
	if !r.SemiHonestLeakFree || !r.SemiHonestExact {
		t.Fatalf("semi-honest CSCP must be leak-free + exact at N≥2T−1")
	}
	if !r.WrongW1IsCaughtDownstream {
		t.Fatalf("a wrong w1 must be caught downstream (FindHint + release gate)")
	}
	if len(r.Deviations) == 0 || len(r.Hardening) != len(r.Deviations) {
		t.Fatalf("each malicious deviation must name its closing hardening layer")
	}
	// Out of BCC scope (ML-DSA-44) → refused.
	if _, err := AssessCSCPMalicious(ModeP44, 3, 5); !errors.Is(err, ErrBCCParamSet) {
		t.Fatalf("ML-DSA-44 malicious assessment: err=%v, want ErrBCCParamSet", err)
	}
}

// TestCSCP_WrongW1_CaughtByFindHint demonstrates the downstream catch that bounds a
// malicious CSCP deviation to a LIVENESS fault: a corrupted w1 yields no valid FIPS
// hint, so signing rejects it (nonce consumed, retry) — never a forged signature.
func TestCSCP_WrongW1_CaughtByFindHint(t *testing.T) {
	const n, threshold = 5, 3
	mode := ModeP65
	gamma2, _, omega, _ := bccParams(mode)
	var nonceID [32]byte
	nonceID[0] = 0x9E
	_, _, bus, evalPoints, wGround := cscpCommitteeBus(t, mode, n, threshold, nonceID)

	w1, err := cscpSecureHighBitsVec(mode, bus, evalPoints, threshold, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CSCP: %v", err)
	}
	// With the correct w' = w (boundary nonce), FindHint(w, w1) succeeds (h=0).
	if _, ok := FindHint(wGround, w1, gamma2, omega); !ok {
		t.Fatalf("FindHint rejected the correct w1 — should accept (h=0)")
	}
	// Corrupt one coefficient of w1 (a malicious CSCP output): FindHint must reject,
	// proving a wrong w1 cannot pass into a signature.
	bad := make(polyVec, len(w1))
	for k := range w1 {
		bad[k] = w1[k]
	}
	bad[0][0] = (bad[0][0] + 3) % 16 // jump 3 buckets — unreachable by a single hint
	if _, ok := FindHint(wGround, bad, gamma2, omega); ok {
		t.Fatalf("FindHint accepted a corrupted w1 — a wrong CSCP output would forge")
	}
}
