package pulsar

import (
	"math/rand"
	"testing"
)

// These are DEBUG-ORACLE tests: they reconstruct the hidden commitment w
// directly to verify the BCC/CEF arithmetic, lemmas, and yield. Production
// code must NOT compute or publish full w (PULSAR-V13-W-LEAK); it publishes
// only w1, a commitment to w, and a ZK boundary-clearance proof.

func randPolyVec(rng *rand.Rand, k int) polyVec {
	w := make(polyVec, k)
	for i := 0; i < k; i++ {
		for j := 0; j < mldsaN; j++ {
			w[i][j] = uint32(rng.Int63n(mldsaQ))
		}
	}
	return w
}

func subMod(a uint32, delta int32) uint32 {
	v := (int64(a) - int64(delta)) % mldsaQ
	if v < 0 {
		v += mldsaQ
	}
	return uint32(v)
}

// The leaking AlgebraicAggregate path must be disabled by default
// (PULSAR-V13-HINT-LEAK), independent of any other signer state.
func TestThresholdV03DisabledByDefault(t *testing.T) {
	s := &AlgebraicThresholdSigner{}
	if _, _, err := s.Round2Sign(nil, nil); err != ErrUnsafeThresholdV03HintPath {
		t.Fatalf("threshold_v03 must fail closed by default; got err=%v", err)
	}
}

// BCC/CEF is proven only where ||c·t0||_inf < gamma2 (ML-DSA-65/87, not 44).
func TestBCCParamGuard(t *testing.T) {
	for _, m := range []Mode{ModeP65, ModeP87} {
		if _, _, _, ok := bccParams(m); !ok {
			t.Fatalf("mode %d must be in BCC scope", m)
		}
	}
	if _, _, _, ok := bccParams(ModeP44); ok {
		t.Fatalf("ML-DSA-44 must be rejected (tau*2^(d-1) >= gamma2)")
	}
	// Sanity on the c·t0 bound itself.
	for _, m := range []Mode{ModeP65, ModeP87} {
		tau, _, _, g2 := modeTauOmega(m)
		if uint32(tau)*(1<<(bccD-1)) >= g2 {
			t.Fatalf("mode %d: c·t0 bound should be vacuous", m)
		}
	}
}

// Theorem: findHintToTarget(w', target) = (h, true) implies
// UseHint(h, w') = target coefficient-wise. The hint bit is validated via
// FIPS UseHint, never an informal ±1 corrector.
func TestFindHintToTargetMatchesUseHint(t *testing.T) {
	gamma2, _, omega, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	rng := rand.New(rand.NewSource(2))
	checked := 0
	for iter := 0; iter < 3000; iter++ {
		wPrime := randPolyVec(rng, k)
		// Build a reachable, omega-sparse target like a real ML-DSA hint:
		// baseline all h=0 (HighBits), then flip up to omega coefficients to
		// the h=1 result.
		target := highBitsVec(wPrime, gamma2)
		nflip := rng.Intn(int(omega) + 1)
		for f := 0; f < nflip; f++ {
			i := rng.Intn(k)
			j := rng.Intn(mldsaN)
			target[i][j] = useHint(1, wPrime[i][j], gamma2)
		}
		h, ok := findHintToTarget(wPrime, target, gamma2, omega)
		if !ok {
			continue // weight > omega for random targets; skip
		}
		checked++
		for i := 0; i < k; i++ {
			for j := 0; j < mldsaN; j++ {
				if useHint(h[i][j], wPrime[i][j], gamma2) != target[i][j] {
					t.Fatalf("UseHint(h,w') != target at [%d][%d]", i, j)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no reachable targets exercised")
	}
	t.Logf("verified UseHint(findHintToTarget(w',t),w')==t on %d vectors", checked)
}

// Core BCC+ lemma (debug oracle): a boundary-clear w keeps HighBits stable
// under every hidden ||c·s2||_inf <= beta shift, and the hidden r0 stays in
// the FIPS rejection range — without the protocol ever forming c·s2 or r0.
func TestBoundaryClearImpliesHighBitsStable(t *testing.T) {
	gamma2, beta, _, ok := bccParams(ModeP65)
	if !ok {
		t.Fatal("P65 params")
	}
	k, _, _ := modeShape(ModeP65)
	rng := rand.New(rand.NewSource(1))
	cleared := 0
	for iter := 0; iter < 4000; iter++ {
		w := randPolyVec(rng, k)
		if !BoundaryClear(w, gamma2, beta) {
			continue
		}
		cleared++
		hb0 := highBitsVec(w, gamma2)
		for i := 0; i < k; i++ {
			for j := 0; j < mldsaN; j++ {
				delta := int32(rng.Intn(int(2*beta+1))) - int32(beta) // [-beta, beta]
				shifted := subMod(w[i][j], delta)
				if highBitsCoeff(shifted, gamma2) != hb0[i][j] {
					t.Fatalf("HighBits moved under |c·s2|<=beta on boundary-clear w [%d][%d]", i, j)
				}
				r0 := centeredLowBits(shifted, gamma2)
				if r0 < 0 {
					r0 = -r0
				}
				if uint32(r0) >= gamma2-beta {
					t.Fatalf("hidden r0 bound violated on boundary-clear w [%d][%d]", i, j)
				}
			}
		}
	}
	if cleared == 0 {
		t.Fatal("no boundary-clear nonces sampled")
	}
	t.Logf("verified HighBits-stable + r0-bound on %d boundary-clear nonces", cleared)
}

// Exact off-by-one audit of the 2β margin against FIPS Decompose.
func TestBoundaryClearEdgeCases(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	thr := int32(boundaryThreshold(gamma2, beta)) // gamma2 - 2*beta
	mk := func(a0 int32) uint32 {                 // coefficient with centered low bits a0 in bucket 1
		v := (int64(2*gamma2) + int64(a0)) % mldsaQ
		if v < 0 {
			v += mldsaQ
		}
		return uint32(v)
	}
	cases := []struct {
		a0   int32
		want bool
	}{
		{thr - 1, true}, {thr, false}, {thr + 1, false},
		{-(thr - 1), true}, {-thr, false}, {-(thr + 1), false},
		{0, true},
	}
	for _, c := range cases {
		a := mk(c.a0)
		if got := centeredLowBits(a, gamma2); got != c.a0 {
			t.Fatalf("centeredLowBits(mk(%d))=%d", c.a0, got)
		}
		if got := boundaryClearCoeff(a, gamma2, beta); got != c.want {
			t.Fatalf("boundaryClearCoeff(a0=%d)=%v want %v (thr=%d)", c.a0, got, c.want, thr)
		}
	}
}

// Measure the real offline boundary-clearance yield for ML-DSA-65.
func TestBoundaryClearanceYield(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	rng := rand.New(rand.NewSource(3))
	const trials = 3000
	clear := 0
	for i := 0; i < trials; i++ {
		if BoundaryClear(randPolyVec(rng, k), gamma2, beta) {
			clear++
		}
	}
	yield := float64(clear) / trials
	t.Logf("ML-DSA-65 boundary-clear yield (margin 2β=%d, γ2=%d): %.4f", 2*beta, gamma2, yield)
	if yield < 0.03 || yield > 0.25 {
		t.Fatalf("yield %.4f outside expected ~0.10 band", yield)
	}
}
