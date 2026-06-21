package pulsar

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
)

func hasFieldNamed(t reflect.Type, name string) bool {
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Name == name {
			return true
		}
	}
	return false
}

func boundaryClearW(rng *rand.Rand, k int, gamma2, beta uint32) polyVec {
	for {
		w := randPolyVec(rng, k)
		if BoundaryClear(w, gamma2, beta) {
			return w
		}
	}
}

// The production cert carries w1 + clearance QC, never full w.
func TestBoundaryNonceCertHasNoFullW(t *testing.T) {
	typ := reflect.TypeOf(BoundaryNonceCert{})
	for _, f := range []string{"W", "FullW", "WPolyVec", "LowBitsW", "BoundaryDistance", "R0", "CS2", "CT0", "D2", "D0"} {
		if hasFieldNamed(typ, f) {
			t.Fatalf("BoundaryNonceCert contains forbidden field %q", f)
		}
	}
	for _, f := range []string{"W1", "CommitRoot", "RegionRoot", "MPCTranscriptRoot", "ClearanceQC"} {
		if !hasFieldNamed(typ, f) {
			t.Fatalf("BoundaryNonceCert missing required field %q", f)
		}
	}
}

func TestBoundaryNonceCertRequiresClearanceQC(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(11)), k, gamma2, beta)
	cert, _ := RunNonceMPCDebug(w, ModeP65, [32]byte{1})
	cert.ClearanceQC = QuorumCert{} // strip the QC
	if err := VerifyBoundaryNonceCert(cert, 5, 8); err != ErrMissingClearanceQC {
		t.Fatalf("expected missing-QC, got %v", err)
	}
}

func TestBoundaryNonceCertBindsAllConsensusFields(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(12)), k, gamma2, beta)
	base, _ := RunNonceMPCDebug(w, ModeP65, [32]byte{2})
	if err := VerifyBoundaryNonceCert(base, 5, 8); err != nil {
		t.Fatalf("base cert should verify, got %v", err)
	}
	mutations := []func(*BoundaryNonceCert){
		func(c *BoundaryNonceCert) { c.PKEpoch++ },
		func(c *BoundaryNonceCert) { c.CommitteeID[0] ^= 1 },
		func(c *BoundaryNonceCert) { c.SignerSetRoot[0] ^= 1 },
		func(c *BoundaryNonceCert) { c.CommitRoot[0] ^= 1 },
		func(c *BoundaryNonceCert) { c.RegionRoot[0] ^= 1 },
		func(c *BoundaryNonceCert) { c.MPCTranscriptRoot[0] ^= 1 },
		func(c *BoundaryNonceCert) { c.Margin++ },
		func(c *BoundaryNonceCert) { c.W1[0] ^= 1 },
	}
	for i, mut := range mutations {
		bad := *base
		bad.W1 = append([]byte{}, base.W1...)
		mut(&bad)
		if err := VerifyBoundaryNonceCert(&bad, 5, 8); err == nil {
			t.Fatalf("mutation %d not detected (QC must bind all fields)", i)
		}
	}
}

func TestNonceMPCDoesNotRevealW(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(13)), k, gamma2, beta)
	_, tr := RunNonceMPCDebug(w, ModeP65, [32]byte{3})
	fullW := packPolyVec(w)
	if bytes.Contains(tr.PublicView(), fullW) {
		t.Fatal("NonceMPC public view leaks full w")
	}
	// low bits must not appear either
	low := make(polyVec, k)
	for i := 0; i < k; i++ {
		for j := 0; j < mldsaN; j++ {
			low[i][j] = uint32(centeredLowBits(w[i][j], gamma2) + mldsaQ)
		}
	}
	if bytes.Contains(tr.PublicView(), packPolyVec(low)) {
		t.Fatal("NonceMPC public view leaks LowBits(w)")
	}
}

func TestNonceMPCOutputsCorrectW1_DebugOracle(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(14)), k, gamma2, beta)
	cert, _ := RunNonceMPCDebug(w, ModeP65, [32]byte{4})
	if !bytes.Equal(cert.W1, packPolyVec(highBitsVec(w, gamma2))) {
		t.Fatal("cert.W1 != HighBits(w)")
	}
}

func TestNonceMPCBoundaryClear_DebugOracle(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	rng := rand.New(rand.NewSource(15))
	// clear nonce → votable
	w := boundaryClearW(rng, k, gamma2, beta)
	_, tr := RunNonceMPCDebug(w, ModeP65, [32]byte{5})
	if !BoundaryClear(tr.debugFullW, gamma2, beta) || !tr.Clear {
		t.Fatal("clear nonce not flagged clear")
	}
	if _, err := ValidateAndVoteNonceCert(tr); err != nil {
		t.Fatalf("clear nonce should be votable, got %v", err)
	}
	// non-clear nonce → not votable
	var wbad polyVec
	for {
		wbad = randPolyVec(rng, k)
		if !BoundaryClear(wbad, gamma2, beta) {
			break
		}
	}
	_, trbad := RunNonceMPCDebug(wbad, ModeP65, [32]byte{6})
	if _, err := ValidateAndVoteNonceCert(trbad); err != ErrNonceNotBoundaryClear {
		t.Fatalf("non-clear nonce must not be votable, got %v", err)
	}
}

func TestNonceCertQCVerifies(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(16)), k, gamma2, beta)
	cert, _ := RunNonceMPCDebug(w, ModeP65, [32]byte{7})
	if err := VerifyBoundaryNonceCert(cert, 5, 8); err != nil {
		t.Fatalf("valid NonceMPC cert should verify, got %v", err)
	}
}

func TestBadNonceMPCTranscriptRootRejected(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(17)), k, gamma2, beta)
	cert, _ := RunNonceMPCDebug(w, ModeP65, [32]byte{8})
	cert.MPCTranscriptRoot[0] ^= 1 // tamper → payload root no longer matches the QC
	if err := VerifyBoundaryNonceCert(cert, 5, 8); err != ErrBadClearanceQC {
		t.Fatalf("tampered transcript root must be rejected, got %v", err)
	}
}

// Permanent proof of WHY full w is forbidden: publishing w + the public
// w' = A·z − c·t1·2^d reveals the secret residual Δ = c·t0 − c·s2.
func TestPublishingFullWWouldRevealResidual_DebugOracle(t *testing.T) {
	k, _, _ := modeShape(ModeP65)
	rng := rand.New(rand.NewSource(18))
	w := randPolyVec(rng, k)
	delta := make(polyVec, k) // a stand-in for c·t0 − c·s2
	for i := 0; i < k; i++ {
		for j := 0; j < mldsaN; j++ {
			delta[i][j] = uint32(rng.Int63n(mldsaQ))
		}
	}
	wPrime := addVecMod(w, delta) // public verifier value = w + Δ
	residual := subVecMod(wPrime, w)
	for i := 0; i < k; i++ {
		for j := 0; j < mldsaN; j++ {
			if residual[i][j] != delta[i][j] {
				t.Fatal("w' − w must equal the secret residual Δ (this is why w is forbidden)")
			}
		}
	}
}
