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
func TestNonceCertHasNoFullW(t *testing.T) {
	typ := reflect.TypeOf(NonceCert{})
	for _, f := range []string{"W", "FullW", "WPolyVec", "LowBitsW", "BoundaryDistance", "R0", "CS2", "CT0", "D2", "D0"} {
		if hasFieldNamed(typ, f) {
			t.Fatalf("NonceCert contains forbidden field %q", f)
		}
	}
	for _, f := range []string{"W1", "CommitRoot", "RegionRoot", "NonceTranscriptRoot", "ClearanceQC"} {
		if !hasFieldNamed(typ, f) {
			t.Fatalf("NonceCert missing required field %q", f)
		}
	}
}

func TestNonceCertRequiresClearanceQC(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(11)), k, gamma2, beta)
	cert, _, err := RunNonceMPCDebug(w, ModeP65, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	cert.ClearanceQC = QuorumCert{} // strip the QC
	if err := VerifyNonceCert(cert, 5, 8); err != ErrMissingClearanceQC {
		t.Fatalf("expected missing-QC, got %v", err)
	}
}

func TestNonceCertBindsAllConsensusFields(t *testing.T) {
	useDebugQuorumSig(t)
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(12)), k, gamma2, beta)
	base, _, err := RunNonceMPCDebug(w, ModeP65, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNonceCert(base, 5, 8); err != nil {
		t.Fatalf("base cert should verify, got %v", err)
	}
	mutations := []func(*NonceCert){
		func(c *NonceCert) { c.PKEpoch++ },
		func(c *NonceCert) { c.CommitteeID[0] ^= 1 },
		func(c *NonceCert) { c.SignerSetRoot[0] ^= 1 },
		func(c *NonceCert) { c.CommitRoot[0] ^= 1 },
		func(c *NonceCert) { c.RegionRoot[0] ^= 1 },
		func(c *NonceCert) { c.NonceTranscriptRoot[0] ^= 1 },
		func(c *NonceCert) { c.Margin++ },
		func(c *NonceCert) { c.W1[0] ^= 1 },
		func(c *NonceCert) { c.WCommitment = []byte{9} }, // swappable hidden-w commitment
		func(c *NonceCert) { c.ClearanceProof = []byte{7} },
		func(c *NonceCert) { c.Consumed = !c.Consumed }, // anti-replay flag
	}
	for i, mut := range mutations {
		bad := *base
		bad.W1 = append([]byte{}, base.W1...)
		mut(&bad)
		if err := VerifyNonceCert(&bad, 5, 8); err == nil {
			t.Fatalf("mutation %d not detected (QC must bind all fields)", i)
		}
	}
}

func TestNonceMPCDoesNotRevealW(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(13)), k, gamma2, beta)
	_, tr, err := RunNonceMPCDebug(w, ModeP65, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
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
	cert, _, err := RunNonceMPCDebug(w, ModeP65, [32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
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
	_, tr, err := RunNonceMPCDebug(w, ModeP65, [32]byte{5})
	if err != nil {
		t.Fatal(err)
	}
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
	_, trbad, err := RunNonceMPCDebug(wbad, ModeP65, [32]byte{6})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAndVoteNonceCert(trbad); err != ErrNonceNotBoundaryClear {
		t.Fatalf("non-clear nonce must not be votable, got %v", err)
	}
}

func TestNonceCertQCVerifies(t *testing.T) {
	useDebugQuorumSig(t)
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(16)), k, gamma2, beta)
	cert, _, err := RunNonceMPCDebug(w, ModeP65, [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNonceCert(cert, 5, 8); err != nil {
		t.Fatalf("valid NonceMPC cert should verify, got %v", err)
	}
}

func TestBadNonceTranscriptRootRejected(t *testing.T) {
	useDebugQuorumSig(t)
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(17)), k, gamma2, beta)
	cert, _, err := RunNonceMPCDebug(w, ModeP65, [32]byte{8})
	if err != nil {
		t.Fatal(err)
	}
	cert.NonceTranscriptRoot[0] ^= 1 // tamper → payload root no longer matches the QC
	if err := VerifyNonceCert(cert, 5, 8); err != ErrBadClearanceQC {
		t.Fatalf("tampered transcript root must be rejected, got %v", err)
	}
}

// Out-of-scope parameter sets (e.g. ML-DSA-44, where ‖c·t0‖∞ < γ2 fails and
// boundary clearance is vacuous) are refused both at mint and at verify.
func TestNonceCertRefusesOutOfScopeMode(t *testing.T) {
	useDebugQuorumSig(t)
	k, _, _ := modeShape(ModeP65)
	w := make(polyVec, k) // shape only; the mode gate fires before any use
	if _, _, err := RunNonceMPCDebug(w, ModeP44, [32]byte{9}); err != ErrBCCParamSet {
		t.Fatalf("RunNonceMPCDebug must refuse ML-DSA-44, got %v", err)
	}
	// A hand-built cert claiming ML-DSA-44 must be refused even with an
	// otherwise well-formed QC.
	cert := &NonceCert{Mode: ModeP44}
	cert.ClearanceQC = QuorumCert{SignerBitmap: []byte{0xFF}, Signatures: debugSigs([]byte{0xFF})}
	cert.ClearanceQC.PayloadRoot = nonceCertPayloadRoot(cert)
	if err := VerifyNonceCert(cert, 5, 8); err != ErrBCCParamSet {
		t.Fatalf("VerifyNonceCert must refuse ML-DSA-44, got %v", err)
	}
}

// Without a registered validator-set verifier, a structurally-valid cert still
// fails closed (the QC signatures are never blindly trusted).
func TestNonceCertFailsClosedWithoutQuorumVerifier(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	k, _, _ := modeShape(ModeP65)
	w := boundaryClearW(rand.New(rand.NewSource(19)), k, gamma2, beta)
	cert, _, err := RunNonceMPCDebug(w, ModeP65, [32]byte{10})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNonceCert(cert, 5, 8); err != ErrQuorumSigVerifierUnregistered {
		t.Fatalf("expected fail-closed without a registered verifier, got %v", err)
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
