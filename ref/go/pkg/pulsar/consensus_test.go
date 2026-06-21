package pulsar

import (
	"math/rand"
	"testing"
)

// Production wire types must carry no hint-secret field (PULSAR-V13).
func TestNoHintSecretFieldsInProductionWireTypes(t *testing.T) {
	for _, typ := range productionWireTypes() {
		if name, bad := typeHasForbiddenField(typ); bad {
			t.Fatalf("production wire type %s carries forbidden hint-secret field %q",
				typ.Name(), name)
		}
	}
}

// Nonce selection is deterministic per session (non-grindable) and in range.
func TestCanonicalNonceSelection(t *testing.T) {
	var sid, root [32]byte
	sid[0], root[0] = 1, 2
	a := CanonicalNonceIndex(sid, root, 1000)
	if a != CanonicalNonceIndex(sid, root, 1000) {
		t.Fatal("nonce selection must be deterministic for a session")
	}
	if a >= 1000 {
		t.Fatalf("index %d out of range", a)
	}
	// changing the session changes the index input (range still enforced)
	sid2 := sid
	sid2[1] = 9
	if b := CanonicalNonceIndex(sid2, root, 1000); b >= 1000 {
		t.Fatalf("index %d out of range", b)
	}
}

// Tree aggregation equals flat aggregation, up to a 1000-signer committee.
func TestTreeAggregateEqualsFlat(t *testing.T) {
	_, l, _ := modeShape(ModeP65)
	rng := rand.New(rand.NewSource(7))
	for _, n := range []int{1, 2, 3, 7, 16, 100, 1000} {
		shares := make([]polyVec, n)
		for i := range shares {
			shares[i] = randPolyVec(rng, l)
		}
		flat := FlatAggregateZ(shares, l)
		tree := TreeAggregateZ(shares, l)
		for i := 0; i < l; i++ {
			for j := 0; j < mldsaN; j++ {
				if flat[i][j] != tree[i][j] {
					t.Fatalf("tree != flat at n=%d [%d][%d]", n, i, j)
				}
			}
		}
	}
}

// ---- shared debug quorum-signature verifier (test-only) ----
//
// The real validator-set signature verifier is registered by the consensus
// layer. For unit tests we register a debug verifier that structurally checks
// the QC (right payload root, one non-empty signature per set bit). It does NOT
// perform real signature crypto — it stands in for the registered seam so the
// fail-closed default and the binding logic can both be exercised.
type debugQuorumSig struct{}

func (debugQuorumSig) VerifyQuorum(root [32]byte, qc QuorumCert) error {
	if qc.PayloadRoot != root {
		return ErrBadClearanceQC
	}
	if bitmapWeight(qc.SignerBitmap) != len(qc.Signatures) {
		return ErrBadClearanceQC
	}
	for _, s := range qc.Signatures {
		if len(s) == 0 {
			return ErrBadClearanceQC
		}
	}
	return nil
}

// useDebugQuorumSig installs the debug verifier for the duration of a test and
// restores the previous (default fail-closed) verifier afterward.
func useDebugQuorumSig(t *testing.T) {
	t.Helper()
	prev := registeredQuorumSigVerifier
	registeredQuorumSigVerifier = debugQuorumSig{}
	t.Cleanup(func() { registeredQuorumSigVerifier = prev })
}

// debugSigs returns one non-empty stand-in signature per set bit in bitmap.
func debugSigs(bitmap []byte) [][]byte {
	out := make([][]byte, bitmapWeight(bitmap))
	for i := range out {
		out[i] = []byte{1}
	}
	return out
}

// Two-certificate accountability: quorum + signer-set membership + the bitmap
// is cryptographically bound to the signature via the accountability QC.
func TestConsensusCertAccountability(t *testing.T) {
	useDebugQuorumSig(t)
	mk := func(bitmap []byte) *ConsensusCert {
		c := &ConsensusCert{
			Epoch:        1,
			Height:       2,
			Round:        3,
			SignerBitmap: append([]byte{}, bitmap...),
			Signature:    Signature{Mode: ModeP65, Bytes: []byte("joint-sig")},
		}
		root := consensusCertPayloadRoot(c)
		c.AccountabilityQC = QuorumCert{
			SignerBitmap: append([]byte{}, bitmap...),
			PayloadRoot:  root,
			Signatures:   debugSigs(bitmap),
		}
		return c
	}

	ok := mk([]byte{0b00011111}) // bits 0..4, weight 5
	if err := ok.Verify(5, 8); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if err := ok.Verify(6, 8); err != ErrQuorumNotMet {
		t.Fatalf("expected quorum-not-met, got %v", err)
	}
	oob := mk([]byte{0b10011111}) // bit 7 set
	if err := oob.Verify(5, 7); err != ErrSignerOutOfSet {
		t.Fatalf("expected out-of-set, got %v", err)
	}

	// Accountability forgery: rewrite the signer bitmap after the QC is
	// formed. The QC's payload root no longer matches → rejected.
	forged := mk([]byte{0b00011111})
	forged.SignerBitmap = []byte{0b00111110} // frame a different validator set
	if err := forged.Verify(5, 8); err != ErrBitmapNotAttested {
		t.Fatalf("bitmap forgery not detected: got %v", err)
	}

	// Splicing a different signature under the same accountability QC also
	// breaks the binding.
	spliced := mk([]byte{0b00011111})
	spliced.Signature.Bytes = []byte("other-sig")
	if err := spliced.Verify(5, 8); err != ErrBitmapNotAttested {
		t.Fatalf("signature splice not detected: got %v", err)
	}
}

// With no validator-set verifier registered, a structurally-valid cert still
// fails closed.
func TestConsensusCertFailsClosedWithoutQuorumVerifier(t *testing.T) {
	bitmap := []byte{0b00011111}
	c := &ConsensusCert{Epoch: 1, SignerBitmap: bitmap, Signature: Signature{Mode: ModeP65, Bytes: []byte("s")}}
	c.AccountabilityQC = QuorumCert{SignerBitmap: bitmap, Signatures: debugSigs(bitmap)}
	c.AccountabilityQC.PayloadRoot = consensusCertPayloadRoot(c)
	if err := c.Verify(5, 8); err != ErrQuorumSigVerifierUnregistered {
		t.Fatalf("expected fail-closed without a registered verifier, got %v", err)
	}
}

// Abort classes are coarse (no per-signer / per-coefficient detail).
func TestAbortClassesCoarse(t *testing.T) {
	for _, a := range []AbortClass{AbortRetry, AbortBadPartialProof, AbortBadCommitment, AbortReplay} {
		if s := a.String(); s == "" || s == "ABORT_NONE" {
			t.Fatalf("abort class %d has no coarse label", a)
		}
	}
}
