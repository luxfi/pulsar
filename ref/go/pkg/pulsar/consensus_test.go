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

// Two-certificate accountability: quorum + signer-set membership.
func TestConsensusCertStructure(t *testing.T) {
	ok := &ConsensusCert{SignerBitmap: []byte{0b00011111}} // bits 0..4, weight 5
	if err := ok.VerifyStructure(5, 8); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if err := ok.VerifyStructure(6, 8); err != ErrQuorumNotMet {
		t.Fatalf("expected quorum-not-met, got %v", err)
	}
	oob := &ConsensusCert{SignerBitmap: []byte{0b10011111}} // bit 7 set
	if err := oob.VerifyStructure(5, 7); err != ErrSignerOutOfSet {
		t.Fatalf("expected out-of-set, got %v", err)
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
