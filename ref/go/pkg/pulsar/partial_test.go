package pulsar

import (
	"bytes"
	"math/rand"
	"testing"
)

type acceptAllPartialZ struct{}

func (acceptAllPartialZ) VerifyPartial(*Partial, []byte, []byte, []byte) error { return nil }

func validZPartial() (*Partial, ZPartialPublicInput) {
	z := []byte{1, 2, 3, 4}
	p := &Partial{PartyID: 3, SessionID: [32]byte{9}, NonceID: [32]byte{7}, ZShare: z}
	in := ZPartialPublicInput{PartyID: 3, SessionID: [32]byte{9}, NonceID: [32]byte{7},
		Challenge: []byte{0xc}, DKGCommitment: []byte{0xd}, NonceCommitment: []byte{0xe}, ZShare: z}
	return p, in
}

func TestValidZPartialProofAccepted(t *testing.T) {
	old := registeredPartialZVerifier
	RegisterPartialZVerifier(acceptAllPartialZ{})
	defer func() { registeredPartialZVerifier = old }()
	p, in := validZPartial()
	if err := VerifyZPartial(p, in); err != nil {
		t.Fatalf("valid partial rejected: %v", err)
	}
}

func TestBadZShareRejected(t *testing.T) {
	old := registeredPartialZVerifier
	RegisterPartialZVerifier(acceptAllPartialZ{})
	defer func() { registeredPartialZVerifier = old }()
	p, in := validZPartial()
	p.ZShare = []byte{9, 9, 9, 9} // corrupted
	if err := VerifyZPartial(p, in); err != ErrBadZPartialProof {
		t.Fatalf("corrupt z-share must be rejected, got %v", err)
	}
}

func TestZPartialBindsSessionNoncePartyChallenge(t *testing.T) {
	old := registeredPartialZVerifier
	RegisterPartialZVerifier(acceptAllPartialZ{})
	defer func() { registeredPartialZVerifier = old }()
	for i, mut := range []func(*ZPartialPublicInput){
		func(in *ZPartialPublicInput) { in.SessionID[0] ^= 1 },
		func(in *ZPartialPublicInput) { in.NonceID[0] ^= 1 },
		func(in *ZPartialPublicInput) { in.PartyID++ },
	} {
		p, in := validZPartial()
		mut(&in)
		if err := VerifyZPartial(p, in); err == nil {
			t.Fatalf("binding mutation %d not detected", i)
		}
	}
}

func TestPartialZFailClosedByDefault(t *testing.T) {
	p, in := validZPartial()
	if err := VerifyZPartial(p, in); err != ErrPartialZProofUnsound {
		t.Fatalf("default partial-z verifier must fail closed, got %v", err)
	}
}

func aggWith(sid, nid [32]byte, bitmap []byte, z polyVec) Aggregate {
	return Aggregate{SessionID: sid, NonceID: nid, SignerBitmap: bitmap, ZSum: packPolyVec(z)}
}

func TestMergeAggregatesDuplicateAndSession(t *testing.T) {
	_, l, _ := modeShape(ModeP65)
	rng := rand.New(rand.NewSource(21))
	sid, nid := [32]byte{1}, [32]byte{2}
	a := aggWith(sid, nid, []byte{0b0001}, randPolyVec(rng, l))
	b := aggWith(sid, nid, []byte{0b0010}, randPolyVec(rng, l))
	if _, err := MergeAggregates([]Aggregate{a, b}, l); err != nil {
		t.Fatalf("disjoint merge should succeed: %v", err)
	}
	dup := aggWith(sid, nid, []byte{0b0001}, randPolyVec(rng, l)) // overlaps a
	if _, err := MergeAggregates([]Aggregate{a, dup}, l); err != ErrDuplicateSigner {
		t.Fatalf("duplicate signer must be rejected, got %v", err)
	}
	wrong := aggWith([32]byte{9}, nid, []byte{0b0100}, randPolyVec(rng, l))
	if _, err := MergeAggregates([]Aggregate{a, wrong}, l); err != ErrWrongSessionAgg {
		t.Fatalf("wrong session must be rejected, got %v", err)
	}
}

func TestMergeAggregatesSumsZ(t *testing.T) {
	_, l, _ := modeShape(ModeP65)
	rng := rand.New(rand.NewSource(22))
	sid, nid := [32]byte{3}, [32]byte{4}
	z1, z2 := randPolyVec(rng, l), randPolyVec(rng, l)
	merged, err := MergeAggregates([]Aggregate{
		aggWith(sid, nid, []byte{0b0001}, z1),
		aggWith(sid, nid, []byte{0b0010}, z2),
	}, l)
	if err != nil {
		t.Fatal(err)
	}
	want := FlatAggregateZ([]polyVec{z1, z2}, l)
	if !bytes.Equal(merged.ZSum, packPolyVec(want)) {
		t.Fatal("merged ZSum != flat sum")
	}
}

func TestNoT0InProductionDKGTypes(t *testing.T) {
	for _, typ := range productionDKGTypes() {
		for _, f := range []string{"T0", "T0Share", "S2", "S2Share", "S2Correction", "FullT", "MasterSecret", "S1Master", "S2Master", "T0Master"} {
			if hasFieldNamed(typ, f) {
				t.Fatalf("%s has forbidden DKG field %q", typ.Name(), f)
			}
		}
	}
}
