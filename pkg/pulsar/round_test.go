package pulsar

import "testing"

func TestCanonicalSignerSetDeterministicAndAntiGrind(t *testing.T) {
	mk := func(ids ...uint32) []Partial {
		ps := make([]Partial, len(ids))
		for i, id := range ids {
			ps[i] = Partial{PartyID: id, ZShare: []byte{byte(id)}}
		}
		return ps
	}
	// same valid set in different orders -> identical chosen subset + bitmap
	a, bmA, err := CanonicalSignerSet(mk(5, 2, 9, 1, 7), 3)
	if err != nil {
		t.Fatal(err)
	}
	b, bmB, _ := CanonicalSignerSet(mk(9, 7, 1, 5, 2), 3)
	if len(a) != 3 || a[0].PartyID != 1 || a[1].PartyID != 2 || a[2].PartyID != 5 {
		t.Fatalf("canonical set must be the first-threshold by PartyID, got %v %v %v", a[0].PartyID, a[1].PartyID, a[2].PartyID)
	}
	if string(bmA) != string(bmB) {
		t.Fatal("canonical bitmap must be order-independent (anti-grind)")
	}
	for i := range a {
		if a[i].PartyID != b[i].PartyID {
			t.Fatal("canonical subset must be deterministic regardless of input order")
		}
	}
	if _, _, err := CanonicalSignerSet(mk(1, 2), 3); err != ErrInsufficientSigners {
		t.Fatalf("below threshold must error, got %v", err)
	}
}
