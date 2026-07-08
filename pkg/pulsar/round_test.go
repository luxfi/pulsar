package pulsar

import (
	"math"
	"testing"
)

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

// TestCanonicalSignerSet_RejectsOversizedPartyID is the Item7(a) library-side
// defense-in-depth lock: a Partial naming a PartyID above MaxCanonicalPartyID
// must be rejected with ErrPartyIDOutOfRange BEFORE any PartyID-sized bitmap
// allocation. Prior to this the bitmap was make([]byte, maxID/8+1) with maxID
// straight from an attacker-controlled uint32 — a single MaxUint32 sized a
// ~512MiB allocation.
func TestCanonicalSignerSet_RejectsOversizedPartyID(t *testing.T) {
	mk := func(ids ...uint32) []Partial {
		ps := make([]Partial, len(ids))
		for i, id := range ids {
			ps[i] = Partial{PartyID: id, ZShare: []byte{byte(id)}}
		}
		return ps
	}

	// Hostile PartyID == MaxUint32 among legitimate small IDs.
	if _, _, err := CanonicalSignerSet(mk(1, 2, math.MaxUint32), 2); err != ErrPartyIDOutOfRange {
		t.Fatalf("expected ErrPartyIDOutOfRange for PartyID=MaxUint32, got %v", err)
	}

	// Rejected even when the oversized PartyID would be excluded from the
	// chosen (smallest-threshold) subset — the whole valid slice is checked.
	if _, _, err := CanonicalSignerSet(mk(1, 2, 3, 4, math.MaxUint32), 2); err != ErrPartyIDOutOfRange {
		t.Fatalf("expected ErrPartyIDOutOfRange even when oversized PartyID is excluded from chosen, got %v", err)
	}

	// Exactly at the cap is out of range (valid indices are [0, cap)).
	if _, _, err := CanonicalSignerSet(mk(0, 1, MaxCanonicalPartyID), 2); err != ErrPartyIDOutOfRange {
		t.Fatalf("expected ErrPartyIDOutOfRange for PartyID==MaxCanonicalPartyID, got %v", err)
	}

	// Just below the cap is accepted, and the resulting bitmap is bounded
	// to at most 128 KiB (never the ~512MiB an unbounded uint32 would give).
	chosen, bitmap, err := CanonicalSignerSet(mk(1, MaxCanonicalPartyID-1), 2)
	if err != nil {
		t.Fatalf("PartyID just below the cap must be accepted, got %v", err)
	}
	if len(chosen) != 2 {
		t.Fatalf("expected 2 chosen, got %d", len(chosen))
	}
	if len(bitmap) > MaxCanonicalPartyID/8+1 {
		t.Fatalf("bitmap length %d exceeds the MaxCanonicalPartyID ceiling", len(bitmap))
	}
}
