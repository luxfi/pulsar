// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"testing"
)

// TestRefreshPreservesSecret — the core HJKY97 invariant: a Refresh
// round leaves the master secret unchanged but rotates every share.
//
// We build (t, n)-Shamir shares of a planted secret, run Refresh, and
// verify:
//
//   1. Old shares interpolate to the planted secret.
//   2. New shares interpolate to the SAME planted secret.
//   3. New shares ≠ old shares (Hamming/byte distance positive — the
//      probability all coordinates collide is < 2^-48 per coordinate
//      times nVec*N coordinates ≈ 2^-48 * 7 * 256 ≈ negligible).
//
// This is the canonical test that proves Refresh implements the
// HJKY97 zero-polynomial pattern correctly.
func TestRefreshPreservesSecret(t *testing.T) {
	r := canonicalRing(t)

	const tThr, n = 3, 5
	secret := pickSecret(r, "refresh-preserve", testNVec)
	rs := newFakeRand([]byte("refresh-old-shamir"))
	oldShares, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: old shares interpolate to secret.
	rec, err := Verify(r, oldShares, tThr)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec, secret) {
		t.Fatal("old shares do not reconstruct the planted secret")
	}

	// Refresh.
	newShares, err := Refresh(r, oldShares, tThr, newFakeRand([]byte("refresh-z-rng")))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(newShares) != len(oldShares) {
		t.Fatalf("expected %d new shares, got %d", len(oldShares), len(newShares))
	}

	// Same committee → same party IDs as keys.
	for id := range oldShares {
		if _, ok := newShares[id]; !ok {
			t.Fatalf("new shares missing party %d", id)
		}
	}

	// New shares interpolate to the SAME secret.
	rec2, err := Verify(r, newShares, tThr)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec2, secret) {
		t.Fatal("REFRESH BROKE THE SECRET — refreshed shares interpolate to a different value")
	}

	// New shares are different from old shares (this is the WHOLE
	// POINT of Refresh).
	differingParties := 0
	for id, oldS := range oldShares {
		if !bytes.Equal(uint64sToBytes(flattenShare(oldS)), uint64sToBytes(flattenShare(newShares[id]))) {
			differingParties++
		}
	}
	if differingParties != n {
		t.Fatalf("Refresh did not rotate every share: only %d/%d parties have new bytes", differingParties, n)
	}
}

// TestRefreshDeterminism — same RNG stream produces byte-identical
// refreshed shares. Foundation for the C++ KAT.
func TestRefreshDeterminism(t *testing.T) {
	r := canonicalRing(t)
	const tThr, n = 3, 5
	secret := pickSecret(r, "refresh-det", testNVec)
	rs := newFakeRand([]byte("refresh-det-old"))
	oldShares, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	a, err := Refresh(r, oldShares, tThr, newFakeRand([]byte("refresh-det-z")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Refresh(r, oldShares, tThr, newFakeRand([]byte("refresh-det-z")))
	if err != nil {
		t.Fatal(err)
	}
	for id := range oldShares {
		ah := uint64sToBytes(flattenShare(a[id]))
		bh := uint64sToBytes(flattenShare(b[id]))
		if !bytes.Equal(ah, bh) {
			t.Fatalf("party %d: non-deterministic Refresh output", id)
		}
	}
}

// TestRefreshThreshold1 — degenerate t=1 case: every share IS the
// secret. Refresh must be the identity (no zero-polynomial of degree
// 0 can be non-trivial while satisfying z(0) = 0).
func TestRefreshThreshold1(t *testing.T) {
	r := canonicalRing(t)
	const tThr, n = 1, 3
	secret := pickSecret(r, "refresh-t1", testNVec)
	// With t=1, every share equals secret directly (every party holds
	// the secret).
	shares := make(map[int]Share, n)
	for j := 1; j <= n; j++ {
		v := make(Share, testNVec)
		for p := 0; p < testNVec; p++ {
			v[p] = r.NewPoly()
			copy(v[p].Coeffs[0], secret[p].Coeffs[0])
		}
		shares[j] = v
	}

	out, err := Refresh(r, shares, tThr, newFakeRand([]byte("t1-rng")))
	if err != nil {
		t.Fatal(err)
	}
	for id, in := range shares {
		want := flattenShare(in)
		got := flattenShare(out[id])
		if !bytes.Equal(uint64sToBytes(want), uint64sToBytes(got)) {
			t.Fatalf("party %d: Refresh with t=1 should be identity", id)
		}
	}
}

// TestRefreshComposes_RereshareIdempotent — running Refresh repeatedly
// preserves the secret and rotates each round.
func TestRefreshCompositionInvariant(t *testing.T) {
	r := canonicalRing(t)
	const tThr, n = 3, 5
	secret := pickSecret(r, "refresh-compose", testNVec)
	rs := newFakeRand([]byte("compose-old"))
	current, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	for round := 0; round < 4; round++ {
		next, err := Refresh(r, current, tThr,
			newFakeRand([]byte{byte(round)}))
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		rec, err := Verify(r, next, tThr)
		if err != nil {
			t.Fatal(err)
		}
		if !equalSecrets(rec, secret) {
			t.Fatalf("round %d: secret drifted", round)
		}
		current = next
	}
}

// TestRefreshInvalidArgs — error paths for Refresh.
func TestRefreshInvalidArgs(t *testing.T) {
	r := canonicalRing(t)
	const tThr, n = 3, 5
	secret := pickSecret(r, "refresh-invalid", 2)
	rs := newFakeRand([]byte("refresh-invalid-rng"))
	good, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		fn     func() error
		errMsg string
	}{
		{
			"threshold < 1",
			func() error {
				_, err := Refresh(r, good, 0, newFakeRand([]byte("r")))
				return err
			},
			"t_old must be >= 1",
		},
		{
			"empty shares",
			func() error {
				_, err := Refresh(r, map[int]Share{}, 1, newFakeRand([]byte("r")))
				return err
			},
			"no old shares",
		},
		{
			"threshold larger than committee",
			func() error {
				_, err := Refresh(r, good, 99, newFakeRand([]byte("r")))
				return err
			},
			"fewer than t_old shares",
		},
		{
			"zero ID",
			func() error {
				bad := map[int]Share{0: good[1]}
				_, err := Refresh(r, bad, 1, newFakeRand([]byte("r")))
				return err
			},
			"1-indexed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errMsg)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.errMsg)) {
				t.Fatalf("expected error containing %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}

// TestRefreshComposesWithReshare — Refresh then Reshare must still
// preserve the secret, and Reshare then Refresh must do the same.
// This proves the two primitives compose correctly (which Quasar
// relies on: between validator-set rotations the chain may run
// Refresh as a periodic background hygiene step).
func TestRefreshComposesWithReshare(t *testing.T) {
	r := canonicalRing(t)
	const tOld, nOld = 3, 5
	secret := pickSecret(r, "refresh-then-reshare", testNVec)
	rs := newFakeRand([]byte("compose-rt-old"))
	original, err := makeStandardShamirShares(r, secret, tOld, nOld, rs)
	if err != nil {
		t.Fatal(err)
	}

	// Refresh first (same committee).
	refreshed, err := Refresh(r, original, tOld, newFakeRand([]byte("refresh-z")))
	if err != nil {
		t.Fatal(err)
	}
	rec1, err := Verify(r, refreshed, tOld)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec1, secret) {
		t.Fatal("Refresh leg lost the secret")
	}

	// Reshare onto a new committee.
	const tNew = 4
	newSet := []int{20, 21, 22, 23, 24, 25, 26}
	reshared, err := Reshare(r, refreshed, tOld, newSet, tNew,
		newFakeRand([]byte("reshare-rng")))
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := Verify(r, reshared, tNew)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec2, secret) {
		t.Fatal("Reshare-after-Refresh lost the secret")
	}

	// Now reverse: Reshare first, then Refresh on the new committee.
	reshared2, err := Reshare(r, original, tOld, newSet, tNew,
		newFakeRand([]byte("reshare-rng-2")))
	if err != nil {
		t.Fatal(err)
	}
	refreshed2, err := Refresh(r, reshared2, tNew, newFakeRand([]byte("refresh-after-reshare")))
	if err != nil {
		t.Fatal(err)
	}
	rec3, err := Verify(r, refreshed2, tNew)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec3, secret) {
		t.Fatal("Refresh-after-Reshare lost the secret")
	}
}
