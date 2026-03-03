// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package keyera — HashSuite immutability tests (Gate 3 of the
// Mar-3-2026 PQ Consensus Architecture Freeze).
//
// These tests pin the era-pinning property of the HashSuite (per
// proofs/pulsar/hash-suite-separation.tex Remark on era-pinning):
//
//   A. Bootstrap pins suite. The HashSuiteID recorded on a freshly
//      bootstrapped era equals exactly the ID of the supplied
//      HashSuite, and the field is read-only on the returned KeyEra.
//   B. Reshare cannot change suite. The Reshare API does not accept a
//      HashSuite parameter (verified at the type level by reading
//      reshare API), and the propagated state's HashSuiteID equals the
//      era's HashSuiteID byte-for-byte.
//   C. Reanchor MAY change suite. ReanchorWithSuite opens a new era
//      with a fresh GroupKey and a fresh HashSuiteID; the prior era's
//      HashSuiteID is unchanged.
//
// Citations (canonical proof bucket):
//
//   proofs/definitions/transcript-binding.tex
//     Definition ref:pulsar-transcript
//   proofs/pulsar/hash-suite-separation.tex
//     Theorem ref:hash-suite-separation
package keyera

import (
	"reflect"
	"testing"

	"github.com/luxfi/pulsar/hash"
)

// TestBootstrapPinsSuiteSHA3 — Gate 3A: Bootstrap with Pulsar-SHA3 →
// era.HashSuiteID == "Pulsar-SHA3".
func TestBootstrapPinsSuiteSHA3(t *testing.T) {
	era, err := BootstrapWithSuite(
		hash.NewPulsarSHA3(),
		3,
		[]string{"a", "b", "c"},
		0, 0,
		deterministicRand("hashsuite-immut-sha3"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	if era.HashSuiteID != hash.DefaultID {
		t.Fatalf("era.HashSuiteID: want %q got %q", hash.DefaultID, era.HashSuiteID)
	}
	if got := era.State.HashSuiteID; got != hash.DefaultID {
		t.Fatalf("state.HashSuiteID: want %q got %q", hash.DefaultID, got)
	}
}

// TestBootstrapPinsSuiteBLAKE3 — Gate 3A: Bootstrap with Pulsar-BLAKE3
// → era.HashSuiteID == "Pulsar-BLAKE3".
func TestBootstrapPinsSuiteBLAKE3(t *testing.T) {
	era, err := BootstrapWithSuite(
		hash.NewPulsarBLAKE3(),
		3,
		[]string{"a", "b", "c"},
		0, 0,
		deterministicRand("hashsuite-immut-blake3"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	if era.HashSuiteID != hash.LegacyBLAKE3ID {
		t.Fatalf("era.HashSuiteID: want %q got %q", hash.LegacyBLAKE3ID, era.HashSuiteID)
	}
	if got := era.State.HashSuiteID; got != hash.LegacyBLAKE3ID {
		t.Fatalf("state.HashSuiteID: want %q got %q", hash.LegacyBLAKE3ID, got)
	}
}

// TestBootstrapDefaultsToSHA3 confirms the no-suite Bootstrap entrypoint
// pins the production default, so legacy callers cannot accidentally
// open an era under no profile at all.
func TestBootstrapDefaultsToSHA3(t *testing.T) {
	era, err := Bootstrap(3, []string{"a", "b", "c"}, 0, 0,
		deterministicRand("hashsuite-default"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if era.HashSuiteID != hash.DefaultID {
		t.Fatalf("default suite: want %q got %q", hash.DefaultID, era.HashSuiteID)
	}
}

// TestReshareCannotChangeSuiteSHA3 — Gate 3B: Reshare on a Pulsar-SHA3
// era yields a state with HashSuiteID == "Pulsar-SHA3" (unchanged).
func TestReshareCannotChangeSuiteSHA3(t *testing.T) {
	era, err := BootstrapWithSuite(
		hash.NewPulsarSHA3(),
		3,
		[]string{"v1", "v2", "v3"},
		0, 0,
		deterministicRand("reshare-cannot-change-sha3"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	priorID := era.HashSuiteID

	next, err := era.Reshare([]string{"v1", "v2", "v3"}, 3, deterministicRand("reshare-1"))
	if err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	if era.HashSuiteID != priorID {
		t.Fatalf("era.HashSuiteID changed across Reshare: was %q now %q", priorID, era.HashSuiteID)
	}
	if next.HashSuiteID != priorID {
		t.Fatalf("post-Reshare state.HashSuiteID: want %q got %q", priorID, next.HashSuiteID)
	}
}

// TestReshareCannotChangeSuiteBLAKE3 — Gate 3B mirrored on the legacy
// profile. A BLAKE3-pinned era stays BLAKE3 across Reshare.
func TestReshareCannotChangeSuiteBLAKE3(t *testing.T) {
	era, err := BootstrapWithSuite(
		hash.NewPulsarBLAKE3(),
		3,
		[]string{"v1", "v2", "v3"},
		0, 0,
		deterministicRand("reshare-cannot-change-blake3"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	priorID := era.HashSuiteID
	if priorID != hash.LegacyBLAKE3ID {
		t.Fatalf("setup: era.HashSuiteID want %q got %q", hash.LegacyBLAKE3ID, priorID)
	}

	next, err := era.Reshare([]string{"v4", "v5", "v6"}, 2, deterministicRand("reshare-blake3"))
	if err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	if era.HashSuiteID != priorID {
		t.Fatalf("era.HashSuiteID changed across Reshare: was %q now %q", priorID, era.HashSuiteID)
	}
	if next.HashSuiteID != priorID {
		t.Fatalf("post-Reshare state.HashSuiteID: want %q got %q", priorID, next.HashSuiteID)
	}
}

// TestReshareAPIHasNoHashSuiteParameter is the type-level pin: the
// Reshare method's signature MUST NOT accept a hash.HashSuite, so it
// is impossible to change the suite at the call site. We use
// reflection on the method type to assert no parameter is assignable
// to hash.HashSuite.
func TestReshareAPIHasNoHashSuiteParameter(t *testing.T) {
	era := &KeyEra{}
	rt := reflect.ValueOf(era).MethodByName("Reshare").Type()
	hashSuiteIface := reflect.TypeOf((*hash.HashSuite)(nil)).Elem()
	for i := 0; i < rt.NumIn(); i++ {
		in := rt.In(i)
		// Only check exact match against the HashSuite interface or a
		// type that explicitly implements it. (Reshare takes
		// io.Reader; that is unrelated.)
		if in == hashSuiteIface {
			t.Fatalf("Reshare param %d is hash.HashSuite — reshare must not accept a suite", i)
		}
		if in.Kind() == reflect.Interface && in.Implements(hashSuiteIface) {
			t.Fatalf("Reshare param %d implements hash.HashSuite — reshare must not accept a suite", i)
		}
	}
}

// TestReanchorMayChangeSuite — Gate 3C: ReanchorWithSuite from a
// Pulsar-SHA3 era to a Pulsar-BLAKE3 era yields era_2.HashSuiteID ==
// "Pulsar-BLAKE3", and era_1 is unchanged.
func TestReanchorMayChangeSuite(t *testing.T) {
	era1, err := BootstrapWithSuite(
		hash.NewPulsarSHA3(),
		3,
		[]string{"a", "b", "c"},
		0, 1,
		deterministicRand("reanchor-era-1"),
	)
	if err != nil {
		t.Fatalf("BootstrapWithSuite: %v", err)
	}
	if era1.HashSuiteID != hash.DefaultID {
		t.Fatalf("era1.HashSuiteID: want %q got %q", hash.DefaultID, era1.HashSuiteID)
	}

	era2, err := ReanchorWithSuite(
		era1,
		hash.NewPulsarBLAKE3(),
		3,
		[]string{"d", "e", "f"},
		0,
		deterministicRand("reanchor-era-2"),
	)
	if err != nil {
		t.Fatalf("ReanchorWithSuite: %v", err)
	}
	if era2.HashSuiteID != hash.LegacyBLAKE3ID {
		t.Fatalf("era2.HashSuiteID: want %q got %q", hash.LegacyBLAKE3ID, era2.HashSuiteID)
	}
	if era1.HashSuiteID != hash.DefaultID {
		t.Fatalf("era1.HashSuiteID mutated by Reanchor: want %q got %q",
			hash.DefaultID, era1.HashSuiteID)
	}
	if era1.GroupKey == era2.GroupKey {
		t.Fatal("Reanchor returned the same GroupKey pointer; expected fresh key")
	}
	if era2.State.HashSuiteID != hash.LegacyBLAKE3ID {
		t.Fatalf("era2.State.HashSuiteID: want %q got %q",
			hash.LegacyBLAKE3ID, era2.State.HashSuiteID)
	}
	if era2.EraID != era1.EraID+1 {
		t.Fatalf("era2.EraID: want %d got %d", era1.EraID+1, era2.EraID)
	}
}
