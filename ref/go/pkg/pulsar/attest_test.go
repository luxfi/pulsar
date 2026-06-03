// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// attest_test.go — TBS-digest contract for AttestationContext
// (PULSAR-V12-TEE-BIND).
//
// Two invariants pinned:
//
//  1. STABLE — the digest is deterministic across runs for the same
//     (setup, msg) tuple.
//  2. SENSITIVE — changing ANY input field (sessionID, attempt,
//     groupPub, nodeID, commit) changes the digest. This is the
//     load-bearing property: an attacker that can flip ONE field
//     while keeping the quote bound to the OLD digest must lose,
//     so the digest function must be coverage-complete.

import (
	"bytes"
	"testing"
)

func attestFixtureSetup() *AlgebraicSetup {
	pub := &PublicKey{Mode: ModeP65, Bytes: make([]byte, 1952)}
	for i := range pub.Bytes {
		pub.Bytes[i] = byte(i)
	}
	return &AlgebraicSetup{Mode: ModeP65, Pub: pub}
}

func attestFixtureMsg() *AlgebraicRound1Message {
	m := &AlgebraicRound1Message{
		SessionID: [16]byte{'s', 'i', 'd', '-', 'a', 't', 't', '-', '0', '0', '0', '1'},
		Attempt:   0x01020304,
	}
	for i := range m.NodeID {
		m.NodeID[i] = byte(0x10 + i)
	}
	for i := range m.Commit {
		m.Commit[i] = byte(0x80 + i)
	}
	return m
}

// TestAttestationContext_Stable — same inputs => same digest.
func TestAttestationContext_Stable(t *testing.T) {
	setup := attestFixtureSetup()
	msg := attestFixtureMsg()
	a := AttestationContext(setup, msg)
	b := AttestationContext(setup, msg)
	if a != b {
		t.Fatalf("AttestationContext non-deterministic:\n  a = %x\n  b = %x", a, b)
	}
	var zero [32]byte
	if a == zero {
		t.Fatalf("AttestationContext returned zero on valid inputs")
	}
}

// TestAttestationContext_NilInputs — defensive returns the zero digest.
func TestAttestationContext_NilInputs(t *testing.T) {
	var zero [32]byte
	if got := AttestationContext(nil, attestFixtureMsg()); got != zero {
		t.Fatalf("nil setup did not return zero digest: %x", got)
	}
	if got := AttestationContext(attestFixtureSetup(), nil); got != zero {
		t.Fatalf("nil msg did not return zero digest: %x", got)
	}
	setupNilPub := &AlgebraicSetup{Mode: ModeP65}
	if got := AttestationContext(setupNilPub, attestFixtureMsg()); got != zero {
		t.Fatalf("nil setup.Pub did not return zero digest: %x", got)
	}
}

// TestAttestationContext_Sensitive — every input field, when mutated,
// MUST produce a different digest. This is the coverage-complete
// property; an attacker that wants to keep a TEE quote (bound to the
// old digest) valid while replaying with ANY altered field must lose.
func TestAttestationContext_Sensitive(t *testing.T) {
	base := AttestationContext(attestFixtureSetup(), attestFixtureMsg())

	t.Run("sessionID", func(t *testing.T) {
		msg := attestFixtureMsg()
		msg.SessionID[0] ^= 1
		mut := AttestationContext(attestFixtureSetup(), msg)
		if mut == base {
			t.Fatalf("sessionID mutation did not change digest")
		}
	})

	t.Run("attempt", func(t *testing.T) {
		msg := attestFixtureMsg()
		msg.Attempt ^= 0x01
		mut := AttestationContext(attestFixtureSetup(), msg)
		if mut == base {
			t.Fatalf("attempt mutation did not change digest")
		}
	})

	t.Run("groupPub", func(t *testing.T) {
		setup := attestFixtureSetup()
		setup.Pub.Bytes[0] ^= 1
		mut := AttestationContext(setup, attestFixtureMsg())
		if mut == base {
			t.Fatalf("groupPub mutation did not change digest")
		}
	})

	t.Run("nodeID", func(t *testing.T) {
		msg := attestFixtureMsg()
		msg.NodeID[0] ^= 1
		mut := AttestationContext(attestFixtureSetup(), msg)
		if mut == base {
			t.Fatalf("nodeID mutation did not change digest")
		}
	})

	t.Run("commit", func(t *testing.T) {
		msg := attestFixtureMsg()
		msg.Commit[0] ^= 1
		mut := AttestationContext(attestFixtureSetup(), msg)
		if mut == base {
			t.Fatalf("commit mutation did not change digest")
		}
	})
}

// TestAttestationContext_DomainSeparation — the customisation tag
// must be reflected in the output. A digest computed with a different
// customisation string (over the same inputs) must differ. Asserted
// via cshake256 directly — we re-derive what the function should
// produce and compare.
func TestAttestationContext_DomainSeparation(t *testing.T) {
	setup := attestFixtureSetup()
	msg := attestFixtureMsg()
	got := AttestationContext(setup, msg)

	var attemptBytes [4]byte
	attemptBytes[0] = byte(msg.Attempt >> 24)
	attemptBytes[1] = byte(msg.Attempt >> 16)
	attemptBytes[2] = byte(msg.Attempt >> 8)
	attemptBytes[3] = byte(msg.Attempt)

	want := transcriptHash32(
		AttestationContextTag,
		msg.SessionID[:],
		attemptBytes[:],
		setup.Pub.Bytes,
		msg.NodeID[:],
		msg.Commit[:],
	)
	if got != want {
		t.Fatalf("AttestationContext disagrees with transcriptHash32:\n  got  = %x\n  want = %x", got, want)
	}

	// Same parts under a different customisation must differ.
	other := transcriptHash32(
		"pulsar-att-different",
		msg.SessionID[:],
		attemptBytes[:],
		setup.Pub.Bytes,
		msg.NodeID[:],
		msg.Commit[:],
	)
	if bytes.Equal(other[:], got[:]) {
		t.Fatalf("customisation tag did not domain-separate the digest")
	}
}
