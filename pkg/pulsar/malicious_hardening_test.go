// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// malicious_hardening_test.go — item 5 achievable subset: nonce-ticket
// lifecycle, authenticated-message equivocation detection. (The capstone
// "bad behavior ⇒ abort/blame, never forge/leak" lives in
// malicious_capstone_test.go.)

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/sha3"
)

// ── nonce-ticket lifecycle ────────────────────────────────────────────────

func TestNonceTicketLifecycle(t *testing.T) {
	var committeeID [32]byte
	committeeID[0] = 0x11
	w1 := []byte("packed-w1-nonce-commitment-AAAA")
	digestA := sha3Sum32([]byte("message A"))
	digestB := sha3Sum32([]byte("message B"))
	bindA := NonceBinding{Epoch: 7, CommitteeID: committeeID, MessageKind: 1, Digest: digestA}
	bindB := NonceBinding{Epoch: 7, CommitteeID: committeeID, MessageKind: 1, Digest: digestB}

	// (1) UNIQUE ticket_id per (nonce, binding): same nonce material, different
	//     message ⇒ different TicketID (audit handle) …
	tkA := NewNonceTicket(committeeID, w1, bindA)
	tkB := NewNonceTicket(committeeID, w1, bindB)
	if tkA.TicketID == tkB.TicketID {
		t.Fatalf("ticket ids collided for different bindings")
	}
	// … but the SAME MaterialKey (single-use dedup is on the nonce, not the label).
	if tkA.MaterialKey() != tkB.MaterialKey() {
		t.Fatalf("material keys differ for the same nonce material — dedup would be bypassable")
	}

	// (2) ONE-USE + DOMAIN-BOUND: first reserve OK; the same nonce material under
	//     a DIFFERENT message/ticket is rejected (the nonce is burned).
	led := NewInMemoryNonceLedger()
	if err := ReserveNonceTicket(led, tkA); err != nil {
		t.Fatalf("first ticket reserve must succeed: %v", err)
	}
	if err := ReserveNonceTicket(led, tkB); err != ErrNonceReused {
		t.Fatalf("reusing the same nonce material (msg B) returned %v, want ErrNonceReused", err)
	}
	// A relabeled ticket (new TicketID via different binding, same w1) is also rejected.
	tkRelabel := NewNonceTicket(committeeID, w1, NonceBinding{Epoch: 99, CommitteeID: committeeID, MessageKind: 5, Digest: digestA})
	if err := ReserveNonceTicket(led, tkRelabel); err != ErrNonceReused {
		t.Fatalf("relabeled reuse returned %v, want ErrNonceReused", err)
	}

	// (3) DOMAIN binding recorded; CheckBinding tripwire fires on a different
	//     binding for the SAME material key.
	if reserved, err := led.CheckBinding(tkA.MaterialKey(), bindA); !reserved || err != nil {
		t.Fatalf("CheckBinding(original)=%v,%v want true,nil", reserved, err)
	}
	if reserved, err := led.CheckBinding(tkA.MaterialKey(), bindB); !reserved || err != ErrNonceBindingMismatch {
		t.Fatalf("CheckBinding(other binding)=%v,%v want true,ErrNonceBindingMismatch", reserved, err)
	}

	// (4) ABORT DOESN'T LEAK reusable state: a FRESH nonce reserved then "aborted"
	//     (we simulate the signer failing after reserve) stays burned — a second
	//     attempt on that nonce is refused, never re-openable.
	w1b := []byte("packed-w1-nonce-commitment-BBBB")
	tkFresh := NewNonceTicket(committeeID, w1b, NonceBinding{Epoch: 7, CommitteeID: committeeID, Digest: digestA})
	if err := ReserveNonceTicket(led, tkFresh); err != nil {
		t.Fatalf("fresh reserve: %v", err)
	}
	// (signer would now abort, e.g. proof failure — no rollback happens)
	if err := ReserveNonceTicket(led, tkFresh); err != ErrNonceReused {
		t.Fatalf("post-abort reuse returned %v, want ErrNonceReused (aborted attempt leaked reusable nonce state!)", err)
	}
	t.Logf("nonce-ticket lifecycle PASS: unique ticket ids, single-use on material, domain-bound, abort doesn't leak reusable state")
}

func sha3Sum32(b []byte) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write(b)
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// ── authenticated messages + equivocation detection ───────────────────────

// stubIdentity is a test identity layer: sign = SHAKE256("k"‖author‖tbs)[:64].
type stubIdentity struct{}

func (stubIdentity) sign(author NodeID, tbs []byte) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("stub-identity-key"))
	_, _ = h.Write(author[:])
	_, _ = h.Write(tbs)
	out := make([]byte, 64)
	_, _ = h.Read(out)
	return out
}

func (s stubIdentity) VerifyAbortSignature(author NodeID, transcript, signature []byte) bool {
	return bytes.Equal(signature, s.sign(author, transcript))
}

func TestSignedProtocolMessage_Equivocation(t *testing.T) {
	id := stubIdentity{}
	var author, observer NodeID
	author[0] = 0xAA
	observer[0] = 0xBB
	ctx := ProtocolContext{Epoch: 3, Round: ProtocolRoundPartial}
	ctx.SessionID[0] = 0x01

	mk := func(payload string) SignedProtocolMessage {
		dig := sha3Sum32([]byte(payload))
		m := SignedProtocolMessage{Author: author, Context: ctx, PayloadDigest: dig}
		m.Signature = id.sign(author, ProtocolMessageTBS(author, ctx, dig))
		return m
	}
	msgX := mk("z-partial X")
	msgY := mk("z-partial Y (conflicting, same slot)")

	// Both messages verify under the identity layer.
	if !VerifySignedProtocolMessage(&msgX, id) || !VerifySignedProtocolMessage(&msgY, id) {
		t.Fatal("signed messages failed verification")
	}

	// Two distinct payloads, same slot, both signed ⇒ provable equivocation.
	ev, ok := DetectEquivocation(observer, msgX, msgY, ctx.Epoch, id)
	if !ok {
		t.Fatal("equivocation not detected on two conflicting signed messages")
	}
	if ev.Kind != ComplaintEquivocation || ev.Accused != author || ev.Accuser != observer {
		t.Fatalf("equivocation evidence fields wrong: kind=%v accused=%x accuser=%x", ev.Kind, ev.Accused[:4], ev.Accuser[:4])
	}
	if err := ValidateAbortEvidence(ev); err != nil {
		t.Fatalf("equivocation AbortEvidence malformed: %v", err)
	}

	// NON-equivocation: identical payload ⇒ no conflict.
	if _, ok := DetectEquivocation(observer, msgX, msgX, ctx.Epoch, id); ok {
		t.Fatal("identical payloads wrongly flagged as equivocation")
	}
	// Different slot ⇒ not equivocation.
	other := msgY
	other.Context.Round = ProtocolRoundFinal
	other.Signature = id.sign(author, ProtocolMessageTBS(author, other.Context, other.PayloadDigest))
	if _, ok := DetectEquivocation(observer, msgX, other, ctx.Epoch, id); ok {
		t.Fatal("different-slot messages wrongly flagged as equivocation")
	}
	// Forged (bad signature) ⇒ not provable equivocation.
	forged := msgY
	forged.Signature = []byte("not-a-valid-signature-................................................")
	if _, ok := DetectEquivocation(observer, msgX, forged, ctx.Epoch, id); ok {
		t.Fatal("a message with an invalid signature must not yield equivocation evidence")
	}
	t.Logf("equivocation PASS: two validly-signed conflicting same-slot messages ⇒ ComplaintEquivocation; non-conflicts and forgeries rejected")
}
