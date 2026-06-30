// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// protocol_auth.go — authenticated protocol messages + equivocation detection
// (item 5: authenticated channels / signed protocol messages, equivocation).
//
// SCOPE. This is the CRYPTO primitive: a canonical to-be-signed encoding for a
// protocol message bound to its (epoch, session, round) slot, a pluggable
// identity verifier (the same AbortSignatureVerifier shape — one identity layer,
// DRY), and a SOUND equivocation detector: two validly-signed messages from the
// SAME author for the SAME slot with DIFFERENT payloads is provable misbehavior
// and yields a ComplaintEquivocation AbortEvidence. The NETWORKED transport that
// collects these messages (authenticated channels over the wire) is owned by the
// consensus layer (round.go) and is a flagged residual — this package supplies
// the signable bytes and the detector, not the sockets.

import (
	"bytes"

	"github.com/luxfi/mlwe/transcript"
)

// ProtocolRound enumerates the signable protocol message slots. Equivocation is
// defined per (Author, Epoch, SessionID, Round): one author may sign at most one
// distinct payload per slot.
type ProtocolRound uint8

const (
	ProtocolRoundNonce ProtocolRound = iota + 1 // Round1 nonce binding
	ProtocolRoundPartial                        // Round2 z-partial
	ProtocolRoundFinal                          // Finalize / aggregate
)

// ProtocolContext is the slot a protocol message is bound to.
type ProtocolContext struct {
	Epoch     uint64
	SessionID [32]byte
	NonceID   [32]byte
	Round     ProtocolRound
}

// SignedProtocolMessage is an authenticated protocol message: the author's
// identity-key signature over the canonical to-be-signed bytes of (context,
// payload digest). PayloadDigest is a 32-byte digest of the message body
// (e.g. packed z-partial, nonce cert) so equivocation comparison is constant-size.
type SignedProtocolMessage struct {
	Author        NodeID
	Context       ProtocolContext
	PayloadDigest [32]byte
	Signature     []byte
}

// ProtocolMessageTBS is the canonical to-be-signed byte string for a protocol
// message: SP 800-185 framed (domain ‖ author ‖ epoch ‖ session ‖ nonce ‖ round
// ‖ payload-digest). The author's identity key signs THESE bytes; a verifier
// re-derives them and checks the signature. There is exactly one encoding.
func ProtocolMessageTBS(author NodeID, ctx ProtocolContext, payloadDigest [32]byte) []byte {
	parts := [][]byte{
		[]byte("PULSAR/protocol-msg/v1"),
		author[:],
		u64be(ctx.Epoch),
		ctx.SessionID[:],
		ctx.NonceID[:],
		{byte(ctx.Round)},
		payloadDigest[:],
	}
	out := append([]byte{}, transcript.LeftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, transcript.EncodeString(p)...)
	}
	return out
}

// u64be is the 8-byte big-endian encoding of x (helper for the TBS framing).
func u64be(x uint64) []byte {
	return []byte{
		byte(x >> 56), byte(x >> 48), byte(x >> 40), byte(x >> 32),
		byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x),
	}
}

// VerifySignedProtocolMessage checks the author's identity-key signature over
// the canonical TBS bytes via the supplied verifier. A nil verifier is rejected
// (no implicit skip-verification path — fail closed).
func VerifySignedProtocolMessage(m *SignedProtocolMessage, v AbortSignatureVerifier) bool {
	if m == nil || v == nil || len(m.Signature) == 0 {
		return false
	}
	return v.VerifyAbortSignature(m.Author, ProtocolMessageTBS(m.Author, m.Context, m.PayloadDigest), m.Signature)
}

// DetectEquivocation returns a ComplaintEquivocation AbortEvidence iff a and b
// are two DISTINCT-payload messages from the SAME author for the SAME slot, both
// carrying a VALID identity signature. This is sound non-repudiable misbehavior:
// the two signatures prove the author committed to two payloads in one slot.
// accuser is the observer raising the complaint. Returns (nil, false) when the
// pair is not equivocation (different slot/author, equal payload, or either
// signature invalid).
func DetectEquivocation(accuser NodeID, a, b SignedProtocolMessage, epoch uint64, v AbortSignatureVerifier) (*AbortEvidence, bool) {
	if v == nil {
		return nil, false
	}
	if a.Author != b.Author || a.Context != b.Context {
		return nil, false
	}
	if a.PayloadDigest == b.PayloadDigest {
		return nil, false // same payload — no conflict
	}
	if accuser == a.Author {
		return nil, false // never self-accuse
	}
	if !VerifySignedProtocolMessage(&a, v) || !VerifySignedProtocolMessage(&b, v) {
		return nil, false // unsigned/forged — not provable equivocation
	}
	// Order the two commits canonically so the evidence is deterministic.
	c1, c2 := a, b
	if bytes.Compare(a.PayloadDigest[:], b.PayloadDigest[:]) > 0 {
		c1, c2 = b, a
	}
	ev := &AbortEvidence{
		Kind:    ComplaintEquivocation,
		Accuser: accuser,
		Accused: a.Author,
		Epoch:   epoch,
		Evidence: buildEquivocationEvidence(
			c1.PayloadDigest[:], c2.PayloadDigest[:], c1.Signature, c2.Signature),
	}
	return ev, true
}

// buildEquivocationEvidence packs the 4-field equivocation evidence blob
// (commit1, commit2, sig1, sig2) in the TLV form abort.go validates.
func buildEquivocationEvidence(commit1, commit2, sig1, sig2 []byte) []byte {
	out := make([]byte, 0, 4*4+len(commit1)+len(commit2)+len(sig1)+len(sig2))
	for _, f := range [][]byte{commit1, commit2, sig1, sig2} {
		var l [4]byte
		l[0] = byte(len(f) >> 24)
		l[1] = byte(len(f) >> 16)
		l[2] = byte(len(f) >> 8)
		l[3] = byte(len(f))
		out = append(out, l[:]...)
		out = append(out, f...)
	}
	return out
}
