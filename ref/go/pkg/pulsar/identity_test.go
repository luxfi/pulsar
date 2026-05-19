// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"testing"
)

// identityFixture provisions a deterministic IdentityKey for every
// committee member. Test code calls this once per (committee, seed)
// pair; identity material is reused across DKG / threshold / reshare
// sessions so the same identities authenticate every round.
//
// Determinism guarantees: re-running with the same committee + seed
// produces byte-identical IdentityKey objects (and therefore byte-
// identical envelope ciphertexts).
type identityFixture struct {
	keys      map[NodeID]*IdentityKey
	directory IdentityDirectory
}

func newIdentityFixture(t testing.TB, committee []NodeID, seed []byte) *identityFixture {
	t.Helper()
	keys := make(map[NodeID]*IdentityKey, len(committee))
	pubs := make(map[NodeID]*IdentityPublicKey, len(committee))
	for i, id := range committee {
		rng := deterministicReader(append(append([]byte{}, seed...), byte(i), 0xFE))
		k, err := GenerateIdentity(rng)
		if err != nil {
			t.Fatalf("GenerateIdentity %d: %v", i, err)
		}
		keys[id] = k
		pubs[id] = k.PublicKey()
	}
	dir, err := NewIdentityDirectory(pubs)
	if err != nil {
		t.Fatalf("NewIdentityDirectory: %v", err)
	}
	return &identityFixture{keys: keys, directory: dir}
}

// quorumSessionKeys runs SymmetricSession for every pair in the
// quorum and returns each party's local view (peer -> session key).
//
// For a quorum of t parties this is t*(t-1)/2 key exchanges. Test-
// only helper; production drivers stream KEM ciphertexts + signatures
// through the chain message bus.
func (f *identityFixture) quorumSessionKeys(t testing.TB, quorum []NodeID, sid [16]byte, transcript []byte) map[NodeID]map[NodeID][32]byte {
	t.Helper()
	out := make(map[NodeID]map[NodeID][32]byte, len(quorum))
	for _, id := range quorum {
		out[id] = make(map[NodeID][32]byte, len(quorum)-1)
	}
	for i := 0; i < len(quorum); i++ {
		for j := i + 1; j < len(quorum); j++ {
			a, b := quorum[i], quorum[j]
			key, err := SymmetricSession(a, f.keys[a], b, f.keys[b], sid, transcript)
			if err != nil {
				t.Fatalf("SymmetricSession %x↔%x: %v", a[:4], b[:4], err)
			}
			out[a][b] = key
			out[b][a] = key
		}
	}
	return out
}

func TestEstablishSession_AuthenticatesViaIdentity(t *testing.T) {
	// Two parties; both derive byte-identical session keys.
	a := NodeID{0x01}
	b := NodeID{0x02}
	aKey, err := GenerateIdentity(deterministicReader([]byte{0xA0}))
	if err != nil {
		t.Fatal(err)
	}
	bKey, err := GenerateIdentity(deterministicReader([]byte{0xB0}))
	if err != nil {
		t.Fatal(err)
	}
	var sid [16]byte
	copy(sid[:], "session-test-01")
	transcript := []byte("sample-transcript")

	keyAB, err := SymmetricSession(a, aKey, b, bKey, sid, transcript)
	if err != nil {
		t.Fatalf("SymmetricSession: %v", err)
	}
	// Different sid → different key.
	var sid2 [16]byte
	copy(sid2[:], "session-test-02")
	keyAB2, err := SymmetricSession(a, aKey, b, bKey, sid2, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if keyAB == keyAB2 {
		t.Fatal("different sid produced identical session key")
	}

	// Tampered ML-DSA signature MUST be rejected by VerifyPeerEncapsulation.
	_, ct, sig, err := EstablishSession(b, bKey, a, aKey.PublicKey(), sid, transcript)
	if err != nil {
		t.Fatal(err)
	}
	sigTamp := append([]byte{}, sig...)
	sigTamp[42] ^= 0x80
	if _, err := VerifyPeerEncapsulation(aKey, bKey.PublicKey(), ct, sigTamp); err == nil {
		t.Fatal("tampered identity signature accepted at VerifyPeerEncapsulation")
	}

	// Tampered KEM ciphertext MUST be rejected (signature now signs the
	// untampered ct; the tampered ct fails verification because the
	// signature was over the original).
	ctTamp := append([]byte{}, ct...)
	ctTamp[100] ^= 0x01
	if _, err := VerifyPeerEncapsulation(aKey, bKey.PublicKey(), ctTamp, sig); err == nil {
		t.Fatal("tampered KEM ciphertext accepted at VerifyPeerEncapsulation")
	}
}

func TestEstablishSession_RejectsSelfPeer(t *testing.T) {
	a := NodeID{0x01}
	aKey, err := GenerateIdentity(deterministicReader([]byte{0xAB}))
	if err != nil {
		t.Fatal(err)
	}
	var sid [16]byte
	if _, _, _, err := EstablishSession(a, aKey, a, aKey.PublicKey(), sid, nil); err != ErrSessionPeerSelf {
		t.Fatalf("self peer not rejected: %v", err)
	}
}

func TestEnvelopeEncryption_PlaintextIsRejected(t *testing.T) {
	// A passive observer who picks up the envelope ciphertext but
	// lacks the recipient's KEM secret key cannot decrypt or forge.
	dealer := NodeID{0x01}
	recipient := NodeID{0x02}
	dealerKey, _ := GenerateIdentity(deterministicReader([]byte{0xAA}))
	recipientKey, _ := GenerateIdentity(deterministicReader([]byte{0xBB}))
	_ = dealerKey

	var committeeRoot [32]byte
	copy(committeeRoot[:], "committee-root-fixed-for-test")
	var share [64]byte
	for i := range share {
		share[i] = byte(i)
	}
	var contribution [SeedSize]byte
	for i := range contribution {
		contribution[i] = byte(i ^ 0x55)
	}
	var encapSeed [32]byte
	copy(encapSeed[:], "encap-seed-32-bytes-fixed-here!!")

	env, err := sealEnvelope(dealer, recipient, committeeRoot, share, contribution,
		recipientKey.PublicKey().KEMPub, encapSeed[:])
	if err != nil {
		t.Fatal(err)
	}
	// Verify open round-trips.
	gotShare, gotContrib, err := sealOpenEnvelope(dealer, recipient, committeeRoot, env, recipientKey)
	if err != nil {
		t.Fatalf("legitimate open: %v", err)
	}
	if gotShare != share {
		t.Fatal("share round-trip mismatch")
	}
	if gotContrib != contribution {
		t.Fatal("contribution round-trip mismatch")
	}

	// 1. Random observer with no KEM key — cannot decrypt. We
	//    simulate by handing in a different IdentityKey: decapsulation
	//    yields garbage and the auth-tag check fails.
	stranger, _ := GenerateIdentity(deterministicReader([]byte{0xCC}))
	if _, _, err := sealOpenEnvelope(dealer, recipient, committeeRoot, env, stranger); err != ErrEnvelopeAuthBad {
		t.Fatalf("stranger decrypted envelope: %v", err)
	}

	// 2. Wrong dealer / recipient binding — auth tag fails.
	wrongDealer := NodeID{0x99}
	if _, _, err := sealOpenEnvelope(wrongDealer, recipient, committeeRoot, env, recipientKey); err != ErrEnvelopeAuthBad {
		t.Fatalf("wrong-dealer binding accepted: %v", err)
	}

	// 3. Bit-flipped sealed payload — auth tag fails.
	envTamp := DKGShareEnvelope{
		KEMCiphertext: env.KEMCiphertext,
		Sealed:        append([]byte{}, env.Sealed...),
	}
	envTamp.Sealed[10] ^= 0x01
	if _, _, err := sealOpenEnvelope(dealer, recipient, committeeRoot, envTamp, recipientKey); err != ErrEnvelopeAuthBad {
		t.Fatalf("tampered sealed payload accepted: %v", err)
	}

	// 4. Determinism: same inputs → same envelope bytes (KAT gate).
	env2, err := sealEnvelope(dealer, recipient, committeeRoot, share, contribution,
		recipientKey.PublicKey().KEMPub, encapSeed[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(env.KEMCiphertext, env2.KEMCiphertext) {
		t.Fatal("envelope KEM ciphertext is not deterministic from seed")
	}
	if !bytes.Equal(env.Sealed, env2.Sealed) {
		t.Fatal("envelope sealed payload is not deterministic from seed")
	}
}
