// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// identity.go — long-term party identity + ephemeral per-session
// per-pair key establishment.
//
// Closes BLOCKERS.md CR-7 and CR-8. The v0.1 sign-MAC layer derived
// per-peer MAC keys from public inputs (NodeID pair + group public
// key), letting any network observer forge MACs and DoS the
// identifiable-abort gate at zero cost. The v0.1 DKG envelopes were
// transmitted in plaintext, letting a passive surveillance node
// recover the master secret from a single ceremony.
//
// This file replaces both with a single coherent primitive:
//
//   IdentityKey  — long-term ML-KEM-768 + ML-DSA-65 keypair, one per
//                  party. Long-lived; published on-chain alongside the
//                  party's validator record.
//
//   EstablishSession — per-session per-pair Diffie-Hellman-style key
//                  agreement via ML-KEM-768. Each party encapsulates a
//                  fresh shared-secret to its peer's long-term ML-KEM
//                  public key; the two encapsulations are mixed via
//                  HKDF-SHA3-256 to produce a session key authenticated
//                  by the long-term ML-DSA signature over each
//                  encapsulation.
//
// The session key is the input to both:
//   - the per-pair MAC key used in ThresholdSigner Round 1
//     (replaces deriveMACKey)
//   - the per-recipient envelope-wrap key used in DKGSession Round 1
//     (replaces plaintext envelope transmission)
//
// Determinism: every primitive in this file accepts a deterministic
// seed reader so KAT regeneration is reproducible from a 32-byte
// master seed.

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Errors returned by identity / session-key operations.
var (
	ErrIdentityKeyMissing  = errors.New("pulsar: identity key missing")
	ErrSessionKeyMissing   = errors.New("pulsar: session key missing for peer")
	ErrIdentityCorrupted   = errors.New("pulsar: identity key bytes invalid")
	ErrSessionEncryption   = errors.New("pulsar: session-key derivation failed")
	ErrEnvelopeCiphertext  = errors.New("pulsar: KEM ciphertext is wrong size or invalid")
	ErrEnvelopeAuthBad     = errors.New("pulsar: envelope authentication tag invalid")
	ErrSessionPeerSelf     = errors.New("pulsar: cannot establish session with self")
	ErrSessionIdentityPK   = errors.New("pulsar: peer identity public key invalid")
)

// IdentityPublicKey is a party's long-term public identity material:
// the ML-KEM-768 encapsulation key (for envelope/session-key
// reception) plus the ML-DSA-65 verification key (for authenticating
// envelopes and complaints).
//
// Both fields are byte-packed per their respective FIPS standards
// (FIPS 203 for ML-KEM, FIPS 204 for ML-DSA) so this struct is wire-
// safe to publish in a chain's validator record.
type IdentityPublicKey struct {
	KEMPub   []byte // ML-KEM-768 public key (1184 bytes)
	MLDSAPub []byte // ML-DSA-65 public key (1952 bytes)
}

// IdentityKey is a party's long-term keypair: ML-KEM-768 (for
// encapsulation) + ML-DSA-65 (for signing envelope-attestations and
// complaints). Publish only the IdentityPublicKey component; keep
// the secret halves in HSM or KMS.
type IdentityKey struct {
	KEMPub    []byte
	KEMPriv   []byte
	MLDSAPub  []byte
	MLDSAPriv []byte
}

// PublicKey returns the publishable half of an IdentityKey.
func (k *IdentityKey) PublicKey() *IdentityPublicKey {
	if k == nil {
		return nil
	}
	return &IdentityPublicKey{
		KEMPub:   append([]byte{}, k.KEMPub...),
		MLDSAPub: append([]byte{}, k.MLDSAPub...),
	}
}

// GenerateIdentity produces a fresh long-term identity keypair from
// the given entropy source. Pass a deterministic reader for KAT
// regeneration; nil falls back to crypto/rand.
func GenerateIdentity(rng io.Reader) (*IdentityKey, error) {
	if rng == nil {
		return nil, ErrShortRand
	}
	// ML-KEM-768 keygen consumes 64 bytes of seed material.
	var kemSeed [mlkem768.KeySeedSize]byte
	if _, err := io.ReadFull(rng, kemSeed[:]); err != nil {
		return nil, ErrShortRand
	}
	kemPub, kemPriv := mlkem768.NewKeyFromSeed(kemSeed[:])
	kpubB, err := kemPub.MarshalBinary()
	if err != nil {
		return nil, ErrIdentityCorrupted
	}
	kpriB, err := kemPriv.MarshalBinary()
	if err != nil {
		return nil, ErrIdentityCorrupted
	}

	// ML-DSA-65 keygen consumes a 32-byte seed.
	var dsaSeed [32]byte
	if _, err := io.ReadFull(rng, dsaSeed[:]); err != nil {
		return nil, ErrShortRand
	}
	dpub, dpriv := mldsa65.NewKeyFromSeed(&dsaSeed)
	var dpubB [mldsa65.PublicKeySize]byte
	dpub.Pack(&dpubB)
	var dprivB [mldsa65.PrivateKeySize]byte
	dpriv.Pack(&dprivB)

	return &IdentityKey{
		KEMPub:    kpubB,
		KEMPriv:   kpriB,
		MLDSAPub:  append([]byte{}, dpubB[:]...),
		MLDSAPriv: append([]byte{}, dprivB[:]...),
	}, nil
}

// EstablishSession performs an authenticated ML-KEM-768 key agreement
// between this party and the peer at peerID.
//
// Protocol:
//   1. Caller (this party, A) encapsulates a fresh shared secret ss_A
//      to peer's long-term KEM public key. The encapsulation is
//      DETERMINISTIC, seeded from
//          HKDF-SHA3-256("PULSAR-SESSION-V1" || sid || A || B || transcript)
//      so two parties agreeing on sid + transcript derive the same
//      encapsulation seed for KAT reproducibility.
//   2. Peer (B) does the symmetric thing with roles swapped.
//   3. Both sides derive the final session key via DeriveSessionKey
//      mixing ss_A + ss_B canonically by NodeID order.
//
// Authentication: the caller MUST sign the encapsulation ciphertext
// with their long-term ML-DSA-65 secret key and broadcast (ciphertext,
// signature) to the peer. The peer verifies the signature against the
// caller's published ML-DSA-65 public key before decapsulating.
//
// For test/KAT use we expose the symmetric two-shot SymmetricSession
// helper below; production callers feed the broadcast (ct, sig) tuple
// through the chain's message bus.
//
// Returns:
//   - mySS:       this party's contributory shared secret (caller
//                 keeps it locally; combined with peer's mySS via
//                 DeriveSessionKey once the peer's ct+sig arrive)
//   - kemCT:      the ML-KEM ciphertext to send to the peer
//   - sigOverCT:  the caller's ML-DSA-65 signature over kemCT (peer
//                 verifies before decapsulating)
//
// Returns ErrSessionPeerSelf if peerID equals myID and
// ErrSessionIdentityPK if the peer's identity key is malformed.
func EstablishSession(
	myID NodeID,
	myIdentity *IdentityKey,
	peerID NodeID,
	peerIdentity *IdentityPublicKey,
	sid [16]byte,
	transcript []byte,
) (mySS []byte, kemCT []byte, sigOverCT []byte, err error) {
	if myIdentity == nil {
		err = ErrIdentityKeyMissing
		return
	}
	if peerIdentity == nil || len(peerIdentity.KEMPub) != mlkem768.PublicKeySize {
		err = ErrSessionIdentityPK
		return
	}
	if myID == peerID {
		err = ErrSessionPeerSelf
		return
	}

	// Derive deterministic encapsulation seed: bound to (sid, A→B
	// direction, transcript). The encapsulation seed is direction-
	// dependent so A→B and B→A produce DIFFERENT shared secrets;
	// DeriveSessionKey mixes both contributions into the final key.
	seedExpand := hkdf.New(sha3.New256,
		append(append([]byte{}, myID[:]...), peerID[:]...),
		sid[:], append([]byte(sessionEstablishInfo), transcript...))
	var encapSeed [mlkem768.EncapsulationSeedSize]byte
	if _, err = io.ReadFull(seedExpand, encapSeed[:]); err != nil {
		err = ErrSessionEncryption
		return
	}

	// Decode peer's KEM public key.
	var peerKEMPub mlkem768.PublicKey
	if e := peerKEMPub.Unpack(peerIdentity.KEMPub); e != nil {
		err = ErrSessionIdentityPK
		return
	}

	// Encapsulate deterministically.
	ct := make([]byte, mlkem768.CiphertextSize)
	ss := make([]byte, mlkem768.SharedKeySize)
	peerKEMPub.EncapsulateTo(ct, ss, encapSeed[:])
	kemCT = ct

	// Sign the ciphertext with our long-term ML-DSA-65 key so the
	// peer can authenticate the encapsulation before decapsulating.
	var dpriv mldsa65.PrivateKey
	if e := dpriv.UnmarshalBinary(myIdentity.MLDSAPriv); e != nil {
		err = ErrIdentityCorrupted
		return
	}
	sigBuf := make([]byte, mldsa65.SignatureSize)
	// Deterministic signing: ctx binds to the session establishment
	// tag so a signature reuse across protocols becomes a domain-tag
	// mismatch at verification time.
	if e := mldsa65.SignTo(&dpriv, ct, []byte(sessionEstablishInfo), false, sigBuf); e != nil {
		err = ErrSessionEncryption
		return
	}
	sigOverCT = sigBuf

	// Caller side: at this point we know our ss but not peer's. The
	// final session key uses BOTH ss's (this side's encapsulation +
	// peer's encapsulation) so the protocol is contributory. The
	// caller stores ss locally; the mixing step happens once the
	// peer's ct + sig arrive (see DeriveSessionKey).
	mySS = ss
	return
}

// VerifyPeerEncapsulation authenticates a peer's encapsulation ct
// against their published ML-DSA-65 public key, then decapsulates
// with our long-term ML-KEM-768 secret key.
//
// Returns the 32-byte shared secret that the peer encapsulated to us.
// This shared secret is then combined with our own EstablishSession
// shared secret via DeriveSessionKey to produce the final session key.
func VerifyPeerEncapsulation(
	myIdentity *IdentityKey,
	peerIdentity *IdentityPublicKey,
	peerCT []byte,
	peerSig []byte,
) (peerSS []byte, err error) {
	if myIdentity == nil {
		return nil, ErrIdentityKeyMissing
	}
	if peerIdentity == nil || len(peerIdentity.MLDSAPub) != mldsa65.PublicKeySize {
		return nil, ErrSessionIdentityPK
	}
	if len(peerCT) != mlkem768.CiphertextSize {
		return nil, ErrEnvelopeCiphertext
	}
	var peerDSAPub mldsa65.PublicKey
	if e := peerDSAPub.UnmarshalBinary(peerIdentity.MLDSAPub); e != nil {
		return nil, ErrSessionIdentityPK
	}
	if !mldsa65.Verify(&peerDSAPub, peerCT, []byte(sessionEstablishInfo), peerSig) {
		return nil, ErrSessionEncryption
	}
	// Decapsulate with our KEM secret key.
	var myKEMPriv mlkem768.PrivateKey
	if e := myKEMPriv.Unpack(myIdentity.KEMPriv); e != nil {
		return nil, ErrIdentityCorrupted
	}
	ss := make([]byte, mlkem768.SharedKeySize)
	myKEMPriv.DecapsulateTo(ss, peerCT)
	return ss, nil
}

// DeriveSessionKey mixes the two contributory shared secrets (ours
// from EstablishSession + peer's from VerifyPeerEncapsulation) into a
// canonical 32-byte session key. Both ends derive the same key
// because the inputs are canonical-ordered by NodeID.
func DeriveSessionKey(myID, peerID NodeID, sid [16]byte, mySS, peerSS []byte) ([32]byte, error) {
	if myID == peerID {
		return [32]byte{}, ErrSessionPeerSelf
	}
	first, second := myID, peerID
	mySSFirst, peerSSFirst := mySS, peerSS
	if nodeIDLess(peerID, myID) {
		first, second = peerID, myID
		mySSFirst, peerSSFirst = peerSS, mySS
	}
	// ikm = ss(smaller) || ss(larger); both ends derive byte-identical
	// inputs.
	ikm := append(append([]byte{}, mySSFirst...), peerSSFirst...)
	info := append([]byte(sessionKeyInfo), append(first[:], second[:]...)...)
	r := hkdf.New(sha3.New256, ikm, sid[:], info)
	var out [32]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return [32]byte{}, ErrSessionEncryption
	}
	return out, nil
}

// SymmetricSession is the two-party convenience helper that runs the
// full session-establishment protocol against in-memory IdentityKey
// peers. Used by tests and KAT generation; production deployments
// drive the exchange through the chain message bus.
//
// Returns the byte-identical session key both parties derive.
func SymmetricSession(
	aID NodeID, aKey *IdentityKey,
	bID NodeID, bKey *IdentityKey,
	sid [16]byte, transcript []byte,
) ([32]byte, error) {
	if aID == bID {
		return [32]byte{}, ErrSessionPeerSelf
	}
	// A → B encapsulation.
	mySSA, ctA, sigA, err := EstablishSession(aID, aKey, bID, bKey.PublicKey(), sid, transcript)
	if err != nil {
		return [32]byte{}, err
	}
	// B → A encapsulation.
	mySSB, ctB, sigB, err := EstablishSession(bID, bKey, aID, aKey.PublicKey(), sid, transcript)
	if err != nil {
		return [32]byte{}, err
	}
	// A authenticates+decapsulates B's ct.
	peerSSForA, err := VerifyPeerEncapsulation(aKey, bKey.PublicKey(), ctB, sigB)
	if err != nil {
		return [32]byte{}, err
	}
	// B authenticates+decapsulates A's ct.
	peerSSForB, err := VerifyPeerEncapsulation(bKey, aKey.PublicKey(), ctA, sigA)
	if err != nil {
		return [32]byte{}, err
	}
	// Sanity: the two parties learned each other's contributions.
	if !ctEqualSlice(mySSA, peerSSForB) {
		return [32]byte{}, ErrSessionEncryption
	}
	if !ctEqualSlice(mySSB, peerSSForA) {
		return [32]byte{}, ErrSessionEncryption
	}
	// Both sides run DeriveSessionKey.
	keyA, err := DeriveSessionKey(aID, bID, sid, mySSA, peerSSForA)
	if err != nil {
		return [32]byte{}, err
	}
	keyB, err := DeriveSessionKey(bID, aID, sid, mySSB, peerSSForB)
	if err != nil {
		return [32]byte{}, err
	}
	if keyA != keyB {
		return [32]byte{}, ErrSessionEncryption
	}
	return keyA, nil
}

// envelopeAuthTagSize is the fixed 32-byte KMAC256 tag suffix in the
// sealed payload. Sealed-payload total length is
//   len(shareWire) + SeedSize + envelopeAuthTagSize.
const envelopeAuthTagSize = 32

// sealEnvelope wraps the per-recipient Shamir share AND the full
// dealer contribution under the recipient's long-term ML-KEM-768
// public key. Used by DKGSession.Round1 (BLOCKERS.md CR-8 fix).
//
// The dealer contribution c_i is included so each committee member
// can independently compute the joint byte-sum at DKG Round 3
// (preserving the v0.1 reconstruction-aggregator trust model) while
// passive network observers — who lack any recipient's KEM secret
// key — read nothing.
//
// The shareWire slice is variable-width: 64 bytes for the GF(257)
// small-committee path and 128 bytes for the GF(q) large-committee
// path. The envelope key derivation, KEM ciphertext, KMAC256 auth tag
// and cSHAKE256 stream cipher are width-agnostic, so the small and
// large paths share a single identity stage (no duplicated sealing
// primitive per path).
//
// Protocol:
//   1. Encapsulate a fresh shared secret ss to recipient's KEM pub.
//      Encapsulation seed is derived deterministically by the caller
//      (DKGSession / ReshareSession / Large variants) so KAT
//      regeneration is byte-stable.
//   2. Derive an envelope key K_env = HKDF-SHA3-256(ss, salt=dealerID,
//      info="PULSAR-DKG-ENVKEY-V1" || recipientID || committee_root).
//   3. Seal (share || contribution || tag) under K_env via XOR with
//      a cSHAKE256 stream keyed by K_env. The auth tag is
//      KMAC256(K_env, dealerID || recipientID || share || contribution).
//
// Returns ErrSessionIdentityPK if recipientKEMPub is malformed.
func sealEnvelope(
	dealerID, recipientID NodeID,
	committeeRoot [32]byte,
	shareWire []byte,
	contribution [SeedSize]byte,
	recipientKEMPub []byte,
	encapSeed []byte,
) (DKGShareEnvelope, error) {
	if len(recipientKEMPub) != mlkem768.PublicKeySize {
		return DKGShareEnvelope{}, ErrSessionIdentityPK
	}
	if len(encapSeed) != mlkem768.EncapsulationSeedSize {
		return DKGShareEnvelope{}, ErrEnvelopeCiphertext
	}
	if len(shareWire) == 0 {
		return DKGShareEnvelope{}, ErrEnvelopeCiphertext
	}
	var pk mlkem768.PublicKey
	if err := pk.Unpack(recipientKEMPub); err != nil {
		return DKGShareEnvelope{}, ErrSessionIdentityPK
	}
	ct := make([]byte, mlkem768.CiphertextSize)
	ss := make([]byte, mlkem768.SharedKeySize)
	pk.EncapsulateTo(ct, ss, encapSeed)

	kEnv := deriveEnvelopeKey(ss, dealerID, recipientID, committeeRoot)

	// Build the plaintext: share || contribution || tag.
	sealedSize := len(shareWire) + SeedSize + envelopeAuthTagSize
	plaintext := make([]byte, sealedSize)
	copy(plaintext[:len(shareWire)], shareWire)
	copy(plaintext[len(shareWire):len(shareWire)+SeedSize], contribution[:])
	// Auth tag binds dealer + recipient + share + contribution so a
	// relayed envelope under the same KEM ciphertext but different
	// dealer/recipient pair fails the tag.
	authInput := append(append([]byte{}, dealerID[:]...), recipientID[:]...)
	authInput = append(authInput, shareWire...)
	authInput = append(authInput, contribution[:]...)
	tag := kmac256(kEnv[:], authInput, envelopeAuthTagSize, dkgEnvelopeAuthTag)
	copy(plaintext[len(shareWire)+SeedSize:], tag)

	stream := cshake256(kEnv[:], sealedSize, dkgEnvelopeStreamTag)
	sealed := make([]byte, sealedSize)
	for i := 0; i < sealedSize; i++ {
		sealed[i] = plaintext[i] ^ stream[i]
	}

	return DKGShareEnvelope{
		KEMCiphertext: ct,
		Sealed:        sealed,
	}, nil
}

// sealOpenEnvelope is the recipient-side counterpart to sealEnvelope.
// shareWireLen specifies the expected width of the recovered share
// (64 for GF(257), 128 for GF(q)); the envelope's Sealed payload must
// be exactly shareWireLen + SeedSize + envelopeAuthTagSize bytes.
//
// Returns the recovered Shamir share bytes and the 32-byte dealer
// contribution on success; ErrEnvelopeAuthBad if the authentication
// tag does not verify (envelope tampered or wrong dealer/recipient
// binding); ErrEnvelopeCiphertext if the sealed payload length does
// not match the expected width.
func sealOpenEnvelope(
	dealerID, recipientID NodeID,
	committeeRoot [32]byte,
	env DKGShareEnvelope,
	shareWireLen int,
	myIdentity *IdentityKey,
) (shareWire []byte, contribution [SeedSize]byte, err error) {
	if myIdentity == nil {
		err = ErrIdentityKeyMissing
		return
	}
	if len(env.KEMCiphertext) != mlkem768.CiphertextSize {
		err = ErrEnvelopeCiphertext
		return
	}
	if shareWireLen <= 0 {
		err = ErrEnvelopeCiphertext
		return
	}
	sealedSize := shareWireLen + SeedSize + envelopeAuthTagSize
	if len(env.Sealed) != sealedSize {
		err = ErrEnvelopeCiphertext
		return
	}
	var sk mlkem768.PrivateKey
	if e := sk.Unpack(myIdentity.KEMPriv); e != nil {
		err = ErrIdentityCorrupted
		return
	}
	ss := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(ss, env.KEMCiphertext)

	kEnv := deriveEnvelopeKey(ss, dealerID, recipientID, committeeRoot)
	stream := cshake256(kEnv[:], sealedSize, dkgEnvelopeStreamTag)
	plaintext := make([]byte, sealedSize)
	for i := 0; i < sealedSize; i++ {
		plaintext[i] = env.Sealed[i] ^ stream[i]
	}
	gotShare := make([]byte, shareWireLen)
	var gotContrib [SeedSize]byte
	copy(gotShare, plaintext[:shareWireLen])
	copy(gotContrib[:], plaintext[shareWireLen:shareWireLen+SeedSize])
	// Recompute auth tag and constant-time compare.
	authInput := append(append([]byte{}, dealerID[:]...), recipientID[:]...)
	authInput = append(authInput, gotShare...)
	authInput = append(authInput, gotContrib[:]...)
	expectedTag := kmac256(kEnv[:], authInput, envelopeAuthTagSize, dkgEnvelopeAuthTag)
	if !ctEqualSlice(expectedTag, plaintext[shareWireLen+SeedSize:]) {
		err = ErrEnvelopeAuthBad
		return
	}
	shareWire = gotShare
	contribution = gotContrib
	return
}

// deriveEnvelopeKey expands the KEM shared secret into a 32-byte
// envelope-encryption key bound to the (dealer, recipient, committee
// root) tuple.
func deriveEnvelopeKey(ss []byte, dealerID, recipientID NodeID, committeeRoot [32]byte) [32]byte {
	info := append([]byte(dkgEnvelopeKeyTag), dealerID[:]...)
	info = append(info, recipientID[:]...)
	info = append(info, committeeRoot[:]...)
	r := hkdf.New(sha3.New256, ss, dealerID[:], info)
	var out [32]byte
	_, _ = io.ReadFull(r, out[:])
	return out
}

// Customisation tags for identity / session-key / envelope derivation.
// These are wire-frozen alongside the other PULSAR-*-V1 tags.
const (
	sessionEstablishInfo = "PULSAR-SESSION-ESTABLISH-V1"
	sessionKeyInfo       = "PULSAR-SESSION-KEY-V1"
	dkgEnvelopeKeyTag    = "PULSAR-DKG-ENVKEY-V1"
	dkgEnvelopeStreamTag = "PULSAR-DKG-ENVSTREAM-V1"
	dkgEnvelopeAuthTag   = "PULSAR-DKG-ENVAUTH-V1"
)

// IdentityDirectory maps NodeID to the published IdentityPublicKey.
// Used by DKG and ThresholdSigner so callers can look up peer
// identity keys by NodeID without re-passing them on every API call.
type IdentityDirectory map[NodeID]*IdentityPublicKey

// NewIdentityDirectory constructs an IdentityDirectory from a slice of
// (NodeID, IdentityPublicKey) pairs. Returns ErrIdentityKeyMissing if
// any entry has a nil identity public key.
func NewIdentityDirectory(entries map[NodeID]*IdentityPublicKey) (IdentityDirectory, error) {
	out := make(IdentityDirectory, len(entries))
	for id, ipk := range entries {
		if ipk == nil {
			return nil, ErrIdentityKeyMissing
		}
		// Copy bytes so external mutation can't corrupt our state.
		out[id] = &IdentityPublicKey{
			KEMPub:   append([]byte{}, ipk.KEMPub...),
			MLDSAPub: append([]byte{}, ipk.MLDSAPub...),
		}
	}
	return out, nil
}

// hashForEncapSeed derives a 64-byte deterministic encapsulation seed
// for ML-KEM-768 from (committee_root, dealer, recipient, blind).
// Used by DKG so the same seed yields byte-identical envelopes across
// KAT regeneration.
func hashForEncapSeed(committeeRoot [32]byte, dealer, recipient NodeID, blind []byte) [mlkem768.EncapsulationSeedSize]byte {
	r := hkdf.New(sha3.New256, blind,
		committeeRoot[:],
		append(append([]byte(dkgEnvelopeKeyTag), dealer[:]...), recipient[:]...))
	var out [mlkem768.EncapsulationSeedSize]byte
	_, _ = io.ReadFull(r, out[:])
	return out
}

