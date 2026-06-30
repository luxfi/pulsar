// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// reference.go — the ReferenceDealer: a single-party, NON-threshold engine.
//
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║ FOOTGUN — DEV / TEST ONLY. NEVER USE IN PRODUCTION.                       ║
// ║ The ReferenceDealer holds the ENTIRE group ML-DSA-65 secret key in ONE    ║
// ║ process. It has NO threshold property: one machine can forge a quorum     ║
// ║ signature. It exists solely to prove the verify path end-to-end — a real  ║
// ║ group keypair, a real signature over the subject under the Pulsar lane    ║
// ║ context, accepted by warp.VerifyPulsar — while the dealerless TALUS engine ║
// ║ remains fail-closed (engine.go, docs/talus-design.tex).                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝
//
// This mirrors corona's trusted-dealer footgun: a deliberately-labeled, single-
// party reference so the surrounding service can be exercised before the real
// dealerless ceremony exists.

package pulsard

import (
	"crypto/rand"
	"errors"
	"io"

	mldsa65 "github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// ReferenceKeygenMode is the KeyEra.KeygenMode tag stamped on eras produced by
// the ReferenceDealer, so audit can always tell a reference-keyed era from a
// real ceremony-keyed one.
const ReferenceKeygenMode = "reference-trusted-dealer"

// ErrDealerClosed is returned when a ReferenceDealer is used after Close.
var ErrDealerClosed = errors.New("pulsard: reference dealer is closed (secret dropped)")

// ReferenceDealer is the single-party reference engine (FOOTGUN — see file
// header). It satisfies ThresholdEngine but performs no threshold protocol: it
// simply signs with the group secret it holds.
type ReferenceDealer struct {
	sk  *mldsa65.PrivateKey
	pub []byte
}

// NewReferenceDealer generates a fresh group ML-DSA-65 keypair and returns the
// dealer plus the warp.PulsarKeyEra it keys (KeygenMode = ReferenceKeygenMode).
// randSrc nil uses crypto/rand. FOOTGUN: the returned dealer holds the whole
// secret.
func NewReferenceDealer(
	chainID, signerSetID ids.ID,
	keyEraID, generation, pChainHeight uint64,
	threshold warp.WeightThreshold,
	randSrc io.Reader,
) (*ReferenceDealer, warp.PulsarKeyEra, error) {
	if randSrc == nil {
		randSrc = rand.Reader
	}
	pk, sk, err := mldsa65.GenerateKey(randSrc)
	if err != nil {
		return nil, warp.PulsarKeyEra{}, err
	}
	return newReferenceDealer(pk, sk, chainID, signerSetID, keyEraID, generation, pChainHeight, threshold)
}

// NewReferenceDealerFromSeed derives the group keypair deterministically from a
// seed (FIPS-204 §5.1 ξ via mldsa65.NewKeyFromSeed), for reproducible tests and
// known-answer vectors. FOOTGUN — see file header.
func NewReferenceDealerFromSeed(
	seed []byte,
	chainID, signerSetID ids.ID,
	keyEraID, generation, pChainHeight uint64,
	threshold warp.WeightThreshold,
) (*ReferenceDealer, warp.PulsarKeyEra, error) {
	pk, sk, err := mldsa65.NewKeyFromSeed(seed)
	if err != nil {
		return nil, warp.PulsarKeyEra{}, err
	}
	return newReferenceDealer(pk, sk, chainID, signerSetID, keyEraID, generation, pChainHeight, threshold)
}

func newReferenceDealer(
	pk *mldsa65.PublicKey, sk *mldsa65.PrivateKey,
	chainID, signerSetID ids.ID,
	keyEraID, generation, pChainHeight uint64,
	threshold warp.WeightThreshold,
) (*ReferenceDealer, warp.PulsarKeyEra, error) {
	pub, err := pk.MarshalBinary()
	if err != nil {
		return nil, warp.PulsarKeyEra{}, err
	}
	era, err := NewKeyEra(chainID, signerSetID, keyEraID, generation, pChainHeight, pub, threshold, ReferenceKeygenMode)
	if err != nil {
		return nil, warp.PulsarKeyEra{}, err
	}
	return &ReferenceDealer{sk: sk, pub: pub}, era, nil
}

// Name identifies the engine.
func (d *ReferenceDealer) Name() string { return ReferenceKeygenMode }

// ProduceSignature signs the session's subject with the group secret under the
// LaneContext, deterministically (FIPS-204 §5.2 hedged-off for reproducible
// output). The result is an ordinary ML-DSA-65 signature, identical in every
// byte to what a correct threshold ceremony must produce.
func (d *ReferenceDealer) ProduceSignature(sess *Session) ([]byte, error) {
	if d.sk == nil {
		return nil, ErrDealerClosed
	}
	return mldsa65.Sign(d.sk, sess.Subject(), []byte(LaneContext), false)
}

// Reshare is a no-op refresh for the single-party reference: it advances the
// Generation while preserving the (single) group key, so old signatures still
// verify. A real engine reshapes the secret SHARES here; the public key is
// invariant in both.
func (d *ReferenceDealer) Reshare(era warp.PulsarKeyEra) (warp.PulsarKeyEra, error) {
	if d.sk == nil {
		return warp.PulsarKeyEra{}, ErrDealerClosed
	}
	era.Generation++
	return era, nil
}

// Close drops the secret reference so it can be garbage-collected. NOTE: the
// underlying CIRCL ML-DSA private key does not expose in-place zeroization, so
// this releases rather than wipes the buffer — acceptable for the dev/test
// footgun this type is.
func (d *ReferenceDealer) Close() { d.sk = nil }

// NewReferenceSigner is the one-call dev/test path: it builds a ReferenceDealer
// and wraps it in a Signer, returning the Signer and the era it keys. The Signer
// satisfies warp.PulsarThresholdSigner and its emitted evidence verifies under
// warp.VerifyPulsar (proven by TestReferenceDealer_VerifiesUnderWarp). FOOTGUN —
// see file header.
func NewReferenceSigner(
	chainID, signerSetID ids.ID,
	keyEraID, generation, pChainHeight uint64,
	threshold warp.WeightThreshold,
	randSrc io.Reader,
) (*Signer, warp.PulsarKeyEra, error) {
	dealer, era, err := NewReferenceDealer(chainID, signerSetID, keyEraID, generation, pChainHeight, threshold, randSrc)
	if err != nil {
		return nil, warp.PulsarKeyEra{}, err
	}
	signer, err := New(era, WithEngine(dealer))
	if err != nil {
		return nil, warp.PulsarKeyEra{}, err
	}
	return signer, era, nil
}

// compile-time: ReferenceDealer satisfies the engine SPI.
var _ ThresholdEngine = (*ReferenceDealer)(nil)
