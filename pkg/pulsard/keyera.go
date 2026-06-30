// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// keyera.go — the Pulsar group-key records and the lane constants pulsard
// produces evidence under. The key-era record is warp.PulsarKeyEra reused
// verbatim (never re-declared): pulsard and the chain share ONE definition of
// "which group public key authorizes this era", so the two can never drift.

package pulsard

import (
	"errors"
	"fmt"
	"sync"

	mldsa65 "github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// LaneContext is the FIPS-204 §5.2 domain-separation context bound into every
// Pulsar ML-DSA-65 signature. It MUST equal warp's (unexported) pulsarLaneContext
// byte-for-byte: the offline signer signs with exactly this ctx and
// warp.VerifyPulsar verifies with it. We cannot import warp's private constant,
// so we re-declare its value and GUARD the equality with an end-to-end test
// (TestReferenceDealer_VerifiesUnderWarp): if warp ever changes the context,
// that test fails loudly because the produced signature stops verifying.
const LaneContext = "LUX-QUASAR-PULSAR-MLDSA65-v1"

// Suite is the SuiteID pulsard stamps on every PulsarEvidence and KeyEra. It is
// warp.SuitePulsarThresholdMLDSA65 ("Lux-Pulsar-TALUS-MLDSA65"); the "TALUS"
// token names the offline construction, while the on-wire object is a plain
// FIPS-204 signature.
const Suite = warp.SuitePulsarThresholdMLDSA65

// SubjectLen is the required width of a finality subject (a 32-byte digest: D
// for warp, M for quasar consensus). It is ids.IDLen, the exact width
// warp.VerifyPulsar enforces; producing a signature over any other width yields
// evidence the chain rejects, so pulsard fails closed before signing.
const SubjectLen = ids.IDLen

var (
	// ErrBadSubject is returned when a subject is not exactly SubjectLen bytes.
	ErrBadSubject = fmt.Errorf("pulsard: subject must be a %d-byte digest", SubjectLen)

	// ErrBadGroupKey is returned when group public-key bytes are not a
	// well-formed ML-DSA-65 public key (a malformed key can never verify).
	ErrBadGroupKey = errors.New("pulsard: malformed ML-DSA-65 group public key")

	// ErrKeyEraNotFound is returned by KeyEraStore when no era matches the
	// requested (signerSetID, keyEraID, generation). Fail closed — a missing
	// era never resolves to a default.
	ErrKeyEraNotFound = errors.New("pulsard: no Pulsar key era for those identifiers")
)

// ValidateSubject fails closed unless subject is exactly SubjectLen bytes. It is
// the FIRST check ThresholdSign runs: the offline machinery must never spend a
// nonce on a subject the chain will reject for width.
func ValidateSubject(subject []byte) error {
	if len(subject) != SubjectLen {
		return fmt.Errorf("%w: got %d bytes", ErrBadSubject, len(subject))
	}
	return nil
}

// NewKeyEra assembles a warp.PulsarKeyEra, centralizing the invariants the
// verify path depends on: SchemeID is pinned to Suite, and the group public key
// is validated as a real ML-DSA-65 key up front (so a malformed key is rejected
// at era creation, not silently at first verify). keygenMode is audit metadata
// ("talus-mpc", "ceremony", "tee", "reference-trusted-dealer", ...) and never
// changes verification.
func NewKeyEra(
	chainID, signerSetID ids.ID,
	keyEraID, generation, pChainHeight uint64,
	groupPub []byte,
	threshold warp.WeightThreshold,
	keygenMode string,
) (warp.PulsarKeyEra, error) {
	if len(groupPub) != mldsa65.PublicKeySize {
		return warp.PulsarKeyEra{}, fmt.Errorf("%w: got %d bytes, want %d",
			ErrBadGroupKey, len(groupPub), mldsa65.PublicKeySize)
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(groupPub); err != nil {
		return warp.PulsarKeyEra{}, fmt.Errorf("%w: %v", ErrBadGroupKey, err)
	}
	return warp.PulsarKeyEra{
		ChainID:      chainID,
		SignerSetID:  signerSetID,
		KeyEraID:     keyEraID,
		Generation:   generation,
		PChainHeight: pChainHeight,
		MLDSAPubKey:  append([]byte(nil), groupPub...),
		Threshold:    threshold,
		SchemeID:     Suite,
		KeygenMode:   keygenMode,
	}, nil
}

// eraKey identifies an era within a store.
type eraKey struct {
	signerSet  ids.ID
	keyEraID   uint64
	generation uint64
}

// KeyEraStore is an in-memory warp.PulsarKeyEraResolver: the offline-side
// registry mapping (signerSetID, keyEraID, generation) to the group key the
// chain will resolve. It is the SYMMETRIC offline counterpart of whatever
// on-chain resolver the verify path injects, and is safe for concurrent use.
type KeyEraStore struct {
	mu   sync.RWMutex
	eras map[eraKey]warp.PulsarKeyEra
}

// NewKeyEraStore returns an empty store.
func NewKeyEraStore() *KeyEraStore {
	return &KeyEraStore{eras: make(map[eraKey]warp.PulsarKeyEra)}
}

// Put records (or replaces) an era, keyed by its own identifiers.
func (s *KeyEraStore) Put(era warp.PulsarKeyEra) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eras[eraKey{era.SignerSetID, era.KeyEraID, era.Generation}] = era
}

// ResolvePulsarKeyEra implements warp.PulsarKeyEraResolver.
func (s *KeyEraStore) ResolvePulsarKeyEra(
	signerSetID ids.ID,
	keyEraID uint64,
	generation uint64,
) (warp.PulsarKeyEra, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	era, ok := s.eras[eraKey{signerSetID, keyEraID, generation}]
	if !ok {
		return warp.PulsarKeyEra{}, fmt.Errorf("%w: signerSet=%s era=%d gen=%d",
			ErrKeyEraNotFound, signerSetID, keyEraID, generation)
	}
	return era, nil
}

// compile-time: KeyEraStore is a warp.PulsarKeyEraResolver.
var _ warp.PulsarKeyEraResolver = (*KeyEraStore)(nil)
