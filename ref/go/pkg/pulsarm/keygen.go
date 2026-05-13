// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// keygen.go — single-party key generation. This is the FIPS 204
// keygen path; the threshold-N4 distributed counterpart lives in
// dkg.go.
//
// Output: a FIPS 204 ML-DSA key pair. The public key is byte-equal
// to what FIPS 204 KeyGen would emit on the same seed; the private
// key carries the seed alongside the packed key so the threshold
// layer can reproduce shares deterministically.

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Errors returned by keygen and the surrounding key-handling layer.
var (
	ErrShortRand     = errors.New("pulsarm: short read from entropy source")
	ErrSeedRequired  = errors.New("pulsarm: seed-derived keygen requires 32-byte seed")
	ErrModeMismatch  = errors.New("pulsarm: mode mismatch")
	ErrInvalidPubKey = errors.New("pulsarm: invalid public-key length")
	ErrInvalidPriv   = errors.New("pulsarm: invalid private-key length")
)

// GenerateKey produces a fresh single-party Pulsar key pair. The
// generated key is a FIPS 204 ML-DSA key pair: the public key
// verifies under unmodified mldsa{44,65,87}.Verify.
//
// rand may be nil; if so crypto/rand.Reader is used. Pass a
// deterministic reader (e.g. bytes.NewReader of a fixed seed) for
// KAT-reproducible key generation.
func GenerateKey(params *Params, rng io.Reader) (*PrivateKey, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if rng == nil {
		rng = rand.Reader
	}
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rng, seed[:]); err != nil {
		return nil, ErrShortRand
	}
	return KeyFromSeed(params, seed)
}

// KeyFromSeed deterministically derives a Pulsar key pair from a
// 32-byte seed. This is the canonical seed-based keygen path used by
// every KAT and by the DKG aggregation step.
//
// The seed is copied into the returned PrivateKey so that callers
// can zeroize their input buffer immediately on return.
func KeyFromSeed(params *Params, seed [SeedSize]byte) (*PrivateKey, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	pubBytes, privBytes, err := mldsaKeyFromSeed(params.Mode, seed)
	if err != nil {
		return nil, err
	}
	pub := &PublicKey{Mode: params.Mode, Bytes: pubBytes}
	return &PrivateKey{
		Mode:  params.Mode,
		Bytes: privBytes,
		Seed:  seed,
		Pub:   pub,
	}, nil
}

// mldsaKeyFromSeed dispatches to the correct circl ML-DSA parameter
// set and returns packed (pub, priv). This is the only place in the
// package that touches the underlying FIPS 204 implementation.
func mldsaKeyFromSeed(mode Mode, seed [SeedSize]byte) ([]byte, []byte, error) {
	switch mode {
	case ModeP44:
		pk, sk := mldsa44.NewKeyFromSeed(&seed)
		var packedPub [mldsa44.PublicKeySize]byte
		pk.Pack(&packedPub)
		var packedPriv [mldsa44.PrivateKeySize]byte
		sk.Pack(&packedPriv)
		return append([]byte{}, packedPub[:]...), append([]byte{}, packedPriv[:]...), nil
	case ModeP65:
		pk, sk := mldsa65.NewKeyFromSeed(&seed)
		var packedPub [mldsa65.PublicKeySize]byte
		pk.Pack(&packedPub)
		var packedPriv [mldsa65.PrivateKeySize]byte
		sk.Pack(&packedPriv)
		return append([]byte{}, packedPub[:]...), append([]byte{}, packedPriv[:]...), nil
	case ModeP87:
		pk, sk := mldsa87.NewKeyFromSeed(&seed)
		var packedPub [mldsa87.PublicKeySize]byte
		pk.Pack(&packedPub)
		var packedPriv [mldsa87.PrivateKeySize]byte
		sk.Pack(&packedPriv)
		return append([]byte{}, packedPub[:]...), append([]byte{}, packedPriv[:]...), nil
	default:
		return nil, nil, ErrUnknownMode
	}
}

// Public returns this key's public companion.
func (sk *PrivateKey) Public() *PublicKey {
	return sk.Pub
}

// Equal reports whether two public keys are byte-equal under the
// same mode. Constant-time per byte.
func (p *PublicKey) Equal(other *PublicKey) bool {
	if p == nil || other == nil {
		return false
	}
	if p.Mode != other.Mode {
		return false
	}
	if len(p.Bytes) != len(other.Bytes) {
		return false
	}
	var diff byte
	for i := range p.Bytes {
		diff |= p.Bytes[i] ^ other.Bytes[i]
	}
	return diff == 0
}
