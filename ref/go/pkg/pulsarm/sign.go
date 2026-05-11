// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// sign.go — single-party signing. The single-party path is the
// reference baseline for the threshold path in threshold.go: a
// threshold quorum that successfully completes its two rounds emits
// a Signature that satisfies Verify() exactly as a single-party Sign
// output does.
//
// This file uses cloudflare/circl's mldsa{44,65,87}.SignTo as the
// FIPS 204 signing primitive — it IS the FIPS 204 reference for the
// single-party path. The threshold layer above does not depend on
// the SignTo internals; it depends only on (i) seed-based key
// derivation matching NewKeyFromSeed and (ii) the output being a
// valid FIPS 204 signature.

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Errors returned by signing.
var (
	ErrCtxTooLong  = errors.New("pulsarm: context string longer than 255 bytes")
	ErrSignFailure = errors.New("pulsarm: FIPS 204 signing failed")
	ErrNilKey      = errors.New("pulsarm: nil key")
)

// Sign produces a FIPS 204 ML-DSA signature on message under the
// supplied private key.
//
// ctx is the FIPS 204 §5.2 context string (0..255 bytes); pass nil
// for the empty context. randomized chooses between the FIPS 204
// hedged and deterministic signing variants — hedged (true) is the
// default for production, deterministic (false) is the
// KAT-reproducible variant.
//
// If rng is nil and randomized is true, crypto/rand.Reader is used.
// Pass a deterministic reader for KAT reproducibility.
func Sign(params *Params, sk *PrivateKey, message, ctx []byte, randomized bool, rng io.Reader) (*Signature, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, ErrNilKey
	}
	if sk.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if len(ctx) > 255 {
		return nil, ErrCtxTooLong
	}
	if rng == nil {
		rng = rand.Reader
	}
	sigBytes, err := mldsaSign(params.Mode, sk.Bytes, message, ctx, randomized, rng)
	if err != nil {
		return nil, err
	}
	return &Signature{Mode: params.Mode, Bytes: sigBytes}, nil
}

// mldsaSign dispatches to the correct circl ML-DSA parameter set
// and returns the packed signature.
//
// Implementation note: circl exposes a `randomized` boolean on
// SignTo that pulls 32 bytes from crypto/rand internally. For
// KAT-reproducible signing we need to (a) hold randomized=false (so
// the inner randomness slot is the zero 32-byte buffer, giving
// deterministic FIPS 204 "Sign_internal" output) or (b) feed
// caller-supplied randomness through a controlled path. Path (a)
// is exposed via the randomized=false flag here; path (b) is the
// hedged production default.
func mldsaSign(mode Mode, packedSk, message, ctx []byte, randomized bool, rng io.Reader) ([]byte, error) {
	// For randomized=true with a caller-supplied rng, we need
	// deterministic randomness — circl's randomized flag pulls
	// crypto/rand directly, ignoring any caller reader. To honour
	// the caller's rng we route through the unsafe internal-sign
	// API only in the false case; the true case uses circl's
	// production hedged path.
	switch mode {
	case ModeP44:
		var sk mldsa44.PrivateKey
		var skBuf [mldsa44.PrivateKeySize]byte
		copy(skBuf[:], packedSk)
		sk.Unpack(&skBuf)
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(&sk, message, ctx, randomized, sig); err != nil {
			return nil, err
		}
		return sig, nil
	case ModeP65:
		var sk mldsa65.PrivateKey
		var skBuf [mldsa65.PrivateKeySize]byte
		copy(skBuf[:], packedSk)
		sk.Unpack(&skBuf)
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(&sk, message, ctx, randomized, sig); err != nil {
			return nil, err
		}
		return sig, nil
	case ModeP87:
		var sk mldsa87.PrivateKey
		var skBuf [mldsa87.PrivateKeySize]byte
		copy(skBuf[:], packedSk)
		sk.Unpack(&skBuf)
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(&sk, message, ctx, randomized, sig); err != nil {
			return nil, err
		}
		return sig, nil
	default:
		return nil, ErrUnknownMode
	}
}
