// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// engine.go — the ThresholdEngine SPI: the seam between pulsard's real control
// plane (session/state-machine/release-gate) and the threshold CRYPTO plane.
//
// An engine takes a [Session] and returns ONE standard FIPS-204 ML-DSA-65
// signature over the subject. pulsard ships exactly two engines and a third is
// documented-but-deliberately-absent:
//
//   - [Unimplemented] (DEFAULT) — the dealerless TALUS engine is research-grade
//     (no native FIPS-204 thresholdization exists; see doc.go and
//     docs/talus-design.tex). Rather than ship unsound "looks-done" threshold
//     math, the default engine fails closed with [ErrThresholdMLDSAUnimplemented].
//
//   - [ReferenceDealer] (DEV/TEST FOOTGUN) — a single-party, NON-threshold
//     engine that holds the group secret in one process. It proves the verify
//     path end-to-end and nothing more.
//
//   - The concrete dealerless TALUS engine (github.com/luxfi/pulsar) is NOT
//     registered here on purpose: its keygen is currently trusted-dealer and its
//     secure-comparison layer is semi-honest, so wiring it as "dealerless" would
//     overclaim. docs/talus-design.tex states the exact interop+trust contract
//     it must satisfy before it can be plugged into this SPI.

package pulsard

import (
	"errors"

	"github.com/luxfi/warp"
)

// ErrThresholdMLDSAUnimplemented is returned by the default engine for every
// crypto operation. It is the honest fail-closed signal that no sound dealerless
// threshold ML-DSA engine is wired: pulsard refuses to emit a signature rather
// than fake one.
var ErrThresholdMLDSAUnimplemented = errors.New(
	"pulsard: dealerless threshold ML-DSA (TALUS) is fail-closed pending review — " +
		"no concrete ThresholdEngine is registered (see docs/talus-design.tex); " +
		"the default engine never produces a signature")

// ThresholdEngine is the crypto plane: it produces a single standard FIPS-204
// ML-DSA-65 signature from threshold shares. Implementations MUST sign the
// session's subject with the [LaneContext] under the era's group key. They need
// not self-verify — the [Signer] release-gates every signature through
// warp.VerifyPulsar before emitting evidence, so a buggy or malicious engine
// can never cause non-verifying evidence to leave the process.
type ThresholdEngine interface {
	// Name identifies the engine for audit / KeyEra.KeygenMode. It NEVER affects
	// verification, which is always a plain ML-DSA check.
	Name() string

	// ProduceSignature drives the offline protocol over sess and returns the raw
	// FIPS-204 ML-DSA-65 signature bytes over sess.Subject(). A returned error
	// means no signature is produced (fail closed).
	ProduceSignature(sess *Session) ([]byte, error)

	// Reshare runs a proactive refresh that advances era.Generation while
	// PRESERVING era.MLDSAPubKey (so old signatures still verify), returning the
	// refreshed era.
	Reshare(era warp.PulsarKeyEra) (warp.PulsarKeyEra, error)
}

// Unimplemented returns the default fail-closed engine. Every operation returns
// ErrThresholdMLDSAUnimplemented.
func Unimplemented() ThresholdEngine { return unimplementedEngine{} }

type unimplementedEngine struct{}

func (unimplementedEngine) Name() string { return "talus-unimplemented" }

func (unimplementedEngine) ProduceSignature(*Session) ([]byte, error) {
	return nil, ErrThresholdMLDSAUnimplemented
}

func (unimplementedEngine) Reshare(warp.PulsarKeyEra) (warp.PulsarKeyEra, error) {
	return warp.PulsarKeyEra{}, ErrThresholdMLDSAUnimplemented
}

// compile-time: the default engine satisfies the SPI.
var _ ThresholdEngine = unimplementedEngine{}
