// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsard is the OFFLINE threshold ML-DSA (FIPS-204) signer service for
// the Lux Quasar "Pulsar" finality lane. It implements warp.PulsarThresholdSigner
// (github.com/luxfi/warp): a [Signer] drives a signing session over a 32-byte
// subject and emits ONE warp.PulsarEvidence carrying a single, standard
// FIPS-204 ML-DSA-65 signature. The chain verifies that evidence with
// warp.VerifyPulsar — a plain mldsa65.Verify under a group public key. None of
// the offline threshold machinery ever crosses the verification boundary.
//
//	PRODUCE (offline, here)                      VERIFY (on chain, in warp)
//	  dealerless nonce DKG, BCC, CEF,      ──►     one FIPS-204 ML-DSA-65 verify
//	  CSCP, blame, aggregate (TALUS)              (warp.VerifyPulsar)
//
// # Honest status (read before trusting anything)
//
// Threshold ML-DSA has no native FIPS-204 construction. FROST-style additive
// nonces do not work (ML-DSA's HighBits/r0 rounding is non-linear), so the
// dealerless path is the research-grade TALUS construction (Kao, arXiv:2603.22109).
// This package is scrupulously honest about what is real:
//
//   - REAL: the service shape (warp.PulsarThresholdSigner), the FIPS-204
//     ML-DSA-65 primitives (github.com/luxfi/crypto, the SAME library warp
//     verifies with, so sign/verify interoperate by construction), the key-era
//     /group-public-key records (warp.PulsarKeyEra, reused not re-declared),
//     session/nonce plumbing, the typed protocol round messages and the phase
//     state machine ([Session]), and a MANDATORY release gate ([ReleaseGate])
//     that re-runs warp.VerifyPulsar before any evidence is returned.
//
//   - FAIL-CLOSED STUB: the dealerless TALUS threshold crypto step. It lives
//     behind the [ThresholdEngine] SPI; the default engine ([Unimplemented])
//     returns [ErrThresholdMLDSAUnimplemented]. The intended construction and
//     the exact interop+trust contract a concrete engine must satisfy are
//     specified in docs/talus-design.tex. No fake threshold math is shipped:
//     an honest fail-closed stub is correct; unsound "looks-done" threshold
//     logic is not.
//
//   - REFERENCE-ONLY (dev/test FOOTGUN): [ReferenceDealer] is a single-party,
//     NON-threshold engine that holds the group secret in one process. It
//     exists ONLY to prove the end-to-end verify path: a real group ML-DSA-65
//     keypair, a real signature over the subject under the Pulsar lane context,
//     accepted by warp.VerifyPulsar. NEVER use it in production — it has no
//     threshold property whatsoever.
//
// # The boundary guarantee
//
// [Signer.ThresholdSign] NEVER returns evidence that does not verify. Whatever
// engine is plugged in, the signature is re-checked with warp.VerifyPulsar
// (under the resolved group key, the real subject, the real lane context)
// before it leaves the process. Correctness of emitted evidence is therefore a
// property of this package, independent of the engine's internals.
package pulsard
