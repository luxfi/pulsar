// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_sign.go — the TALUS one-round signing safety gate and the Quasar
// evidence binding. The signing ROUND itself is the existing no-reconstruct
// path (distributed_bcc.go): Round1 binds the canonical nonce cert and derives
// c = H(μ ‖ w1); Round2 broadcasts the proof-carrying z-partial
// z_i = λ_i·y_i + c·λ_i·s1_i; Finalize/AggregateBCC sums z, recovers the hint
// from public w' = A·z − c·t1·2^d, and emits a stock FIPS 204 signature. The
// ONLY difference between the two TALUS profiles is the offline w1 source:
//
//	Pulsar-TEE: a trusted coordinator/TEE forms w (DealNonceMPCDebug) and
//	            publishes w1 + the per-party y-shares. No honest-majority bound.
//	Pulsar-MPC: the CEF computes w1 over secret-shared ȳ (CEFComputeW1) with no
//	            node forming w; the y-shares come from the dealerless nonce DKG.
//
// This file adds (1) the fail-closed release gate that runs MANDATORY FIPS 204
// verification before any threshold signature is emitted, and (2) the Quasar
// evidence type that pins the parameter set and dispatches verification to the
// correct stock verifier — so no suite string can route a Pulsar leg to the
// Corona verifier or to the wrong ML-DSA parameter set.

import (
	"errors"
	"fmt"
)

var (
	// ErrTalusNoSignature is returned by the release gate when handed an empty
	// signature (aggregation failed, e.g. a non-boundary-clear nonce) — a
	// missing signature is never released as success.
	ErrTalusNoSignature = errors.New("pulsar: TALUS release gate handed no signature (failed aggregation / non-clear nonce)")
	// ErrTalusVerifyRejected wraps a stock FIPS 204 verification failure at the
	// release gate. A signature that fails stock verify is NEVER released.
	ErrTalusVerifyRejected = errors.New("pulsar: TALUS release gate rejected — signature failed stock FIPS 204 verification")
	// ErrTalusEvidenceSuiteMismatch guards the evidence verifier against a suite
	// string whose pinned parameter set disagrees with the signature's mode.
	ErrTalusEvidenceSuiteMismatch = errors.New("pulsar: TALUS evidence suite/mode mismatch — refusing to dispatch to the wrong verifier")
)

// TalusReleaseGate is the MANDATORY pre-release verification (TALUS safety
// gate 4): it runs stock FIPS 204 verification on the aggregated signature and
// NEVER returns a signature that fails. Both profiles route their Finalize
// output through it; a failed BCC/hint/z-bound surfaces as an empty signature
// (ErrTalusNoSignature) and a forged or malformed signature surfaces as
// ErrTalusVerifyRejected — neither is ever released. ctx is the optional FIPS
// 204 §5.4 context (empty for the bare path).
func TalusReleaseGate(params *Params, setup *AlgSetup, msg, ctx []byte, cert ConsensusCert) (ConsensusCert, error) {
	if err := params.Validate(); err != nil {
		return ConsensusCert{}, err
	}
	if setup == nil || setup.Pub == nil {
		return ConsensusCert{}, ErrCEFShape
	}
	if len(cert.Signature.Bytes) == 0 {
		return ConsensusCert{}, ErrTalusNoSignature
	}
	var verifyErr error
	if len(ctx) > 0 {
		verifyErr = VerifyCtx(params, setup.Pub, msg, ctx, &cert.Signature)
	} else {
		verifyErr = Verify(params, setup.Pub, msg, &cert.Signature)
	}
	if verifyErr != nil {
		return ConsensusCert{}, fmt.Errorf("%w: %v", ErrTalusVerifyRejected, verifyErr)
	}
	return cert, nil
}

// TalusEvidence is the Quasar consensus evidence binding for a TALUS threshold
// ML-DSA finality leg. Its Kind is EvidenceKindPulsarTALUS (distinct from
// Corona's), and its Suite pins the FIPS parameter set, so the consensus layer
// dispatches it to the correct stock verifier and never confuses a Pulsar leg
// with a Corona one or with the wrong ML-DSA level. It carries only public
// artifacts: the group-key id, the signer bitmap, and the stock FIPS 204
// signature.
type TalusEvidence struct {
	Kind         string
	Suite        TalusSuite
	Profile      TalusProfile
	GroupPKID    [32]byte
	SignerBitmap []byte
	Signature    Signature
}

// NewTalusEvidence binds a finalized ConsensusCert into Quasar evidence,
// pinning the parameter set via the suite. It refuses parameter sets outside
// the BCC-proven scope (ML-DSA-44).
func NewTalusEvidence(profile TalusProfile, setup *AlgSetup, cert ConsensusCert) (*TalusEvidence, error) {
	if setup == nil {
		return nil, ErrCEFShape
	}
	suite, err := TalusSuiteFor(setup.Mode)
	if err != nil {
		return nil, err
	}
	if cert.Signature.Mode != setup.Mode {
		return nil, ErrTalusEvidenceSuiteMismatch
	}
	return &TalusEvidence{
		Kind:         EvidenceKindPulsarTALUS,
		Suite:        suite,
		Profile:      profile,
		GroupPKID:    pkID(setup.Pub),
		SignerBitmap: append([]byte(nil), cert.SignerBitmap...),
		Signature:    cert.Signature,
	}, nil
}

// Verify checks the evidence's stock FIPS 204 signature against the group public
// key and message, dispatching by the pinned Suite. It enforces that the suite's
// parameter set matches the signature's mode (so a mislabeled suite cannot route
// to the wrong verifier) and then calls the stateless stock verifier
// (VerifyBytes → cloudflare/circl mldsa{65,87}.Verify). groupPKBytes is the
// FIPS 204 packed group public key; for the FIPS 204 §5.4 ctx-bound path, msg is
// the already-ctx-bound message representative the signer used.
func (e *TalusEvidence) Verify(groupPKBytes, msg []byte) error {
	if e.Kind != EvidenceKindPulsarTALUS {
		return ErrTalusEvidenceSuiteMismatch
	}
	suiteMode, err := e.Suite.Mode()
	if err != nil {
		return err
	}
	if suiteMode != e.Signature.Mode {
		return ErrTalusEvidenceSuiteMismatch
	}
	sigBytes, err := e.Signature.MarshalBinary()
	if err != nil {
		return err
	}
	if !VerifyBytes(groupPKBytes, msg, sigBytes) {
		return ErrTalusVerifyRejected
	}
	return nil
}
