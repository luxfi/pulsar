// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// bench_verify_test.go — DECOMPLECTED benchmark, ONE concern: the cost of
// VERIFYING a committee-produced threshold signature under the stock FIPS-204
// verifier (verify.go → cloudflare/circl mldsa{65,87}.Verify). This is the
// cheap baseline the whole dealerless line is measured against: every signing
// path above (RSS reconstruct, hyperball no-reconstruct, BCC distributed) emits
// a byte-stock-FIPS-204 signature, so verification is identical to single-key
// verification — the verifier never learns the signature was produced by a
// committee.
//
// What this isolates: a genuine COMMITTEE output (dealerless RSS keygen →
// threshold Sign) is produced in setup (not timed); the timed op is VerifyCtx
// on the group public key. The expectation — and the finding — is that this
// equals the existing single-key BenchmarkVerify_P65/P87 (bench_test.go) to
// within noise: threshold output verifies at stock cost. The committee size is
// irrelevant to verify (it sees only the fixed-size group pk + signature), so
// one committee per mode suffices.
//
// Scope: ML-DSA-65/87 (the threshold-signing scope; the RSS Sign path is
// BCC-proven for 65/87 only).
//
// Run:
//
//	cd pulsar && export SDKROOT="$(xcrun --show-sdk-path)"; export GOWORK=off
//	go test -run='^$' -bench=BenchmarkCommitteeOutputVerify -benchmem ./ref/go/pkg/pulsar/
package pulsar

import (
	"fmt"
	"testing"
)

// committeeVerifyModes — the threshold-signing scope.
var committeeVerifyModes = []Mode{ModeP65, ModeP87}

// committeeOutputVerifyBudget is a generous reconstruct-sign attempt ceiling so
// the setup signature is produced reliably (setup is not timed).
const committeeOutputVerifyBudget = 1024

// BenchmarkCommitteeOutputVerify measures VerifyCtx on a real committee-produced
// signature. Keygen + threshold Sign are setup; the timed op is verification.
func BenchmarkCommitteeOutputVerify(b *testing.B) {
	msg := []byte("Quasar finality subject M — committee-output verify baseline")

	for _, mode := range committeeVerifyModes {
		mode := mode
		b.Run(mode.String(), func(b *testing.B) {
			params, err := ParamsFor(mode)
			if err != nil {
				b.Fatalf("ParamsFor(%s): %v", mode, err)
			}
			// A small high-threshold committee — keygen is cheap, the output is
			// a genuine dealerless threshold signature. n=8,t=8 (C=8).
			mk, err := MithrilRSSKeygen(mode, 8, 8, mithrilSeeds(8))
			if err != nil {
				b.Fatalf("MithrilRSSKeygen(%s): %v", mode, err)
			}
			active := canonicalActive(8)
			rng := newBCCDeterministicRNG(fmt.Sprintf("VERIFY/SETUP/%s", mode))
			sig, err := mk.Sign(active, msg, nil, rng, committeeOutputVerifyBudget)
			if err != nil {
				b.Fatalf("committee Sign(%s): %v", mode, err)
			}
			pk := &PublicKey{Mode: mode, Bytes: mk.Pub()}

			// Confirm validity once before timing (fail-closed baseline).
			if err := VerifyCtx(params, pk, msg, nil, sig); err != nil {
				b.Fatalf("committee output rejected by stock verifier (%s): %v", mode, err)
			}

			b.ReportMetric(float64(len(sig.Bytes)), "sig_bytes")
			b.ReportMetric(float64(len(pk.Bytes)), "pk_bytes")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := VerifyCtx(params, pk, msg, nil, sig); err != nil {
					b.Fatalf("VerifyCtx(%s) at iter %d: %v", mode, i, err)
				}
			}
		})
	}
}
