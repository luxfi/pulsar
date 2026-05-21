// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/sha3"
)

// fakeQuoter is a software-only TEEQuoter used to pin the binding
// between the aggregator's claimed report-data and the embedded
// signature event. Production deployments wire in a real SGX/SEV/TDX
// quoter; this test surface exists only so we can pin the function's
// contract end-to-end.
type fakeQuoter struct {
	platform    string
	measurement []byte
	failWith    error
}

func (f *fakeQuoter) Platform() string         { return f.platform }
func (f *fakeQuoter) EnclaveMeasurement() []byte { return f.measurement }
func (f *fakeQuoter) Quote(reportData []byte) ([]byte, error) {
	if f.failWith != nil {
		return nil, f.failWith
	}
	// A real quote envelope is platform-specific. For test purposes we
	// build a synthetic envelope whose internal layout is:
	//   measurement (32 B) || reportData (64 B) || sha3-256(quote prefix)
	// so the verifier can recover both fields without a vendor parser.
	envelope := make([]byte, 0, len(f.measurement)+len(reportData)+32)
	envelope = append(envelope, f.measurement...)
	envelope = append(envelope, reportData...)
	tail := sha3.Sum256(envelope)
	envelope = append(envelope, tail[:]...)
	return envelope, nil
}

func TestCombineWithAttestation_RoundTrip(t *testing.T) {
	params := MustParamsFor(ModeP65)
	pub, shares, _, ident := runDKGWithIdentities(t, 5, 3, ModeP65)

	msg := []byte("threshold sign with TEE attestation")
	var sid [16]byte
	copy(sid[:], "pulsar-tee-01")
	attempt := uint32(1)
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, err := NewThresholdSigner(params, sid, attempt, quorum, shares[i], sessionKeys[shares[i].NodeID], msg, deterministicReader([]byte{byte(i), 0xEE}))
		if err != nil {
			t.Fatal(err)
		}
		signers[i] = s
	}

	r1 := make([]*Round1Message, 3)
	for i, s := range signers {
		m, err := s.Round1(msg)
		if err != nil {
			t.Fatalf("Round1 %d: %v", i, err)
		}
		r1[i] = m
	}
	r2 := make([]*Round2Message, 3)
	for i, s := range signers {
		m, _, err := s.Round2(r1)
		if err != nil {
			t.Fatalf("Round2 %d: %v", i, err)
		}
		r2[i] = m
	}

	measurement := bytes.Repeat([]byte{0x4D}, 32)
	q := &fakeQuoter{platform: "sgx-dcap", measurement: measurement}

	sig, err := CombineWithAttestation(params, pub, msg, nil, false, sid, attempt, quorum, 3, r1, r2, shares, q)
	if err != nil {
		t.Fatalf("CombineWithAttestation: %v", err)
	}

	// The signature must verify under stock FIPS 204 — the TEE
	// attestation is an ADDITIONAL layer, never a replacement for
	// signature verification.
	if err := Verify(params, pub, msg, sig); err != nil {
		t.Fatalf("FIPS 204 Verify rejected the threshold-produced sig: %v", err)
	}

	// The attestation must be present and well-formed.
	if sig.Attestation == nil {
		t.Fatal("Attestation is nil — quoter was wired but produced no attestation")
	}
	if sig.Attestation.Platform != "sgx-dcap" {
		t.Errorf("Platform = %q want sgx-dcap", sig.Attestation.Platform)
	}
	if !bytes.Equal(sig.Attestation.EnclaveMeasurement, measurement) {
		t.Errorf("EnclaveMeasurement mismatch")
	}
	if len(sig.Attestation.ReportData) != 64 {
		t.Fatalf("ReportData len = %d want 64 (SGX REPORT_DATA slot width)", len(sig.Attestation.ReportData))
	}

	// Report-data must match the canonical binding.
	wantReport := CombineReportData(sid, attempt, pub, msg)
	if !bytes.Equal(sig.Attestation.ReportData, wantReport) {
		t.Error("ReportData does not match CombineReportData(sid,attempt,pub,msg)")
	}

	// Quote must embed both measurement and report-data verbatim.
	embeddedMeasurement := sig.Attestation.Quote[:32]
	embeddedReportData := sig.Attestation.Quote[32:96]
	if !bytes.Equal(embeddedMeasurement, measurement) {
		t.Error("Quote did not embed measurement at the expected offset")
	}
	if !bytes.Equal(embeddedReportData, sig.Attestation.ReportData) {
		t.Error("Quote did not embed report-data at the expected offset")
	}
}

func TestCombineWithAttestation_NoQuoter_ProducesPlainSignature(t *testing.T) {
	params := MustParamsFor(ModeP65)
	pub, shares, _, ident := runDKGWithIdentities(t, 5, 3, ModeP65)

	msg := []byte("no quoter wired — bare Combine")
	var sid [16]byte
	copy(sid[:], "pulsar-tee-02")
	attempt := uint32(1)
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, err := NewThresholdSigner(params, sid, attempt, quorum, shares[i], sessionKeys[shares[i].NodeID], msg, deterministicReader([]byte{byte(i), 0xEE}))
		if err != nil {
			t.Fatal(err)
		}
		signers[i] = s
	}

	r1 := make([]*Round1Message, 3)
	for i, s := range signers {
		m, _ := s.Round1(msg)
		r1[i] = m
	}
	r2 := make([]*Round2Message, 3)
	for i, s := range signers {
		m, _, _ := s.Round2(r1)
		r2[i] = m
	}

	sig, err := CombineWithAttestation(params, pub, msg, nil, false, sid, attempt, quorum, 3, r1, r2, shares, nil)
	if err != nil {
		t.Fatalf("CombineWithAttestation(nil quoter): %v", err)
	}
	if sig.Attestation != nil {
		t.Error("Attestation is non-nil despite nil quoter")
	}
	if err := Verify(params, pub, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestCombineWithAttestation_QuoterError_DiscardsSignature(t *testing.T) {
	params := MustParamsFor(ModeP65)
	pub, shares, _, ident := runDKGWithIdentities(t, 5, 3, ModeP65)

	msg := []byte("quoter fails — no signature should be returned")
	var sid [16]byte
	copy(sid[:], "pulsar-tee-03")
	attempt := uint32(1)
	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

	signers := make([]*ThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, err := NewThresholdSigner(params, sid, attempt, quorum, shares[i], sessionKeys[shares[i].NodeID], msg, deterministicReader([]byte{byte(i), 0xEE}))
		if err != nil {
			t.Fatal(err)
		}
		signers[i] = s
	}

	r1 := make([]*Round1Message, 3)
	for i, s := range signers {
		m, _ := s.Round1(msg)
		r1[i] = m
	}
	r2 := make([]*Round2Message, 3)
	for i, s := range signers {
		m, _, _ := s.Round2(r1)
		r2[i] = m
	}

	wantErr := errors.New("tee: enclave attestation service unreachable")
	q := &fakeQuoter{platform: "sgx-dcap", measurement: bytes.Repeat([]byte{0x4D}, 32), failWith: wantErr}

	sig, err := CombineWithAttestation(params, pub, msg, nil, false, sid, attempt, quorum, 3, r1, r2, shares, q)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v want %v (quoter failure must propagate)", err, wantErr)
	}
	if sig != nil {
		t.Error("sig is non-nil despite quoter error — caller must NOT receive a signature without attestation when one was requested")
	}
}

func TestCombineReportData_Stable(t *testing.T) {
	// Pure-function property: same inputs ⇒ same 64-byte output.
	var sid [16]byte
	copy(sid[:], "stable-report-01")
	pub := &PublicKey{Mode: ModeP65, Bytes: bytes.Repeat([]byte{0xAB}, 32)}
	msg := []byte("hello pulsar")

	a := CombineReportData(sid, 7, pub, msg)
	b := CombineReportData(sid, 7, pub, msg)
	if !bytes.Equal(a, b) {
		t.Fatal("CombineReportData is not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("CombineReportData length = %d want 64", len(a))
	}

	// Different attempt ⇒ different report-data.
	c := CombineReportData(sid, 8, pub, msg)
	if bytes.Equal(a, c) {
		t.Error("ReportData collides across distinct attempts")
	}

	// Different message ⇒ different report-data.
	d := CombineReportData(sid, 7, pub, []byte("hello pulsar!"))
	if bytes.Equal(a, d) {
		t.Error("ReportData collides across distinct messages")
	}
}
