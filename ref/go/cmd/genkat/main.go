// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// genkat is the canonical KAT (Known Answer Test) generator for
// Pulsar. It produces the JSON vector files committed under
// vectors/ — keygen, sign, verify, threshold-sign, dkg.
//
// Re-running genkat on a clean checkout MUST produce byte-identical
// output. Drift is a CI failure. The deterministic-fixture gate is
// validated by scripts/gen_vectors.sh re-running this binary and
// diffing against the committed JSON.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	pm "github.com/luxfi/pulsar/ref/go/pkg/pulsarm"
)

// MasterSeed is the head-of-file 48-byte seed from which every KAT
// in the file is reproducible. Re-running genkat with the same
// MasterSeed gives bit-identical output.
const masterSeedHex = "e72de37c9c46cabcb45ed59f76ddf0937d3cc7a9fed9b1f23a30b9c98e8f1f59" +
	"3a9bd1e6f5c12f4e3082a18b6e75d27a"

type KeygenKAT struct {
	Mode      string `json:"mode"`
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type SignKAT struct {
	Mode      string `json:"mode"`
	Seed      string `json:"seed"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
}

type VerifyKAT struct {
	Mode      string `json:"mode"`
	PublicKey string `json:"public_key"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
	Valid     bool   `json:"valid"`
}

type ThresholdSignKAT struct {
	Mode      string   `json:"mode"`
	N         int      `json:"n"`
	T         int      `json:"t"`
	Message   string   `json:"message"`
	PublicKey string   `json:"public_key"`
	Signature string   `json:"signature"`
	Quorum    []string `json:"quorum"`
	SessionID string   `json:"session_id"`
	Attempt   uint32   `json:"attempt"`
}

type DKGKAT struct {
	Mode           string   `json:"mode"`
	N              int      `json:"n"`
	T              int      `json:"t"`
	Committee      []string `json:"committee"`
	PublicKey      string   `json:"public_key"`
	TranscriptHash string   `json:"transcript_hash"`
	Shares         []string `json:"shares"` // per-party packed share (64 bytes hex)
}

// detReader is a deterministic byte stream from a seed via cSHAKE256.
type detReader struct {
	seed []byte
	buf  []byte
	off  int
}

func newDetReader(seed []byte) *detReader {
	return &detReader{seed: seed}
}

func (r *detReader) Read(p []byte) (int, error) {
	// We pull blocks of 4096 bytes via SHA-256 chaining for clean
	// determinism without requiring the pulsarm package's internal
	// cshake256. SHA-256(seed || counter) → 32 bytes per block.
	for n := 0; n < len(p); {
		if r.off >= len(r.buf) {
			ctr := uint32(len(r.buf) / 32)
			r.buf = nil
			for i := 0; i < 128; i++ {
				h := sha256.New()
				h.Write(r.seed)
				h.Write([]byte{byte(ctr >> 24), byte(ctr >> 16), byte(ctr >> 8), byte(ctr)})
				r.buf = append(r.buf, h.Sum(nil)...)
				ctr++
			}
			r.off = 0
		}
		c := copy(p[n:], r.buf[r.off:])
		n += c
		r.off += c
	}
	return len(p), nil
}

func main() {
	outDir := flag.String("out", "vectors", "output directory for KAT JSON files")
	flag.Parse()

	masterSeed, err := hex.DecodeString(masterSeedHex)
	if err != nil {
		fail(err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fail(err)
	}

	// ---- keygen ----
	keygenKATs := []KeygenKAT{}
	for _, mode := range []pm.Mode{pm.ModeP44, pm.ModeP65, pm.ModeP87} {
		params := pm.MustParamsFor(mode)
		// Use 3 distinct seeds per mode.
		for i := 0; i < 3; i++ {
			seedReader := newDetReader(append(masterSeed, []byte{0x00, byte(mode), byte(i)}...))
			var seed [pm.SeedSize]byte
			_, _ = seedReader.Read(seed[:])
			sk, err := pm.KeyFromSeed(params, seed)
			if err != nil {
				fail(err)
			}
			keygenKATs = append(keygenKATs, KeygenKAT{
				Mode:       mode.String(),
				Seed:       hex.EncodeToString(seed[:]),
				PublicKey:  hex.EncodeToString(sk.Pub.Bytes),
				PrivateKey: hex.EncodeToString(sk.Bytes),
			})
		}
	}
	writeJSON(filepath.Join(*outDir, "keygen.json"), keygenKATs)

	// ---- sign ----
	signKATs := []SignKAT{}
	for _, mode := range []pm.Mode{pm.ModeP44, pm.ModeP65, pm.ModeP87} {
		params := pm.MustParamsFor(mode)
		for i := 0; i < 3; i++ {
			seedReader := newDetReader(append(masterSeed, []byte{0x10, byte(mode), byte(i)}...))
			var seed [pm.SeedSize]byte
			_, _ = seedReader.Read(seed[:])
			sk, _ := pm.KeyFromSeed(params, seed)
			msg := []byte(fmt.Sprintf("Pulsar KAT message %s #%d", mode.String(), i))
			sig, err := pm.Sign(params, sk, msg, nil, false, nil)
			if err != nil {
				fail(err)
			}
			signKATs = append(signKATs, SignKAT{
				Mode:      mode.String(),
				Seed:      hex.EncodeToString(seed[:]),
				Message:   hex.EncodeToString(msg),
				Context:   "",
				Signature: hex.EncodeToString(sig.Bytes),
			})
		}
	}
	writeJSON(filepath.Join(*outDir, "sign.json"), signKATs)

	// ---- verify ----
	// Each verify KAT is a (pk, msg, sig, valid) tuple. We emit both
	// positive and negative cases.
	verifyKATs := []VerifyKAT{}
	for _, mode := range []pm.Mode{pm.ModeP44, pm.ModeP65, pm.ModeP87} {
		params := pm.MustParamsFor(mode)
		seedReader := newDetReader(append(masterSeed, []byte{0x20, byte(mode)}...))
		var seed [pm.SeedSize]byte
		_, _ = seedReader.Read(seed[:])
		sk, _ := pm.KeyFromSeed(params, seed)
		msg := []byte(fmt.Sprintf("Pulsar Verify KAT %s", mode.String()))
		sig, _ := pm.Sign(params, sk, msg, nil, false, nil)
		verifyKATs = append(verifyKATs, VerifyKAT{
			Mode:      mode.String(),
			PublicKey: hex.EncodeToString(sk.Pub.Bytes),
			Message:   hex.EncodeToString(msg),
			Context:   "",
			Signature: hex.EncodeToString(sig.Bytes),
			Valid:     true,
		})
		// Negative: flip a byte.
		badSig := make([]byte, len(sig.Bytes))
		copy(badSig, sig.Bytes)
		badSig[len(badSig)/2] ^= 0x01
		verifyKATs = append(verifyKATs, VerifyKAT{
			Mode:      mode.String(),
			PublicKey: hex.EncodeToString(sk.Pub.Bytes),
			Message:   hex.EncodeToString(msg),
			Context:   "",
			Signature: hex.EncodeToString(badSig),
			Valid:     false,
		})
	}
	writeJSON(filepath.Join(*outDir, "verify.json"), verifyKATs)

	// ---- threshold-sign ----
	thresholdKATs := []ThresholdSignKAT{}
	for _, mode := range []pm.Mode{pm.ModeP65} { // mode P65 is the canonical target
		for _, tc := range []struct{ N, T int }{{3, 2}, {5, 3}, {7, 4}, {10, 7}} {
			params := pm.MustParamsFor(mode)
			committee := makeKATCommittee(tc.N)
			pub, shares, _ := runKATDKG(params, committee, tc.T, mode)
			msg := []byte(fmt.Sprintf("Pulsar Threshold KAT %s n=%d t=%d", mode.String(), tc.N, tc.T))
			quorum := make([]pm.NodeID, tc.T)
			for i := 0; i < tc.T; i++ {
				quorum[i] = shares[i].NodeID
			}
			var sid [16]byte
			copy(sid[:], "kat-threshold01")
			attempt := uint32(1)
			signers := make([]*pm.ThresholdSigner, tc.T)
			for i := 0; i < tc.T; i++ {
				rng := newDetReader(append(masterSeed, []byte{0x30, byte(mode), byte(tc.T), byte(i)}...))
				signers[i], _ = pm.NewThresholdSigner(params, sid, attempt, quorum, shares[i], msg, rng)
			}
			r1 := make([]*pm.Round1Message, tc.T)
			for i, s := range signers {
				r1[i], _ = s.Round1(msg)
			}
			r2 := make([]*pm.Round2Message, tc.T)
			for i, s := range signers {
				r2[i], _, _ = s.Round2(r1)
			}
			sig, err := pm.Combine(params, pub, msg, nil, false, sid, attempt, quorum, tc.T, r1, r2, shares)
			if err != nil {
				fail(fmt.Errorf("threshold combine n=%d t=%d: %w", tc.N, tc.T, err))
			}
			// Cross-check: verify under unmodified FIPS 204.
			if err := pm.Verify(params, pub, msg, sig); err != nil {
				fail(fmt.Errorf("threshold KAT FIPS 204 Verify failed: %w", err))
			}
			quorumHex := make([]string, len(quorum))
			for i, q := range quorum {
				quorumHex[i] = hex.EncodeToString(q[:])
			}
			thresholdKATs = append(thresholdKATs, ThresholdSignKAT{
				Mode:      mode.String(),
				N:         tc.N,
				T:         tc.T,
				Message:   hex.EncodeToString(msg),
				PublicKey: hex.EncodeToString(pub.Bytes),
				Signature: hex.EncodeToString(sig.Bytes),
				Quorum:    quorumHex,
				SessionID: hex.EncodeToString(sid[:]),
				Attempt:   attempt,
			})
		}
	}
	writeJSON(filepath.Join(*outDir, "threshold-sign.json"), thresholdKATs)

	// ---- dkg ----
	dkgKATs := []DKGKAT{}
	for _, mode := range []pm.Mode{pm.ModeP65} {
		for _, tc := range []struct{ N, T int }{{3, 2}, {5, 3}, {7, 4}} {
			params := pm.MustParamsFor(mode)
			committee := makeKATCommittee(tc.N)
			pub, shares, transcript := runKATDKG(params, committee, tc.T, mode)
			committeeHex := make([]string, tc.N)
			for i, c := range committee {
				committeeHex[i] = hex.EncodeToString(c[:])
			}
			shareHex := make([]string, tc.N)
			for i, s := range shares {
				shareHex[i] = hex.EncodeToString(s.Share[:])
			}
			dkgKATs = append(dkgKATs, DKGKAT{
				Mode:           mode.String(),
				N:              tc.N,
				T:              tc.T,
				Committee:      committeeHex,
				PublicKey:      hex.EncodeToString(pub.Bytes),
				TranscriptHash: hex.EncodeToString(transcript[:]),
				Shares:         shareHex,
			})
		}
	}
	writeJSON(filepath.Join(*outDir, "dkg.json"), dkgKATs)

	fmt.Println("KAT vectors written to", *outDir)
}

func makeKATCommittee(n int) []pm.NodeID {
	out := make([]pm.NodeID, n)
	for i := 0; i < n; i++ {
		out[i][0] = byte(i + 1)
	}
	return out
}

// runKATDKG is a deterministic DKG run for KAT generation.
func runKATDKG(params *pm.Params, committee []pm.NodeID, threshold int, mode pm.Mode) (*pm.PublicKey, []*pm.KeyShare, [48]byte) {
	n := len(committee)
	sessions := make([]*pm.DKGSession, n)
	for i := range sessions {
		// Deterministic per-party seed.
		seedTag := append([]byte("PULSAR-DKG-KAT-V1"), []byte{byte(mode), byte(n), byte(threshold), byte(i)}...)
		rng := newDetReader(seedTag)
		s, _ := pm.NewDKGSession(params, committee, threshold, committee[i], rng)
		sessions[i] = s
	}
	r1 := make([]*pm.DKGRound1Msg, n)
	for i, s := range sessions {
		r1[i], _ = s.Round1()
	}
	r2 := make([]*pm.DKGRound2Msg, n)
	for i, s := range sessions {
		r2[i], _ = s.Round2(r1)
	}
	out := make([]*pm.DKGOutput, n)
	for i, s := range sessions {
		out[i], _ = s.Round3(r1, r2)
	}
	shares := make([]*pm.KeyShare, n)
	for i := range out {
		shares[i] = out[i].SecretShare
	}
	return out[0].GroupPubkey, shares, out[0].TranscriptHash
}

func writeJSON(path string, v any) {
	f, err := os.Create(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "genkat: error:", err)
	os.Exit(1)
}
