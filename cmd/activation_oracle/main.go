// Copyright (c) 2025-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// activation_oracle — emits byte-equal KATs for the post-reshare
// activation circuit-breaker. Drives reshare.ActivationMessage and
// reshare.ReshareTranscript through their canonical SignableBytes /
// Hash routines under the production Pulsar-SHA3 suite.
//
// Wire format (per entry):
//
//	chain_id_hex             ChainID for TranscriptInputs
//	group_id_hex             GroupID for TranscriptInputs
//	variant                  TranscriptInputs.Variant ("reshare" | "dkg")
//	commit_digests_hex       map[party_id][32]byte serialized as
//	                         sorted (party_id, digest_hex) pairs
//	complaint_hashes_hex     [][32]byte
//	disqualified_senders     []int
//	qualified_quorum         []int
//	transcript_hash_hex      32-byte canonical Transcript hash
//	exchange_hash_hex        32-byte canonical ReshareTranscript hash
//	signable_bytes_hex       SignableBytes(SHA3) — 89 bytes total
//	signable_bytes_sha256    sha256(SignableBytes) — fingerprint for ports
//
// Determinism contract: every entry is byte-identical across hosts /
// builds / OSes given the seed. The C++ port consumes
// (chain_id, group_id, variant, commit_digests, complaint_hashes,
// disqualified_senders, qualified_quorum) and must produce the exact
// transcript_hash_hex, exchange_hash_hex and signable_bytes_hex.
//
// Output: <luxcpp/crypto>/pulsar/test/kat/activation_kat.json
//
// Algorithm references:
//   - pulsar/reshare/activation.go (canonical Go)
//   - luxcpp/crypto/pulsar/reshare/activation.hpp (C++ port)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/luxfi/pulsar/reshare"
)

type CommitEntry struct {
	PartyID   int    `json:"party_id"`
	DigestHex string `json:"digest_hex"`
}

type Entry struct {
	Name                string        `json:"name"`
	ChainIDHex          string        `json:"chain_id_hex"`
	GroupIDHex          string        `json:"group_id_hex"`
	Variant             string        `json:"variant"`
	CommitDigests       []CommitEntry `json:"commit_digests"`
	ComplaintHashesHex  []string      `json:"complaint_hashes_hex"`
	DisqualifiedSenders []int         `json:"disqualified_senders"`
	QualifiedQuorum     []int         `json:"qualified_quorum"`
	TranscriptHashHex   string        `json:"transcript_hash_hex"`
	ExchangeHashHex     string        `json:"exchange_hash_hex"`
	SignableBytesHex    string        `json:"signable_bytes_hex"`
	SignableBytesSHA256 string        `json:"signable_bytes_sha256"`
}

type Output struct {
	Suite   string  `json:"suite"`
	Version string  `json:"version"`
	Entries []Entry `json:"entries"`
}

// counterDigest returns a deterministic 32-byte digest derived from a
// (label, index) pair via SHA-256. Used to seed CommitDigests and
// ComplaintHashes so the KAT is reproducible without any RNG state.
func counterDigest(label string, idx int) [32]byte {
	h := sha256.New()
	_, _ = io.WriteString(h, "pulsar.activation.kat.v1:")
	_, _ = io.WriteString(h, label)
	var b [8]byte
	for i := 0; i < 8; i++ {
		b[7-i] = byte(uint64(idx) >> (8 * i))
	}
	_, _ = h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func entry(
	name, chainID, groupID, variant string,
	committee []int,
	complaints int,
	disqualified []int,
	quorum []int,
) Entry {
	commit := map[int][32]byte{}
	commitSlice := make([]CommitEntry, 0, len(committee))
	for _, id := range committee {
		d := counterDigest("commit", id)
		commit[id] = d
		commitSlice = append(commitSlice, CommitEntry{
			PartyID:   id,
			DigestHex: hex.EncodeToString(d[:]),
		})
	}
	sort.Slice(commitSlice, func(i, j int) bool {
		return commitSlice[i].PartyID < commitSlice[j].PartyID
	})

	complaintHashes := make([][32]byte, complaints)
	complaintHex := make([]string, complaints)
	for i := 0; i < complaints; i++ {
		complaintHashes[i] = counterDigest("complaint", i)
		complaintHex[i] = hex.EncodeToString(complaintHashes[i][:])
	}

	rt := reshare.ReshareTranscript{
		CommitDigests:       commit,
		ComplaintHashes:     complaintHashes,
		DisqualifiedSenders: append([]int(nil), disqualified...),
		QualifiedQuorum:     append([]int(nil), quorum...),
	}
	msg := reshare.ActivationMessage{
		Transcript: reshare.TranscriptInputs{
			ChainID: []byte(chainID),
			GroupID: []byte(groupID),
			Variant: variant,
		},
		ReshareTranscript: rt,
	}

	tHash := msg.Transcript.Hash(nil)
	eHash := rt.Hash(nil)
	signable := msg.SignableBytes(nil)
	sigBytesHash := sha256.Sum256(signable)

	return Entry{
		Name:                name,
		ChainIDHex:          hex.EncodeToString([]byte(chainID)),
		GroupIDHex:          hex.EncodeToString([]byte(groupID)),
		Variant:             variant,
		CommitDigests:       commitSlice,
		ComplaintHashesHex:  complaintHex,
		DisqualifiedSenders: append([]int(nil), disqualified...),
		QualifiedQuorum:     append([]int(nil), quorum...),
		TranscriptHashHex:   hex.EncodeToString(tHash[:]),
		ExchangeHashHex:     hex.EncodeToString(eHash[:]),
		SignableBytesHex:    hex.EncodeToString(signable),
		SignableBytesSHA256: hex.EncodeToString(sigBytesHash[:]),
	}
}

func main() {
	out := Output{
		Suite:   "Pulsar-SHA3",
		Version: "v1",
	}
	out.Entries = append(out.Entries,
		entry("3-of-5", "lux-mainnet", "p-chain", "reshare",
			[]int{1, 2, 3, 4, 5}, 0, nil, []int{1, 2, 3, 4, 5}),
		entry("3-of-5-with-disqualified", "lux-mainnet", "p-chain", "reshare",
			[]int{1, 2, 3, 4, 5}, 1, []int{4}, []int{1, 2, 3, 5}),
		entry("5-of-7", "lux-testnet", "p-chain", "reshare",
			[]int{1, 2, 3, 4, 5, 6, 7}, 0, nil, []int{1, 2, 3, 4, 5, 6, 7}),
		entry("5-of-7-with-2-complaints", "lux-testnet", "p-chain", "reshare",
			[]int{1, 2, 3, 4, 5, 6, 7}, 2, []int{6, 7}, []int{1, 2, 3, 4, 5}),
		entry("dkg-bootstrap", "lux-devnet", "p-chain", "dkg",
			[]int{1, 2, 3}, 0, nil, []int{1, 2, 3}),
	)

	// Default output: canonical luxcpp KAT directory; allow override via
	// PULSAR_ACTIVATION_KAT_PATH env or a positional arg.
	outPath := filepath.Join(
		os.Getenv("HOME"), "work", "luxcpp", "crypto", "pulsar",
		"test", "kat", "activation_kat.json",
	)
	if env := os.Getenv("PULSAR_ACTIVATION_KAT_PATH"); env != "" {
		outPath = env
	}
	if len(os.Args) >= 2 {
		outPath = os.Args[1]
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fail(err)
	}
	f, err := os.Create(outPath)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "wrote activation_kat.json (%d entries) → %s\n",
		len(out.Entries), outPath)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
