// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// dkg_oracle — emits byte-equal KATs for the Feldman VSS-based DKG protocol
// in github.com/luxfi/pulsar/dkg.
//
// For each (t, n) configuration in the catalogue, the oracle:
//
//   1. Derives a master 32-byte seed from MasterSeed | tag(n,t) via BLAKE3.
//   2. From that master seed, derives one 32-byte sub-seed per party
//      (BLAKE3(master || "party" || BE32(i))).
//   3. Constructs n DKGSessions (party 0..n-1) — they all share the same
//      deterministic A matrix (seedKey = zeros, mirroring dkg.go:99-105).
//   4. Each party calls Round1WithSeed(party_seed[i]) to produce its
//      Commits and per-recipient Shares.
//   5. Each party calls Round2 with the assembled shares/commits.
//
// The KAT pins, per entry:
//   - For each party i: seed_hex[i]                      (sub-seed)
//   - For each party i: SHA-256(Commits[k].WriteTo) × t  (commitment vector hash)
//   - For each party i, each recipient j: SHA-256(Shares[j].WriteTo) — the
//     share that party i computed for party j.
//   - For each party j (the recipient running Round2):
//       SHA-256(secret_share_j.WriteTo)
//       SHA-256(bTilde_j.WriteTo)
//
// Replay invariant: every party agrees on bTilde, so all bTilde hashes
// inside one entry must be identical. The KAT records all n of them so
// the C++ port can prove that property too.
//
// Output: <luxcpp/crypto>/ringtail/test/kat/dkg_kat.json (4 entries:
// 2-of-3, 3-of-5, 5-of-7, 7-of-11).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
	"github.com/luxfi/pulsar/dkg"
	"github.com/luxfi/pulsar/sign"
	"github.com/zeebo/blake3"
)

// MasterSeed is the deterministic root for all DKG KAT entries. Changing
// this invalidates every downstream port's expected outputs.
const MasterSeed uint64 = 0xCAFEBABE_DEADBEEF

// derive expands MasterSeed + a per-entry tag into a 32-byte sub-seed.
func deriveMaster(t, n int) []byte {
	h := blake3.New()
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], MasterSeed)
	binary.BigEndian.PutUint32(buf[8:12], uint32(t))
	binary.BigEndian.PutUint32(buf[12:16], uint32(n))
	_, _ = h.Write([]byte("dkg-oracle:master:"))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)[:32]
}

// derivePartySeed derives party i's 32-byte Round1WithSeed input from the
// master entry seed.
func derivePartySeed(master []byte, partyID int) []byte {
	h := blake3.New()
	_, _ = h.Write([]byte("dkg-oracle:party:"))
	_, _ = h.Write(master)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(partyID))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)[:32]
}

// hashVectorBytes returns SHA-256 of the WriteTo wire bytes of v.
func hashVectorBytes(r *ring.Ring, v structs.Vector[ring.Poly]) (string, []byte) {
	var buf bytes.Buffer
	if _, err := v.WriteTo(&buf); err != nil {
		panic(err)
	}
	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:]), buf.Bytes()
}

// PartyEntry is one party's contribution to the KAT.
type PartyEntry struct {
	PartyID         int      `json:"party_id"`
	SeedHex         string   `json:"seed_hex"`           // Round1WithSeed input
	CommitsHashHex  []string `json:"commits_hash_hex"`   // length t
	SharesHashHex   []string `json:"shares_hash_hex"`    // length n; index j = share for party j
	SecretShareHash string   `json:"secret_share_hash"`  // SHA-256 of secret_share_j (after Round2)
	BTildeHash      string   `json:"btilde_hash"`        // SHA-256 of bTilde_j (after Round2)
}

type Entry struct {
	T            int          `json:"t"`
	N            int          `json:"n"`
	MasterSeedHex string      `json:"master_seed_hex"`
	AHashHex     string       `json:"a_hash_hex"`     // SHA-256(A.WriteTo) — same for all parties
	Parties      []PartyEntry `json:"parties"`
}

type OracleOut struct {
	Description string  `json:"description"`
	Q           uint64  `json:"q"`
	N           int     `json:"n_ring"`
	M           int     `json:"m"`
	Nvec        int     `json:"nvec"`
	Xi          int     `json:"xi"`
	Entries     []Entry `json:"entries"`
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

// runEntry executes one full DKG protocol with deterministic per-party seeds
// and emits the byte-equal KAT entry.
func runEntry(t, n int) Entry {
	master := deriveMaster(t, n)

	params, err := dkg.NewParams()
	if err != nil {
		panic(err)
	}
	r := params.R

	// Build n sessions and run Round1WithSeed for each.
	sessions := make([]*dkg.DKGSession, n)
	for i := 0; i < n; i++ {
		s, err := dkg.NewDKGSession(params, i, n, t)
		if err != nil {
			panic(fmt.Errorf("NewDKGSession(%d, %d, %d): %w", i, n, t, err))
		}
		sessions[i] = s
	}

	// A matrix is identical across parties (deterministic from zero seedKey).
	// Hash session 0's A — this also acts as a sanity check: every party's
	// session.A must produce the same WriteTo bytes.
	aHashHex := hashMatrixHex(sessions[0].A)
	for i := 1; i < n; i++ {
		if got := hashMatrixHex(sessions[i].A); got != aHashHex {
			panic(fmt.Errorf("party %d A matrix hash mismatch: %s vs %s", i, got, aHashHex))
		}
	}

	round1Outs := make([]*dkg.Round1Output, n)
	partyEntries := make([]PartyEntry, n)
	for i := 0; i < n; i++ {
		seed := derivePartySeed(master, i)
		out, err := sessions[i].Round1WithSeed(seed)
		if err != nil {
			panic(fmt.Errorf("Round1WithSeed(party=%d): %w", i, err))
		}
		round1Outs[i] = out

		// Commit hashes: one per polynomial coefficient of f_i (length t).
		commitsHash := make([]string, t)
		for k := 0; k < t; k++ {
			h, _ := hashVectorBytes(r, out.Commits[k])
			commitsHash[k] = h
		}

		// Share hashes: one per recipient party j (length n).
		sharesHash := make([]string, n)
		for j := 0; j < n; j++ {
			share, ok := out.Shares[j]
			if !ok {
				panic(fmt.Errorf("party %d missing share for %d", i, j))
			}
			h, _ := hashVectorBytes(r, share)
			sharesHash[j] = h
		}

		partyEntries[i] = PartyEntry{
			PartyID:        i,
			SeedHex:        hex.EncodeToString(seed),
			CommitsHashHex: commitsHash,
			SharesHashHex:  sharesHash,
		}
	}

	// Round 2: for each recipient party j, run verification + aggregation.
	for j := 0; j < n; j++ {
		shares := make(map[int]structs.Vector[ring.Poly])
		commits := make(map[int][]structs.Vector[ring.Poly])
		for i := 0; i < n; i++ {
			shares[i] = round1Outs[i].Shares[j]
			commits[i] = round1Outs[i].Commits
		}
		secretShare, bTilde, err := sessions[j].Round2(shares, commits)
		if err != nil {
			panic(fmt.Errorf("Round2(party=%d): %w", j, err))
		}
		ssHash, _ := hashVectorBytes(r, secretShare)
		btHash, _ := hashVectorBytes(r, bTilde)
		partyEntries[j].SecretShareHash = ssHash
		partyEntries[j].BTildeHash = btHash
	}

	// Sanity: all bTilde hashes equal.
	bt := partyEntries[0].BTildeHash
	for j := 1; j < n; j++ {
		if partyEntries[j].BTildeHash != bt {
			panic(fmt.Errorf("entry t=%d n=%d: party %d bTilde hash mismatch: %s vs %s",
				t, n, j, partyEntries[j].BTildeHash, bt))
		}
	}

	return Entry{
		T:             t,
		N:             n,
		MasterSeedHex: hex.EncodeToString(master),
		AHashHex:      aHashHex,
		Parties:       partyEntries,
	}
}

// hashMatrixHex serializes a Matrix[Poly] WriteTo and returns SHA-256 hex.
func hashMatrixHex(m structs.Matrix[ring.Poly]) string {
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		panic(err)
	}
	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:])
}

func main() {
	cases := []struct {
		t, n int
	}{
		{2, 3},
		{3, 5},
		{5, 7},
		{7, 11},
	}

	out := OracleOut{
		Description: "DKG Feldman VSS over R = Z_q[X]/(X^256+1), Q=0x1000000004A01. " +
			"Each entry runs the full t-of-n protocol with deterministic per-party " +
			"Round1WithSeed inputs derived from MasterSeed=0xCAFEBABEDEADBEEF. " +
			"Wire format: structs.{Vector,Matrix}[ring.Poly].WriteTo (LE u64). " +
			"Hashes are SHA-256 of those wire bytes. The A matrix is the same " +
			"deterministic uniform sample across all parties (seedKey = 32 zero " +
			"bytes; mirrors dkg.go:99-105).",
		Q:    sign.Q,
		N:    1 << sign.LogN,
		M:    sign.M,
		Nvec: sign.N,
		Xi:   sign.Xi,
	}

	for _, c := range cases {
		fmt.Fprintf(os.Stderr, "running t=%d n=%d ...\n", c.t, c.n)
		out.Entries = append(out.Entries, runEntry(c.t, c.n))
	}

	// Default output path is the C++ port's KAT directory; allow override via
	// argv[1].
	outPath := "../../../luxcpp/crypto/ringtail/test/kat/dkg_kat.json"
	if len(os.Args) >= 2 {
		outPath = os.Args[1]
	}
	if err := writeJSON(outPath, out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)

	// Belt-and-suspenders: re-read the file and dump its top 64 bytes for
	// human inspection.
	f, err := os.Open(outPath)
	if err == nil {
		defer f.Close()
		var head [256]byte
		n, _ := io.ReadFull(f, head[:])
		fmt.Fprintln(os.Stderr, string(head[:n]))
	}
}
