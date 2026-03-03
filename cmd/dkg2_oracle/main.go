// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// dkg2_oracle — emits byte-equal KATs for the Pedersen-style DKG protocol
// in github.com/luxfi/pulsar/dkg2.
//
// For each (t, n) configuration in the catalogue, the oracle:
//
//   1. Derives a master 32-byte seed from MasterSeed | tag(n,t) via BLAKE3.
//   2. From that master seed, derives one 32-byte sub-seed per party
//      (BLAKE3(master || "party" || BE32(i))).
//   3. Constructs n DKGSessions (party 0..n-1) — they all share the same
//      deterministic A and B matrices (derived from b"pulsar.dkg2.A.v1" /
//      b"pulsar.dkg2.B.v1" via BLAKE3-XOF).
//   4. Each party calls Round1WithSeed(party_seed[i]) to produce its
//      Commits, Shares (per recipient), and Blinds (per recipient).
//   5. Each party calls Round2 with the assembled shares/blinds/commits.
//
// The KAT pins, per entry:
//   - For each party i: seed_hex[i]                       (sub-seed)
//   - For each party i: SHA-256(Commits[k].WriteTo) × t   (commitment-vector hash)
//   - For each party i: BLAKE3(serialize(Commits))        (Round 1.5 digest)
//   - For each party i, each recipient j:
//         SHA-256(Shares[j].WriteTo)
//         SHA-256(Blinds[j].WriteTo)
//   - For each party j (the recipient running Round2):
//         SHA-256(s_j.WriteTo)
//         SHA-256(u_j.WriteTo)
//         SHA-256(b_ped_j.WriteTo)
//
// Replay invariant: every party agrees on b_ped, so all b_ped hashes inside
// one entry must be identical. The KAT records all n of them so the C++
// port can prove that property too.
//
// Output: <luxcpp/crypto>/pulsar/dkg2/test/kat/dkg2_kat.json (4 entries:
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

	"github.com/luxfi/pulsar/dkg2"
	"github.com/luxfi/pulsar/sign"
	"github.com/zeebo/blake3"
)

// MasterSeed is the deterministic root for all dkg2 KAT entries.  Distinct
// from dkg/'s 0xCAFEBABE_DEADBEEF root so the two oracles never alias.
const MasterSeed uint64 = 0xC0FFEE_F00D_FACE

// deriveMaster expands MasterSeed + a per-entry tag into a 32-byte sub-seed.
func deriveMaster(t, n int) []byte {
	h := blake3.New()
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], MasterSeed)
	binary.BigEndian.PutUint32(buf[8:12], uint32(t))
	binary.BigEndian.PutUint32(buf[12:16], uint32(n))
	_, _ = h.Write([]byte("dkg2-oracle:master:"))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)[:32]
}

// derivePartySeed derives party i's 32-byte Round1WithSeed input from the
// master entry seed.
func derivePartySeed(master []byte, partyID int) []byte {
	h := blake3.New()
	_, _ = h.Write([]byte("dkg2-oracle:party:"))
	_, _ = h.Write(master)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(partyID))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)[:32]
}

// hashVectorBytes returns SHA-256 of the WriteTo wire bytes of v.
func hashVectorBytes(v structs.Vector[ring.Poly]) string {
	var buf bytes.Buffer
	if _, err := v.WriteTo(&buf); err != nil {
		panic(err)
	}
	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:])
}

func hashMatrix(m structs.Matrix[ring.Poly]) string {
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		panic(err)
	}
	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:])
}

// PartyEntry is one party's contribution to the KAT.
type PartyEntry struct {
	PartyID         int      `json:"party_id"`
	SeedHex         string   `json:"seed_hex"`           // Round1WithSeed input
	CommitsHashHex  []string `json:"commits_hash_hex"`   // length t
	CommitDigestHex string   `json:"commit_digest_hex"`  // BLAKE3 over serialized commits
	SharesHashHex   []string `json:"shares_hash_hex"`    // length n; index j = share to party j
	BlindsHashHex   []string `json:"blinds_hash_hex"`    // length n; index j = blind to party j
	SecretShareHash string   `json:"secret_share_hash"`  // SHA-256(s_j) after Round2
	BlindShareHash  string   `json:"blind_share_hash"`   // SHA-256(u_j) after Round2
	BPedHash        string   `json:"b_ped_hash"`         // SHA-256(b_ped) after Round2
}

type Entry struct {
	T             int          `json:"t"`
	N             int          `json:"n"`
	MasterSeedHex string       `json:"master_seed_hex"`
	AHashHex      string       `json:"a_hash_hex"`
	BHashHex      string       `json:"b_hash_hex"`
	Parties       []PartyEntry `json:"parties"`
}

type OracleOut struct {
	Description string  `json:"description"`
	Q           uint64  `json:"q"`
	N           int     `json:"n_ring"`
	M           int     `json:"m"`
	Nvec        int     `json:"nvec"`
	Xi          int     `json:"xi"`
	TagAHex     string  `json:"tag_a_hex"`
	TagBHex     string  `json:"tag_b_hex"`
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

func runEntry(t, n int) Entry {
	master := deriveMaster(t, n)

	params, err := dkg2.NewParams()
	if err != nil {
		panic(err)
	}

	sessions := make([]*dkg2.DKGSession, n)
	for i := 0; i < n; i++ {
		// Use the legacy BLAKE3 hash suite for the canonical KAT — keeps
		// every byte in dkg2_kat.json byte-stable across the Pulsar-SHA3
		// cutover. Production-track callers use hash.Default() (Pulsar-SHA3).
		s, err := dkg2.NewDKGSession(params, i, n, t, nil)
		if err != nil {
			panic(fmt.Errorf("NewDKGSession(%d, %d, %d): %w", i, n, t, err))
		}
		sessions[i] = s
	}

	// Hash the public matrices.  All sessions must agree.
	aHash := hashMatrix(sessions[0].APublic())
	bHash := hashMatrix(sessions[0].BPublic())
	for i := 1; i < n; i++ {
		if got := hashMatrix(sessions[i].APublic()); got != aHash {
			panic(fmt.Errorf("party %d A-matrix mismatch: %s vs %s", i, got, aHash))
		}
		if got := hashMatrix(sessions[i].BPublic()); got != bHash {
			panic(fmt.Errorf("party %d B-matrix mismatch: %s vs %s", i, got, bHash))
		}
	}

	round1Outs := make([]*dkg2.Round1Output, n)
	partyEntries := make([]PartyEntry, n)
	for i := 0; i < n; i++ {
		seed := derivePartySeed(master, i)
		out, err := sessions[i].Round1WithSeed(seed)
		if err != nil {
			panic(fmt.Errorf("Round1WithSeed(party=%d): %w", i, err))
		}
		round1Outs[i] = out

		commitsHash := make([]string, t)
		for k := 0; k < t; k++ {
			commitsHash[k] = hashVectorBytes(out.Commits[k])
		}
		sharesHash := make([]string, n)
		blindsHash := make([]string, n)
		for j := 0; j < n; j++ {
			sh, ok := out.Shares[j]
			if !ok {
				panic(fmt.Errorf("party %d missing share for %d", i, j))
			}
			bl, ok := out.Blinds[j]
			if !ok {
				panic(fmt.Errorf("party %d missing blind for %d", i, j))
			}
			sharesHash[j] = hashVectorBytes(sh)
			blindsHash[j] = hashVectorBytes(bl)
		}
		// commit_digest_hex pins the legacy BLAKE3 path used by the
		// pre-cutover KAT. CommitDigestBLAKE3 produces byte-stable bytes
		// so the C++ port can replay against the same JSON.
		digest, err := out.CommitDigestBLAKE3()
		if err != nil {
			panic(fmt.Errorf("CommitDigestBLAKE3 (party=%d): %w", i, err))
		}
		partyEntries[i] = PartyEntry{
			PartyID:         i,
			SeedHex:         hex.EncodeToString(seed),
			CommitsHashHex:  commitsHash,
			CommitDigestHex: hex.EncodeToString(digest[:]),
			SharesHashHex:   sharesHash,
			BlindsHashHex:   blindsHash,
		}
	}

	for j := 0; j < n; j++ {
		shares := map[int]structs.Vector[ring.Poly]{}
		blinds := map[int]structs.Vector[ring.Poly]{}
		commits := map[int][]structs.Vector[ring.Poly]{}
		for i := 0; i < n; i++ {
			shares[i] = round1Outs[i].Shares[j]
			blinds[i] = round1Outs[i].Blinds[j]
			commits[i] = round1Outs[i].Commits
		}
		s, u, bPed, err := sessions[j].Round2(shares, blinds, commits)
		if err != nil {
			panic(fmt.Errorf("Round2(party=%d): %w", j, err))
		}
		partyEntries[j].SecretShareHash = hashVectorBytes(s)
		partyEntries[j].BlindShareHash = hashVectorBytes(u)
		partyEntries[j].BPedHash = hashVectorBytes(bPed)
	}

	bp := partyEntries[0].BPedHash
	for j := 1; j < n; j++ {
		if partyEntries[j].BPedHash != bp {
			panic(fmt.Errorf("entry t=%d n=%d: party %d b_ped hash mismatch: %s vs %s",
				t, n, j, partyEntries[j].BPedHash, bp))
		}
	}

	return Entry{
		T:             t,
		N:             n,
		MasterSeedHex: hex.EncodeToString(master),
		AHashHex:      aHash,
		BHashHex:      bHash,
		Parties:       partyEntries,
	}
}

func main() {
	cases := []struct{ t, n int }{
		{2, 3},
		{3, 5},
		{5, 7},
		{7, 11},
	}

	out := OracleOut{
		Description: "Pedersen-style DKG over R = Z_q[X]/(X^256+1), Q=0x1000000004A01. " +
			"C_k = A·NTT(c_k) + B·NTT(r_k) — hiding under MLWE on B, binding under " +
			"MSIS on [A|B].  A derived from BLAKE3(\"pulsar.dkg2.A.v1\"); B from " +
			"BLAKE3(\"pulsar.dkg2.B.v1\").  Each entry runs the full t-of-n protocol " +
			"with deterministic per-party Round1WithSeed inputs derived from " +
			"MasterSeed=0xC0FFEEF00DFACE.  Wire format: structs.{Vector,Matrix}[ring.Poly]" +
			".WriteTo (LE u64).  Hashes are SHA-256 of those wire bytes.  CommitDigest " +
			"is BLAKE3 over the concatenated serialized commits, exchanged in Round 1.5 " +
			"to defeat cross-party inconsistency attacks (Finding 2 of RED-DKG-REVIEW.md).",
		Q:       sign.Q,
		N:       1 << sign.LogN,
		M:       sign.M,
		Nvec:    sign.N,
		Xi:      sign.Xi,
		TagAHex: hex.EncodeToString([]byte("pulsar.dkg2.A.v1")),
		TagBHex: hex.EncodeToString([]byte("pulsar.dkg2.B.v1")),
	}

	for _, c := range cases {
		fmt.Fprintf(os.Stderr, "running t=%d n=%d ...\n", c.t, c.n)
		out.Entries = append(out.Entries, runEntry(c.t, c.n))
	}

	// Default output path: canonical luxcpp KAT directory.  Pass an
	// argument to override.  When the oracle is invoked via `go run` from
	// the pulsar repo root, the relative form ../../../luxcpp/... resolves
	// correctly; otherwise pass an absolute path.
	outPath := "../../../luxcpp/crypto/pulsar/dkg2/test/kat/dkg2_kat.json"
	if env := os.Getenv("PULSAR_DKG2_KAT_PATH"); env != "" {
		outPath = env
	}
	if len(os.Args) >= 2 {
		outPath = os.Args[1]
	}
	if err := writeJSON(outPath, out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)

	if f, err := os.Open(outPath); err == nil {
		defer f.Close()
		var head [256]byte
		n, _ := io.ReadFull(f, head[:])
		fmt.Fprintln(os.Stderr, string(head[:n]))
	}
}
