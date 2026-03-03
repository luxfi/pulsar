// Copyright (c) 2025-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// reshare_oracle — emits byte-equal KATs for the proactive secret-resharing
// protocol implemented in github.com/luxfi/pulsar/reshare. The C++ port at
// ~/work/luxcpp/crypto/pulsar/reshare/ replays each entry's seeds and must
// produce share bytes whose SHA-256 commitment matches the entry's
// new_share_sha256_hex field.
//
// Wire format (per entry):
//
//   - t_old, n_old, t_new, n_new            : protocol parameters
//   - old_set, new_set                      : 1-indexed party IDs
//   - secret_polys_hex   [poly_count]       : the master secret s before sharing
//                                             (4096 hex chars = 256 uint64 BE per poly)
//   - old_shamir_seed_hex                   : deterministic seed for the
//                                             old Shamir random a_1..a_{t_old-1}
//                                             (BLAKE3 XOF, q_byte_len bytes per draw)
//   - reshare_rng_seed_hex                  : deterministic seed for the
//                                             reshare random higher-degree
//                                             coefficients (SHA-256 counter
//                                             mode, see counterRand)
//   - old_shares_hex     [n_old]            : Shamir shares of s for old set
//   - new_shares_hex     [n_new]            : reshared shares for new set
//   - old_share_sha256_hex [n_old]          : sha256 of each old party's full share
//   - new_share_sha256_hex [n_new]          : sha256 of each new party's full share
//
// Entry coverage (16 entries):
//
//	t_old ∈ {2, 3, 5}, t_new ∈ {2, 3, 5, 7}, n_old ∈ {3, 5, 7}, n_new ∈ {3, 5, 7, 9}
//
// Determinism contract: every entry is byte-identical across hosts /
// builds / OSes given the master seed below. The C++ port consumes
// (old_shamir_seed_hex, reshare_rng_seed_hex, secret_polys_hex,
// old_set, new_set, t_old, t_new) and must reproduce
// (old_shares_hex, new_shares_hex) exactly.
//
// Output: ~/work/luxcpp/crypto/pulsar/test/kat/reshare_kat.json
//
// Algorithm references:
//   - pulsar/reshare/reshare.go (canonical Go)
//   - pulsar/papers/lp-073-pulsar/sections/06-resharing.tex (paper)
//
// Note on RNG choice: production reshare.Reshare consumes from
// crypto/rand.Reader by default. For KAT determinism we substitute a
// SHA-256-counter PRNG (counterRand below). The same counterRand is
// implemented in C++ (luxcpp/crypto/pulsar/reshare/counter_rand.cpp).
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/luxfi/pulsar/reshare"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

const (
	// Q is the LP-073 canonical 48-bit NTT-friendly prime.
	Q uint64 = 0x1000000004A01
	// N is R = Z_q[X]/(X^N+1).
	N int = 256
	// QByteLen = len(big.Int.Bytes(Q)).
	QByteLen = 7
	// PolyCount is sign.Nvec = 7 (the secret-vector dimension in the
	// production Pulsar path). Smaller values would also work; 7 lets
	// the KAT exercise the same shape as production.
	PolyCount = 7
)

// counterRand is a deterministic io.Reader: SHA-256 counter mode.
// Pulls 32 bytes per block; uses a single byte-buffer to serve any
// requested length. Matches the C++ implementation byte-for-byte.
type counterRand struct {
	domain []byte
	seed   []byte
	ctr    uint64
	buf    []byte
}

func newCounterRand(domain string, seed []byte) *counterRand {
	return &counterRand{
		domain: []byte(domain),
		seed:   append([]byte{}, seed...),
	}
}

func (c *counterRand) Read(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		if len(c.buf) == 0 {
			h := sha256.New()
			_, _ = h.Write(c.domain)
			_, _ = h.Write([]byte{':'})
			_, _ = h.Write(c.seed)
			var ctrBuf [8]byte
			binary.BigEndian.PutUint64(ctrBuf[:], c.ctr)
			_, _ = h.Write(ctrBuf[:])
			c.buf = h.Sum(nil)
			c.ctr++
		}
		n := copy(p[written:], c.buf)
		c.buf = c.buf[n:]
		written += n
	}
	return written, nil
}

var _ io.Reader = (*counterRand)(nil)

type Entry struct {
	Label              string   `json:"label"`
	Variant            string   `json:"variant"` // "reshare" or "refresh"
	TOld               int      `json:"t_old"`
	NOld               int      `json:"n_old"`
	TNew               int      `json:"t_new"`
	NNew               int      `json:"n_new"`
	OldSet             []int    `json:"old_set"`
	NewSet             []int    `json:"new_set"`
	SecretPolysHex     []string `json:"secret_polys_hex"`
	OldShamirSeedHex   string   `json:"old_shamir_seed_hex"`
	ReshareRngSeedHex  string   `json:"reshare_rng_seed_hex"`
	OldSharesHex       []string `json:"old_shares_hex"`
	NewSharesHex       []string `json:"new_shares_hex"`
	OldShareSHA256Hex  []string `json:"old_share_sha256_hex"`
	NewShareSHA256Hex  []string `json:"new_share_sha256_hex"`
}

type OracleOut struct {
	Description string  `json:"description"`
	Modulus     uint64  `json:"modulus"`
	NPoly       int     `json:"poly_n"`
	QByteLen    int     `json:"q_byte_len"`
	PolyCount   int     `json:"poly_count"`
	Entries     []Entry `json:"entries"`
}

// Configuration cases. Curated to cover:
//   - t_old ∈ {2, 3, 5}
//   - t_new ∈ {2, 3, 5, 7}
//   - committee resize: shrink, grow, equal
//   - threshold change: tighten, loosen, equal
//   - non-overlapping new set IDs (rotated committee)
//   - overlapping new set IDs (validator subset retained)
type config struct {
	label   string
	variant string // "reshare" (default) or "refresh"
	tOld    int
	nOld    int
	tNew    int    // ignored for refresh (= tOld)
	newSet  []int  // 1-indexed party IDs (for refresh, this is the unchanged committee)
}

func main() {
	r, err := ring.NewRing(N, []uint64{Q})
	if err != nil {
		fail(err)
	}
	q := new(big.Int).SetUint64(Q)

	// Hand-curated entries. The default variant is "reshare"; entries
	// with variant "refresh" run the HJKY zero-poly same-committee
	// primitive instead.
	configs := []config{
		// ─── Reshare entries (validator-set rotation) ──────────────
		// Threshold tightening, same committee size.
		{"reshare-t2-n3-to-t3-n5", "reshare", 2, 3, 3, []int{1, 2, 3, 4, 5}},
		{"reshare-t3-n5-to-t5-n7", "reshare", 3, 5, 5, []int{1, 2, 3, 4, 5, 6, 7}},
		// Threshold loosening.
		{"reshare-t5-n7-to-t3-n5", "reshare", 5, 7, 3, []int{2, 4, 6, 8, 10}},
		{"reshare-t5-n7-to-t2-n3", "reshare", 5, 7, 2, []int{20, 21, 22}},
		// Equal threshold, full committee rotation.
		{"reshare-t3-n5-rotate", "reshare", 3, 5, 3, []int{10, 11, 12, 13, 14}},
		{"reshare-t5-n7-rotate", "reshare", 5, 7, 5, []int{20, 21, 22, 23, 24, 25, 26}},
		// Threshold up, committee grows.
		{"reshare-t2-n3-to-t5-n9", "reshare", 2, 3, 5, []int{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		// Edge: t_new = t_old, n_new = n_old, partial overlap.
		{"reshare-t3-n5-partial-overlap", "reshare", 3, 5, 3, []int{3, 4, 5, 100, 101}},
		// Edge: n_new = 1 + t_new (smallest valid new committee).
		{"reshare-t3-n5-min-newset", "reshare", 3, 5, 3, []int{50, 51, 52, 53}},
		// Edge: n_new much larger than n_old.
		{"reshare-t2-n3-grow-9", "reshare", 2, 3, 2, []int{60, 61, 62, 63, 64, 65, 66, 67, 68}},
		// Edge: t_new = 7 (Quasar 21-validator scale-down).
		{"reshare-t5-n7-to-t7-n11", "reshare", 5, 7, 7, []int{30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}},
		// Re-run with different secret seeds to amplify coverage.
		{"reshare-t3-n5-to-t3-n7-runA", "reshare", 3, 5, 3, []int{2, 3, 5, 7, 11, 13, 17}},
		{"reshare-t3-n5-to-t3-n7-runB", "reshare", 3, 5, 3, []int{4, 6, 8, 10, 12, 14, 16}},
		{"reshare-t2-n3-to-t2-n5-runA", "reshare", 2, 3, 2, []int{100, 101, 102, 103, 104}},
		{"reshare-t2-n3-to-t2-n5-runB", "reshare", 2, 3, 2, []int{200, 201, 202, 203, 204}},
		// Edge: t_old = 5, t_new = 5 with disjoint sets.
		{"reshare-t5-n7-disjoint-rotate", "reshare", 5, 7, 5, []int{50, 51, 52, 53, 54, 55, 56}},
		// ─── Refresh entries (same-committee zero-poly) ────────────
		// Same committee preserved; the new_set IS the old_set, the
		// new threshold IS the old threshold. Only share bytes rotate.
		{"refresh-t2-n3", "refresh", 2, 3, 2, []int{1, 2, 3}},
		{"refresh-t3-n5", "refresh", 3, 5, 3, []int{1, 2, 3, 4, 5}},
		{"refresh-t5-n7", "refresh", 5, 7, 5, []int{1, 2, 3, 4, 5, 6, 7}},
		{"refresh-t7-n11", "refresh", 7, 11, 7, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},
		// Edge: threshold = 1 — Refresh must be the identity.
		{"refresh-t1-n3-identity", "refresh", 1, 3, 1, []int{1, 2, 3}},
		// Same committee with non-{1..n} IDs (rotated party labels).
		{"refresh-t3-n5-shifted", "refresh", 3, 5, 3, []int{10, 11, 12, 13, 14}},
	}

	out := OracleOut{
		Description: "Pulsar proactive resharing KAT. " +
			"Each entry deterministically reconstructs (1) Shamir shares of " +
			"a planted secret s for the old committee and (2) reshared " +
			"shares for the new committee, using counterRand SHA-256 streams " +
			"seeded by old_shamir_seed_hex / reshare_rng_seed_hex. The new " +
			"shares interpolate (any t_new of them) to the SAME s. The " +
			"public key b in production is computed from s and is therefore " +
			"unchanged across resharing — see pulsar/papers/lp-073-pulsar/" +
			"sections/06-resharing.tex.",
		Modulus:   Q,
		NPoly:     N,
		QByteLen:  QByteLen,
		PolyCount: PolyCount,
	}

	for runIdx, cfg := range configs {
		variant := cfg.variant
		if variant == "" {
			variant = "reshare"
		}
		// Derive determinism seeds from (label, run_idx).
		secretSeed := deriveSeed("secret", cfg.label, runIdx, cfg.tOld, cfg.nOld)
		shamirSeed := deriveSeed("old-shamir", cfg.label, runIdx, cfg.tOld, cfg.nOld)
		reshareSeed := deriveSeed("reshare-rng", cfg.label, runIdx, cfg.tNew, len(cfg.newSet))

		// Build secret vector deterministically.
		secret := buildSecret(r, secretSeed)

		// Old committee differs by variant. For Refresh the "old set"
		// IS the new set (the committee never changes); the
		// determinism is preserved by always using cfg.newSet for
		// both the share-generation and the resharing committee.
		var oldSet []int
		if variant == "refresh" {
			oldSet = append([]int{}, cfg.newSet...)
		} else {
			oldSet = make([]int, cfg.nOld)
			for i := range oldSet {
				oldSet[i] = i + 1
			}
		}

		// Old Shamir shares.
		oldShares := buildStandardShamirShares(
			r, secret, cfg.tOld, oldSet,
			newCounterRand("old-shamir-stream", shamirSeed),
			q,
		)

		// Run the appropriate primitive.
		var newSharesMap map[int]reshare.Share
		switch variant {
		case "refresh":
			newSharesMap, err = reshare.Refresh(
				r, oldShares, cfg.tOld,
				newCounterRand("refresh-rng-stream", reshareSeed),
			)
		default:
			newSharesMap, err = reshare.Reshare(
				r, oldShares, cfg.tOld, cfg.newSet, cfg.tNew,
				newCounterRand("reshare-rng-stream", reshareSeed),
			)
		}
		if err != nil {
			fail(err)
		}

		// Self-check 1: old shares interpolate to secret.
		recoveredOld, err := reshare.Verify(r, oldShares, cfg.tOld)
		if err != nil {
			fail(err)
		}
		for p := 0; p < PolyCount; p++ {
			for k := 0; k < N; k++ {
				if recoveredOld[p].Coeffs[0][k] != secret[p].Coeffs[0][k] {
					fail(fmt.Errorf("self-check OLD failed at run=%s p=%d k=%d", cfg.label, p, k))
				}
			}
		}
		// Self-check 2: new shares interpolate to secret.
		newThreshold := cfg.tNew
		if variant == "refresh" {
			newThreshold = cfg.tOld
		}
		recoveredNew, err := reshare.Verify(r, newSharesMap, newThreshold)
		if err != nil {
			fail(err)
		}
		for p := 0; p < PolyCount; p++ {
			for k := 0; k < N; k++ {
				if recoveredNew[p].Coeffs[0][k] != secret[p].Coeffs[0][k] {
					fail(fmt.Errorf("self-check NEW failed at run=%s p=%d k=%d", cfg.label, p, k))
				}
			}
		}

		// Serialize entry.
		entry := Entry{
			Label:             cfg.label,
			Variant:           variant,
			TOld:              cfg.tOld,
			NOld:              cfg.nOld,
			TNew:              cfg.tNew,
			NNew:              len(cfg.newSet),
			OldSet:            oldSet,
			NewSet:            cfg.newSet,
			OldShamirSeedHex:  hex.EncodeToString(shamirSeed),
			ReshareRngSeedHex: hex.EncodeToString(reshareSeed),
		}
		// Secret.
		for p := 0; p < PolyCount; p++ {
			entry.SecretPolysHex = append(entry.SecretPolysHex, uint64SliceToHex(secret[p].Coeffs[0]))
		}
		// Old shares (sorted by party ID for determinism).
		for _, pid := range sortedKeysShare(oldShares) {
			flat := flattenShareU64(oldShares[pid])
			entry.OldSharesHex = append(entry.OldSharesHex, uint64SliceToHex(flat))
			h := sha256.Sum256(uint64SliceToBytes(flat))
			entry.OldShareSHA256Hex = append(entry.OldShareSHA256Hex, hex.EncodeToString(h[:]))
		}
		// New shares (sorted by new committee ordering — keep cfg.newSet order
		// for cross-entry stability).
		for _, pid := range cfg.newSet {
			flat := flattenShareU64(newSharesMap[pid])
			entry.NewSharesHex = append(entry.NewSharesHex, uint64SliceToHex(flat))
			h := sha256.Sum256(uint64SliceToBytes(flat))
			entry.NewShareSHA256Hex = append(entry.NewShareSHA256Hex, hex.EncodeToString(h[:]))
		}
		out.Entries = append(out.Entries, entry)
	}

	// Write the file. Default output: canonical luxcpp KAT directory;
	// allow override via PULSAR_RESHARE_KAT_PATH or a positional arg.
	outPath := filepath.Join(
		os.Getenv("HOME"), "work", "luxcpp", "crypto", "pulsar",
		"test", "kat", "reshare_kat.json",
	)
	if env := os.Getenv("PULSAR_RESHARE_KAT_PATH"); env != "" {
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
	fmt.Fprintf(os.Stderr, "wrote reshare_kat.json (%d entries) → %s\n",
		len(out.Entries), outPath)
}

// buildSecret returns a deterministic secret vector seeded by `secretSeed`,
// each coordinate sampled uniformly in [0, Q) via SHA-256 counter mode +
// rejection.
func buildSecret(r *ring.Ring, secretSeed []byte) []ring.Poly {
	q := r.Modulus()
	out := make([]ring.Poly, PolyCount)
	rng := newCounterRand("secret-stream", secretSeed)
	for p := 0; p < PolyCount; p++ {
		out[p] = r.NewPoly()
		coeffs := make([]*big.Int, N)
		for k := 0; k < N; k++ {
			coeffs[k] = sampleModQ(rng, q)
		}
		bigs := make([]*big.Int, N)
		for k := 0; k < N; k++ {
			bigs[k] = coeffs[k]
		}
		r.SetCoefficientsBigint(bigs, out[p])
	}
	return out
}

// buildStandardShamirShares produces (t, n)-Shamir shares of `secret`
// over the committee `partyIDs` (1-indexed), drawing the (t-1)
// random polynomial coefficients per coordinate from `rng`. This is
// the standard "P(x) = secret + a_1·x + ..." form, identical to
// primitives.ShamirSecretSharingGeneralWithSeed but parameterized by
// arbitrary committee IDs (not just {1, ..., n}). Used to build the
// old-committee shares that feed reshare.Reshare in the KAT.
func buildStandardShamirShares(
	r *ring.Ring, secret []ring.Poly, t int, partyIDs []int,
	rng io.Reader, q *big.Int,
) map[int]reshare.Share {
	out := make(map[int]reshare.Share, len(partyIDs))
	for _, j := range partyIDs {
		v := make(reshare.Share, PolyCount)
		for p := 0; p < PolyCount; p++ {
			v[p] = r.NewPoly()
		}
		out[j] = v
	}

	for p := 0; p < PolyCount; p++ {
		for k := 0; k < N; k++ {
			coeffs := make([]*big.Int, t)
			coeffs[0] = new(big.Int).SetUint64(secret[p].Coeffs[0][k])
			for d := 1; d < t; d++ {
				coeffs[d] = sampleModQ(rng, q)
			}
			for _, j := range partyIDs {
				xj := big.NewInt(int64(j))
				acc := new(big.Int).Set(coeffs[t-1])
				for d := t - 2; d >= 0; d-- {
					acc.Mul(acc, xj)
					acc.Add(acc, coeffs[d])
					acc.Mod(acc, q)
				}
				out[j][p].Coeffs[0][k] = acc.Uint64()
			}
		}
	}
	return out
}

// deriveSeed returns a 32-byte SHA-256 derivation tied to (domain,
// label, run, t, k). This is just a domain separator — the actual
// stream consumed by counterRand is determined by the (domain, seed,
// counter) triple.
func deriveSeed(domain, label string, run, t, k int) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("reshare-oracle:"))
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(label))
	var buf [16]byte
	binary.BigEndian.PutUint32(buf[0:4], 0xC0DEBA5E)
	binary.BigEndian.PutUint32(buf[4:8], uint32(run))
	binary.BigEndian.PutUint32(buf[8:12], uint32(t))
	binary.BigEndian.PutUint32(buf[12:16], uint32(k))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)
}

// sampleModQ matches reshare.sampleModQ exactly so the KAT's hand-rolled
// share-generation step pulls from the same byte stream as Reshare's
// internal sampler.
func sampleModQ(rs io.Reader, q *big.Int) *big.Int {
	qByteLen := len(q.Bytes())
	buf := make([]byte, qByteLen)
	for {
		if _, err := io.ReadFull(rs, buf); err != nil {
			panic(fmt.Errorf("rng read: %w", err))
		}
		v := new(big.Int).SetBytes(buf)
		if v.Cmp(q) < 0 {
			return v
		}
	}
}

func uint64SliceToHex(c []uint64) string {
	buf := make([]byte, 8*len(c))
	for i, v := range c {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return hex.EncodeToString(buf)
}

func uint64SliceToBytes(c []uint64) []byte {
	buf := make([]byte, 8*len(c))
	for i, v := range c {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return buf
}

func flattenShareU64(s reshare.Share) []uint64 {
	var out []uint64
	for _, poly := range s {
		out = append(out, poly.Coeffs[0]...)
	}
	return out
}

func sortedKeysShare(m map[int]reshare.Share) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

// silence the unused import linter for structs (we don't use it directly
// but it shows up via reshare.Share = structs.Vector[ring.Poly]).
var _ = structs.Vector[ring.Poly](nil)

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
