// Package main is the Pulsar sign+verify KAT oracle.
//
// Given a fixed master seed, it emits a deterministic JSON file of
// known-answer test vectors covering the full LP-073 Pulsar threshold
// signature pipeline (Gen + SignRound1 + SignRound2{Preprocess,} +
// SignFinalize + Verify) for the canonical (t, n) configurations
// 2-of-3, 3-of-5, 5-of-7, 7-of-11. The C++ port at
// luxcpp/crypto/pulsar/cpp/sign/ replays these entries byte-equal.
//
// Pulsar's sign/sign.go is byte-identical to ringtail/sign/sign.go (the
// only diff is the import path), so the JSON shape mirrors the existing
// ringtail sign_verify_e2e KAT.
//
// Usage:
//
//	go run ./cmd/sign_oracle --out <dir>
//
// Determinism is required. Two runs with the same MasterSeed produce
// byte-equal JSON files.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
	"github.com/luxfi/pulsar/primitives"
	"github.com/luxfi/pulsar/sign"
	"github.com/luxfi/pulsar/utils"
	"github.com/zeebo/blake3"
)

// MasterSeed is the deterministic root of all KAT generation. Changing
// it invalidates every downstream port's expected outputs, so it stays
// fixed across sessions.
const MasterSeed uint64 = 0xDEADBEEFCAFEBABE

// derive expands MasterSeed into a per-KAT 32-byte sub-seed via BLAKE3
// with a domain-separation tag. This keeps each KAT independent of the
// others (so adding a future KAT does not perturb existing files).
func derive(tag string) []byte {
	h := blake3.New()
	var seedBytes [8]byte
	binary.BigEndian.PutUint64(seedBytes[:], MasterSeed)
	_, _ = h.Write(seedBytes[:])
	_, _ = h.Write([]byte(tag))
	return h.Sum(nil)[:32]
}

// expand returns n bytes of BLAKE3 stream from key (deterministic).
func expand(key []byte, n int) []byte {
	out := make([]byte, n)
	xof := blake3.New()
	_, _ = xof.Write(key)
	_, _ = xof.Digest().Read(out)
	return out
}

// uint64SliceToHex emits a fixed-width 16-hex-char-per-uint64 BE encoding.
func uint64SliceToHex(c []uint64) string {
	out := make([]byte, 0, len(c)*16)
	for _, v := range c {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		out = append(out, []byte(hex.EncodeToString(b[:]))...)
	}
	return string(out)
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func hashMatrix(m structs.Matrix[ring.Poly]) string {
	var buf bytes.Buffer
	_, _ = m.WriteTo(&buf)
	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:])
}

func hashVector(v structs.Vector[ring.Poly]) string {
	var buf bytes.Buffer
	_, _ = v.WriteTo(&buf)
	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:])
}

func hashVectors(m map[int]structs.Vector[ring.Poly], n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = hashVector(m[i])
	}
	return out
}

type signEntry struct {
	T              int      `json:"t"`
	N              int      `json:"n"`
	SeedHex        string   `json:"seed_hex"`
	MsgHex         string   `json:"msg_hex"`
	Msg            string   `json:"msg"`
	AHashHex       string   `json:"a_hash_hex"`
	BTildeHashHex  string   `json:"btilde_hash_hex"`
	SkSharesHex    []string `json:"sk_shares_hash_hex"`
	PartialSigsHex []string `json:"partial_sigs_hash_hex"`
	CHex           string   `json:"c_hex"`
	ZHex           string   `json:"z_hex"`
	DeltaHex       string   `json:"delta_hex"`
	Verify         bool     `json:"verify"`
}

func emitSignVerify(outDir string) error {
	root := derive("sign_e2e_pulsar")
	cfgs := []struct{ t, n int }{
		{2, 3}, {3, 5}, {5, 7}, {7, 11},
	}
	// One canonical message per (t,n). The 4-entry KAT requirement keeps
	// the JSON small while still pinning every Sign+Verify byte path.
	msgPerCfg := []string{"alpha", "beta", "gamma", "delta"}

	out := struct {
		Description string      `json:"description"`
		Entries     []signEntry `json:"entries"`
	}{
		Description: "Full Pulsar Sign+Verify round-trip (LP-073 Q-witness). " +
			"For each (t,n,msg,seed): Gen → SignRound1 (all parties) → " +
			"SignRound2Preprocess+SignRound2 (all parties) → SignFinalize → " +
			"Verify. Pulsar's sign module is byte-identical to ringtail's at " +
			"the Go source level (only the import path differs). The current " +
			"KAT signs with K=Threshold=n; the t field documents the " +
			"threshold-aware variant for downstream use. SHA-256 hashes are " +
			"used for large fields (A, BTilde, sk shares, partial sigs) to " +
			"keep file size finite while still binding the C++ port " +
			"byte-for-byte.",
	}

	var q uint64 = sign.Q
	for ci, cfg := range cfgs {
		seed := expand(append(root, []byte(fmt.Sprintf("cfg-%d", ci))...), 32)
		msg := msgPerCfg[ci]

		// Reset global stateful randomness to ensure determinism across
		// calls. The `utils.PrecomputedRandomness` is process-wide.
		utils.PrecomputedRandomness = nil
		utils.RandomnessIndex = 0

		// Force K = n, Threshold = n so the optimized t=k Shamir path runs.
		sign.K = cfg.n
		sign.Threshold = cfg.n

		r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
		if err != nil {
			return fmt.Errorf("ring.NewRing(Q): %w", err)
		}
		rXi, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QXi})
		rNu, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QNu})

		prng, _ := sampling.NewKeyedPRNG(seed)
		uniformSampler := ring.NewUniformSampler(prng, r)

		T := make([]int, cfg.n)
		for i := range T {
			T[i] = i
		}
		lagrange := primitives.ComputeLagrangeCoefficients(r, T, big.NewInt(int64(q)))

		A, skShares, seeds, macKeys, b := sign.Gen(r, rXi, uniformSampler, seed, lagrange)

		parties := make([]*sign.Party, cfg.n)
		for i := 0; i < cfg.n; i++ {
			prngI, _ := sampling.NewKeyedPRNG(seed)
			usI := ring.NewUniformSampler(prngI, r)
			parties[i] = sign.NewParty(i, r, rXi, rNu, usI)
			parties[i].SkShare = skShares[i]
			parties[i].Seed = seeds
			parties[i].MACKeys = macKeys[i]
			lambda := r.NewPoly()
			lambda.Copy(lagrange[i])
			r.NTT(lambda, lambda)
			r.MForm(lambda, lambda)
			parties[i].Lambda = lambda
		}

		sid := 1
		// GenerateRandomSeed pulls the next KeySize bytes from the same
		// PrecomputedRandomness stream that sign.Gen seeded; this makes
		// the prfKey deterministic given `seed` (the C++ runner's
		// recover_prf_key reproduces the same bytes).
		prfKey := primitives.GenerateRandomSeed()

		D := make(map[int]structs.Matrix[ring.Poly])
		MACs := make(map[int]map[int][]byte)
		for _, pid := range T {
			D[pid], MACs[pid] = parties[pid].SignRound1(A, sid, prfKey, T)
		}

		z := make(map[int]structs.Vector[ring.Poly])
		for _, pid := range T {
			ok, DSum, hash := parties[pid].SignRound2Preprocess(A, b, D, MACs, sid, T)
			if !ok {
				return fmt.Errorf("sign-e2e: MAC verify failed t=%d n=%d msg=%q",
					cfg.t, cfg.n, msg)
			}
			z[pid] = parties[pid].SignRound2(A, b, DSum, sid, msg, T, prfKey, hash)
		}

		final := parties[0]
		c, zSum, delta := final.SignFinalize(z, A, b)

		ok := sign.Verify(r, rXi, rNu, zSum, A, msg, b, c, delta)
		if !ok {
			return fmt.Errorf("sign-e2e: Verify returned false for cfg=(%d,%d) msg=%q",
				cfg.t, cfg.n, msg)
		}

		out.Entries = append(out.Entries, signEntry{
			T:              cfg.t,
			N:              cfg.n,
			SeedHex:        hex.EncodeToString(seed),
			MsgHex:         hex.EncodeToString([]byte(msg)),
			Msg:            msg,
			AHashHex:       hashMatrix(A),
			BTildeHashHex:  hashVector(b),
			SkSharesHex:    hashVectors(skShares, cfg.n),
			PartialSigsHex: hashVectors(z, cfg.n),
			CHex:           uint64SliceToHex(c.Coeffs[0]),
			ZHex:           hashVector(zSum),
			DeltaHex:       hashVector(delta),
			Verify:         ok,
		})
	}

	return writeJSON(filepath.Join(outDir, "sign_kat.json"), out)
}

func main() {
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: sign_oracle --out <dir>")
		os.Exit(2)
	}
	if err := emitSignVerify(*out); err != nil {
		fmt.Fprintf(os.Stderr, "emit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s/sign_kat.json (4 entries)\n", *out)
}
