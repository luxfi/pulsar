// Package main is the Ringtail KAT oracle.
//
// Given a fixed master seed, it emits seven JSON files of known-answer
// test vectors covering every internal that the upcoming C++ and GPU ports
// must byte-match: the BLAKE2-XOF KeyedPRNG stream from Lattigo, the
// discrete-Gaussian sampler, Montgomery/NTT operations on Q=0x1000000004A01,
// the structs.Matrix[ring.Poly] wire format, the BLAKE3 transcripts in
// ringtail/primitives/hash.go, deterministic Shamir over R_q, and a full
// Sign+Verify round-trip.
//
// Usage:
//
//	go run ./cmd/ringtail_oracle_v2 emit --out <dir>
//
// Determinism is required. Two runs with the same seed produce byte-equal
// JSON files. The seed is fixed at MasterSeed = 0xDEADBEEFCAFEBABE.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
	"github.com/luxfi/pulsar/primitives"
	"github.com/luxfi/pulsar/sign"
	"github.com/luxfi/pulsar/utils"
	"github.com/spf13/cobra"
	"github.com/zeebo/blake3"
)

// MasterSeed is the deterministic root of all KAT generation. Changing it
// invalidates every downstream port's expected outputs, so it stays fixed
// across sessions.
const MasterSeed uint64 = 0xDEADBEEFCAFEBABE

// derive expands MasterSeed into a per-KAT 32-byte sub-seed via BLAKE3 with
// a domain-separation tag. This keeps each KAT independent of the others
// (so adding a future KAT does not perturb existing files).
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
	h := blake3.New()
	_, _ = h.Write(key)
	d := h.Digest()
	out := make([]byte, n)
	if _, err := io.ReadFull(d, out); err != nil {
		panic(err)
	}
	return out
}

// ---------- shared types ----------

type kvHex struct {
	Key string `json:"key"`
	Val string `json:"val"`
}

func uint64SliceToHex(c []uint64) string {
	buf := make([]byte, 8*len(c))
	for i, v := range c {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return hex.EncodeToString(buf)
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

// ---------- KAT 1: BLAKE2-XOF KeyedPRNG ----------

type prngEntry struct {
	SeedHex   string `json:"seed_hex"`
	StreamHex string `json:"stream_hex"`
	StreamLen int    `json:"stream_len"`
}

func emitPRNG(outDir string) error {
	// blake2b XOF caps key length at 64 bytes; we cover 16/32/48/64.
	seedLengths := []int{16, 32, 48, 64}
	root := derive("prng")
	out := struct {
		Description string      `json:"description"`
		Algorithm   string      `json:"algorithm"`
		Entries     []prngEntry `json:"entries"`
	}{
		Description: "Lattigo KeyedPRNG (BLAKE2b XOF) — first 1024 bytes of stream per seed.",
		Algorithm:   "blake2b-xof, OutputLengthUnknown, key=seed",
		Entries:     make([]prngEntry, 0, len(seedLengths)),
	}
	for _, n := range seedLengths {
		seed := expand(append(root, byte(n)), n)
		prng, err := sampling.NewKeyedPRNG(seed)
		if err != nil {
			return err
		}
		stream := make([]byte, 1024)
		if _, err := prng.Read(stream); err != nil {
			return err
		}
		out.Entries = append(out.Entries, prngEntry{
			SeedHex:   hex.EncodeToString(seed),
			StreamHex: hex.EncodeToString(stream),
			StreamLen: len(stream),
		})
	}
	return writeJSON(filepath.Join(outDir, "prng_blake2_xof.json"), out)
}

// ---------- KAT 2: Discrete Gaussian ----------

type gaussianEntry struct {
	SeedHex  string  `json:"seed_hex"`
	Sigma    float64 `json:"sigma"`
	Bound    float64 `json:"bound"`
	N        int     `json:"n"`
	Coeffs   []int64 `json:"coeffs"`
	Modulus  uint64  `json:"modulus"`
	BytesLog string  `json:"bytes_consumed_note"`
}

func emitGaussian(outDir string) error {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return err
	}
	type sigCfg struct {
		name  string
		sigma float64
		bound float64
	}
	cfgs := []sigCfg{
		{"sigma_e", sign.SigmaE, sign.BoundE},
		{"sigma_u", sign.SigmaU, sign.BoundU},
		{"sigma_1", 1.0, 6.0},
		{"sigma_8", 8.0, 48.0},
		{"sigma_100", 100.0, 600.0},
	}
	root := derive("gaussian")
	var q uint64 = sign.Q
	halfQ := q / 2

	out := struct {
		Description string          `json:"description"`
		Modulus     uint64           `json:"modulus"`
		N           int             `json:"n"`
		Entries     []gaussianEntry `json:"entries"`
	}{
		Description: "Lattigo discrete Gaussian sampler. Coefficients in centered representation: " +
			"if c > Q/2, c -= Q. Each sample drains a 1024-byte BLAKE2-XOF buffer in 4-byte and 8-byte " +
			"chunks via Ziggurat (see ring/sampler_gaussian.go).",
		Modulus: q,
		N:       1 << sign.LogN,
	}
	for _, c := range cfgs {
		seed := expand(append(root, []byte(c.name)...), 32)
		prng, _ := sampling.NewKeyedPRNG(seed)
		samp := ring.NewGaussianSampler(prng, r, ring.DiscreteGaussian{
			Sigma: c.sigma, Bound: c.bound,
		}, false)
		poly := samp.ReadNew()
		coeffs := make([]int64, r.N())
		for i, u := range poly.Coeffs[0] {
			if u > halfQ {
				coeffs[i] = -int64(q - u)
			} else {
				coeffs[i] = int64(u)
			}
		}
		out.Entries = append(out.Entries, gaussianEntry{
			SeedHex: hex.EncodeToString(seed),
			Sigma:   c.sigma,
			Bound:   c.bound,
			N:       r.N(),
			Coeffs:  coeffs,
			Modulus: q,
			BytesLog: "Ziggurat reads 1024-byte buffer; per-sample byte budget is " +
				"variable (rejection sampling). C++ port must match buffer refill semantics, " +
				"not byte count per sample.",
		})
	}
	return writeJSON(filepath.Join(outDir, "discrete_gaussian.json"), out)
}

// ---------- KAT 3: Montgomery / NTT ----------

type mformEntry struct {
	InputHex  string `json:"input_hex"`
	OutputHex string `json:"output_hex"`
}

type mulEntry struct {
	AHex   string `json:"a_hex"`
	BHex   string `json:"b_hex"`
	OutHex string `json:"out_hex"`
}

type mulAccumEntry struct {
	AHex   string `json:"a_hex"`
	BHex   string `json:"b_hex"`
	AccHex string `json:"acc_in_hex"`
	OutHex string `json:"acc_out_hex"`
}

func emitMontgomeryNTT(outDir string) error {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return err
	}
	N := r.N()
	q := r.SubRings[0].Modulus
	mask := r.SubRings[0].Mask

	root := derive("ntt")

	// Helper: pull 64-bit values < Q from BLAKE3 stream (rejection-sample to mask).
	type stream struct {
		buf []byte
		off int
	}
	pullPoly := func(s *stream) []uint64 {
		out := make([]uint64, N)
		for i := 0; i < N; i++ {
			for {
				if s.off+8 > len(s.buf) {
					more := expand(s.buf[len(s.buf)-32:], 8192)
					s.buf = append(s.buf, more...)
				}
				v := binary.BigEndian.Uint64(s.buf[s.off:s.off+8]) & mask
				s.off += 8
				if v < q {
					out[i] = v
					break
				}
			}
		}
		return out
	}

	mform := make([]mformEntry, 0, 64)
	imform := make([]mformEntry, 0, 64)
	nttE := make([]mformEntry, 0, 64)
	inttE := make([]mformEntry, 0, 64)
	mul := make([]mulEntry, 0, 64)
	mulAdd := make([]mulAccumEntry, 0, 64)

	s := &stream{buf: expand(root, 1<<20)}

	for i := 0; i < 64; i++ {
		in := pullPoly(s)
		// MForm
		p1 := r.NewPoly()
		copy(p1.Coeffs[0], in)
		p2 := r.NewPoly()
		r.MForm(p1, p2)
		mform = append(mform, mformEntry{
			InputHex:  uint64SliceToHex(in),
			OutputHex: uint64SliceToHex(p2.Coeffs[0]),
		})
		// IMForm: round-trip from p2 (which is now Montgomery form of in).
		p3 := r.NewPoly()
		r.IMForm(p2, p3)
		imform = append(imform, mformEntry{
			InputHex:  uint64SliceToHex(p2.Coeffs[0]),
			OutputHex: uint64SliceToHex(p3.Coeffs[0]),
		})
	}

	for i := 0; i < 64; i++ {
		in := pullPoly(s)
		p1 := r.NewPoly()
		copy(p1.Coeffs[0], in)
		p2 := r.NewPoly()
		r.NTT(p1, p2)
		nttE = append(nttE, mformEntry{
			InputHex:  uint64SliceToHex(in),
			OutputHex: uint64SliceToHex(p2.Coeffs[0]),
		})
		// INTT round-trip
		p3 := r.NewPoly()
		r.INTT(p2, p3)
		inttE = append(inttE, mformEntry{
			InputHex:  uint64SliceToHex(p2.Coeffs[0]),
			OutputHex: uint64SliceToHex(p3.Coeffs[0]),
		})
	}

	for i := 0; i < 64; i++ {
		a := pullPoly(s)
		b := pullPoly(s)
		// MulCoeffsMontgomery expects Montgomery-form inputs. We keep as-is (raw uniform mod q),
		// matching ringtail's protocol invariant: NTT-Montgomery inputs.
		pa := r.NewPoly()
		copy(pa.Coeffs[0], a)
		pb := r.NewPoly()
		copy(pb.Coeffs[0], b)
		pc := r.NewPoly()
		r.MulCoeffsMontgomery(pa, pb, pc)
		mul = append(mul, mulEntry{
			AHex:   uint64SliceToHex(a),
			BHex:   uint64SliceToHex(b),
			OutHex: uint64SliceToHex(pc.Coeffs[0]),
		})
	}

	for i := 0; i < 64; i++ {
		a := pullPoly(s)
		b := pullPoly(s)
		acc := pullPoly(s)
		pa := r.NewPoly()
		copy(pa.Coeffs[0], a)
		pb := r.NewPoly()
		copy(pb.Coeffs[0], b)
		pc := r.NewPoly()
		copy(pc.Coeffs[0], acc)
		r.MulCoeffsMontgomeryThenAdd(pa, pb, pc)
		mulAdd = append(mulAdd, mulAccumEntry{
			AHex:   uint64SliceToHex(a),
			BHex:   uint64SliceToHex(b),
			AccHex: uint64SliceToHex(acc),
			OutHex: uint64SliceToHex(pc.Coeffs[0]),
		})
	}

	sub := r.SubRings[0]
	out := struct {
		Description    string             `json:"description"`
		Modulus        uint64             `json:"modulus"`
		N              int                `json:"n"`
		BRedConstant   [2]uint64          `json:"bred_constant"`
		MRedConstant   uint64             `json:"mred_constant"`
		Mask           uint64             `json:"mask"`
		PrimitiveRoot  uint64             `json:"primitive_root"`
		NthRoot        uint64             `json:"nth_root"`
		NInvMontgomery uint64             `json:"n_inv_montgomery"`
		RootsForward   string             `json:"roots_forward_hex"`
		RootsBackward  string             `json:"roots_backward_hex"`
		MForm          []mformEntry       `json:"mform"`
		IMForm         []mformEntry       `json:"imform"`
		NTT            []mformEntry       `json:"ntt"`
		INTT           []mformEntry       `json:"intt"`
		Mul            []mulEntry         `json:"mul_coeffs_montgomery"`
		MulAdd         []mulAccumEntry    `json:"mul_coeffs_montgomery_then_add"`
	}{
		Description: "Lattigo Ring at Q=0x1000000004A01, N=256. Constants and " +
			"forward/inverse NTT + Montgomery transform KATs. Inputs are uint64 " +
			"polynomials with coefficients < Q, big-endian-packed.",
		Modulus:        q,
		N:              N,
		BRedConstant:   sub.BRedConstant,
		MRedConstant:   sub.MRedConstant,
		Mask:           sub.Mask,
		PrimitiveRoot:  sub.PrimitiveRoot,
		NthRoot:        sub.NthRoot,
		NInvMontgomery: sub.NInv,
		RootsForward:   uint64SliceToHex(sub.RootsForward),
		RootsBackward:  uint64SliceToHex(sub.RootsBackward),
		MForm:          mform,
		IMForm:         imform,
		NTT:            nttE,
		INTT:           inttE,
		Mul:            mul,
		MulAdd:         mulAdd,
	}
	return writeJSON(filepath.Join(outDir, "montgomery_ntt.json"), out)
}

// ---------- KAT 4: structs.Matrix[ring.Poly] wire format ----------

type matrixEntry struct {
	Rows     int      `json:"rows"`
	Cols     int      `json:"cols"`
	PolysHex []string `json:"polys_hex"`
	WireHex  string   `json:"wire_hex"`
	WireLen  int      `json:"wire_len"`
}

func emitMatrixWire(outDir string) error {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return err
	}
	shapes := []struct{ rows, cols int }{
		{1, 1},
		{2, 2},
		{3, 5},
		{5, 7},
		{7, 11},
	}
	root := derive("matrix_wire")
	stream := expand(root, 1<<20)
	off := 0
	var q uint64 = sign.Q
	mask := r.SubRings[0].Mask
	pullCoeff := func() uint64 {
		for {
			if off+8 > len(stream) {
				stream = append(stream, expand(stream[len(stream)-32:], 1<<20)...)
			}
			v := binary.BigEndian.Uint64(stream[off:off+8]) & mask
			off += 8
			if v < q {
				return v
			}
		}
	}

	out := struct {
		Description string        `json:"description"`
		Modulus     uint64        `json:"modulus"`
		N           int           `json:"n"`
		Entries     []matrixEntry `json:"entries"`
	}{
		Description: "structs.Matrix[ring.Poly].WriteTo. Wire format: " +
			"u64 rows, then for each row { u64 cols, then for each poly: " +
			"u64 levels (=1), u64 N, raw u64 coeffs }. Big-endian throughout (Lattigo buffer.WriteAsUint64).",
		Modulus: q,
		N:       r.N(),
	}

	for _, sh := range shapes {
		mat := make(structs.Matrix[ring.Poly], sh.rows)
		polysHex := make([]string, 0, sh.rows*sh.cols)
		for i := 0; i < sh.rows; i++ {
			mat[i] = make([]ring.Poly, sh.cols)
			for j := 0; j < sh.cols; j++ {
				p := r.NewPoly()
				for k := 0; k < r.N(); k++ {
					p.Coeffs[0][k] = pullCoeff()
				}
				mat[i][j] = p
				polysHex = append(polysHex, uint64SliceToHex(p.Coeffs[0]))
			}
		}
		var buf bytes.Buffer
		if _, err := mat.WriteTo(&buf); err != nil {
			return err
		}
		out.Entries = append(out.Entries, matrixEntry{
			Rows:     sh.rows,
			Cols:     sh.cols,
			PolysHex: polysHex,
			WireHex:  hex.EncodeToString(buf.Bytes()),
			WireLen:  buf.Len(),
		})
	}
	return writeJSON(filepath.Join(outDir, "structs_matrix_wire.json"), out)
}

// ---------- KAT 5: BLAKE3 transcripts (Hash, LowNormHash, MAC, GaussianHash, PRF) ----------

type transcriptEntry struct {
	Name      string   `json:"name"`
	InputDesc string   `json:"input_desc"`
	OutputHex string   `json:"output_hex"`
	Extras    []kvHex  `json:"extras,omitempty"`
}

func emitTranscripts(outDir string) error {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return err
	}
	root := derive("transcripts")
	stream := expand(root, 1<<22)
	off := 0
	var q uint64 = sign.Q
	mask := r.SubRings[0].Mask
	pullCoeff := func() uint64 {
		for {
			if off+8 > len(stream) {
				stream = append(stream, expand(stream[len(stream)-32:], 1<<20)...)
			}
			v := binary.BigEndian.Uint64(stream[off:off+8]) & mask
			off += 8
			if v < q {
				return v
			}
		}
	}
	pullBytes := func(n int) []byte {
		if off+n > len(stream) {
			stream = append(stream, expand(stream[len(stream)-32:], 1<<20)...)
		}
		b := append([]byte(nil), stream[off:off+n]...)
		off += n
		return b
	}
	pullPoly := func() ring.Poly {
		p := r.NewPoly()
		for i := 0; i < r.N(); i++ {
			p.Coeffs[0][i] = pullCoeff()
		}
		return p
	}
	pullMatrix := func(rows, cols int) structs.Matrix[ring.Poly] {
		m := make(structs.Matrix[ring.Poly], rows)
		for i := range m {
			m[i] = make([]ring.Poly, cols)
			for j := range m[i] {
				m[i][j] = pullPoly()
			}
		}
		return m
	}
	pullVector := func(n int) structs.Vector[ring.Poly] {
		v := make(structs.Vector[ring.Poly], n)
		for i := range v {
			v[i] = pullPoly()
		}
		return v
	}

	out := struct {
		Description string            `json:"description"`
		Modulus     uint64            `json:"modulus"`
		N           int               `json:"n"`
		Entries     []transcriptEntry `json:"entries"`
	}{
		Description: "Ringtail BLAKE3 transcripts: Hash, LowNormHash, GenerateMAC, " +
			"GaussianHash, PRF, PRNGKey. Each entry feeds Vector/Matrix.WriteTo + " +
			"binary.BigEndian-encoded scalars into BLAKE3 and emits the 32-byte digest. " +
			"For samplers (LowNormHash, GaussianHash, PRF) the output_hex is the digest; " +
			"the sampled poly/vector follows in the extras.",
		Modulus: q,
		N:       r.N(),
	}

	// 16 fixed bundles per transcript. Mix matrix shapes, T sets, sids.
	bundleCount := 16
	for i := 0; i < bundleCount; i++ {
		// --- Hash(A, b, D, sid, T) ---
		A := pullMatrix(sign.M, sign.N)
		b := pullVector(sign.M)
		D := map[int]structs.Matrix[ring.Poly]{
			0: pullMatrix(sign.M, sign.Dbar+1),
			1: pullMatrix(sign.M, sign.Dbar+1),
			2: pullMatrix(sign.M, sign.Dbar+1),
		}
		sid := int(int64(i) * 7)
		T := []int{0, 1, 2}
		hashOut := primitives.Hash(A, b, D, sid, T)
		out.Entries = append(out.Entries, transcriptEntry{
			Name:      "Hash",
			InputDesc: fmt.Sprintf("bundle=%d, sid=%d, |T|=%d, A=%dx%d, b len=%d, |D|=%d", i, sid, len(T), sign.M, sign.N, sign.M, len(D)),
			OutputHex: hex.EncodeToString(hashOut),
		})

		// --- LowNormHash(A, b, h, mu, kappa) → ring.Poly (sampled in NTT-Montgomery) ---
		// Reuse A, b; sample h independently
		h := pullVector(sign.M)
		mu := fmt.Sprintf("msg-%02x", i)
		c := primitives.LowNormHash(r, A, b, h, mu, sign.Kappa)
		// LowNormHash internally rebuilds the digest before sampling. To capture both,
		// recompute the digest the same way the function does so the C++ port can
		// validate hash → sampler chaining.
		dig := lowNormDigest(A, b, h, mu)
		out.Entries = append(out.Entries, transcriptEntry{
			Name:      "LowNormHash",
			InputDesc: fmt.Sprintf("bundle=%d, mu=%q, kappa=%d, h len=%d", i, mu, sign.Kappa, len(h)),
			OutputHex: hex.EncodeToString(dig),
			Extras: []kvHex{
				{Key: "sampled_c_hex", Val: uint64SliceToHex(c.Coeffs[0])},
			},
		})

		// --- GenerateMAC ---
		TildeD := pullMatrix(sign.M, sign.Dbar+1)
		macKey := pullBytes(32)
		partyID := i % 7
		otherParty := (partyID + 1) % 7
		mac := primitives.GenerateMAC(TildeD, macKey, partyID, sid, T, otherParty, false)
		macVerify := primitives.GenerateMAC(TildeD, macKey, partyID, sid, T, otherParty, true)
		out.Entries = append(out.Entries, transcriptEntry{
			Name:      "GenerateMAC",
			InputDesc: fmt.Sprintf("bundle=%d, partyID=%d, otherParty=%d, sid=%d, |T|=%d", i, partyID, otherParty, sid, len(T)),
			OutputHex: hex.EncodeToString(mac),
			Extras: []kvHex{
				{Key: "mac_verify_branch_hex", Val: hex.EncodeToString(macVerify)},
				{Key: "mac_key_hex", Val: hex.EncodeToString(macKey)},
			},
		})

		// --- GaussianHash ---
		ghHash := pullBytes(32)
		ghMu := fmt.Sprintf("gh-%02x", i)
		gh := primitives.GaussianHash(r, ghHash, ghMu, sign.SigmaU, sign.BoundU, sign.Dbar)
		ghDig := keyedDigest("GaussianHash", ghHash, ghMu)
		// Concat all sampled coeffs of gh (each is NTT-Montgomery, so deterministic).
		ghCoeffs := bytes.Buffer{}
		for _, p := range gh {
			_, _ = ghCoeffs.WriteString(uint64SliceToHex(p.Coeffs[0]))
		}
		out.Entries = append(out.Entries, transcriptEntry{
			Name:      "GaussianHash",
			InputDesc: fmt.Sprintf("bundle=%d, mu=%q, sigma=SigmaU, length=Dbar=%d", i, ghMu, sign.Dbar),
			OutputHex: hex.EncodeToString(ghDig),
			Extras: []kvHex{
				{Key: "sampled_concat_hex", Val: ghCoeffs.String()},
			},
		})

		// --- PRF ---
		prfKey := pullBytes(32)
		sd_ij := pullBytes(32)
		prfMu := fmt.Sprintf("prf-%02x", i)
		prfHash := pullBytes(32)
		prfMask := primitives.PRF(r, sd_ij, prfKey, prfMu, prfHash, sign.N)
		prfDig := prfDigest(prfKey, sd_ij, prfHash, prfMu)
		prfCoeffs := bytes.Buffer{}
		for _, p := range prfMask {
			_, _ = prfCoeffs.WriteString(uint64SliceToHex(p.Coeffs[0]))
		}
		out.Entries = append(out.Entries, transcriptEntry{
			Name:      "PRF",
			InputDesc: fmt.Sprintf("bundle=%d, mu=%q, n=%d", i, prfMu, sign.N),
			OutputHex: hex.EncodeToString(prfDig),
			Extras: []kvHex{
				{Key: "prf_key_hex", Val: hex.EncodeToString(prfKey)},
				{Key: "sd_ij_hex", Val: hex.EncodeToString(sd_ij)},
				{Key: "hash_hex", Val: hex.EncodeToString(prfHash)},
				{Key: "sampled_concat_hex", Val: prfCoeffs.String()},
			},
		})

		// --- PRNGKey(skShare) ---
		skShare := pullVector(sign.N)
		prngKey := primitives.PRNGKey(skShare)
		out.Entries = append(out.Entries, transcriptEntry{
			Name:      "PRNGKey",
			InputDesc: fmt.Sprintf("bundle=%d, skShare len=%d", i, len(skShare)),
			OutputHex: hex.EncodeToString(prngKey),
		})
	}

	return writeJSON(filepath.Join(outDir, "transcript_hash.json"), out)
}

// lowNormDigest rebuilds the BLAKE3 digest LowNormHash hashes before sampling.
func lowNormDigest(A structs.Matrix[ring.Poly], b, h structs.Vector[ring.Poly], mu string) []byte {
	hh := blake3.New()
	buf := new(bytes.Buffer)
	_, _ = A.WriteTo(buf)
	_, _ = b.WriteTo(buf)
	_, _ = h.WriteTo(buf)
	_ = binary.Write(buf, binary.BigEndian, []byte(mu))
	_, _ = hh.Write(buf.Bytes())
	return hh.Sum(nil)[:32]
}

// keyedDigest rebuilds GaussianHash's pre-sampler digest.
func keyedDigest(_ string, hash []byte, mu string) []byte {
	hh := blake3.New()
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, hash)
	_, _ = buf.WriteString(mu)
	_, _ = hh.Write(buf.Bytes())
	return hh.Sum(nil)[:32]
}

// prfDigest rebuilds PRF's pre-sampler digest.
func prfDigest(prfKey, sd_ij, hash []byte, mu string) []byte {
	hh := blake3.New()
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, prfKey)
	_ = binary.Write(buf, binary.BigEndian, sd_ij)
	_ = binary.Write(buf, binary.BigEndian, hash)
	_, _ = buf.WriteString(mu)
	_, _ = hh.Write(buf.Bytes())
	return hh.Sum(nil)[:32]
}

// ---------- KAT 6: Shamir over R_q ----------

type shamirEntry struct {
	T            int      `json:"t"`
	N            int      `json:"n"`
	SecretHex    string   `json:"secret_hex"`
	SharesHex    []string `json:"shares_hex"`
	Indices      []int    `json:"indices"`
	RecoveredHex string   `json:"recovered_hex"`
	Match        bool     `json:"match"`
}

// deterministicShamir mirrors primitives.ShamirSecretSharingGeneral but draws
// the polynomial coefficients from a BLAKE3 stream so the KAT is reproducible.
// Same algebra (poly P(x) = secret + a1*x + ... + a_{t-1}*x^{t-1} mod Q) and
// same wire format (each party's share is a poly with coefficient set in
// non-NTT representation, level 0).
func deterministicShamir(r *ring.Ring, s ring.Poly, t, n int, seed []byte) (map[int]ring.Poly, []byte) {
	q := r.Modulus()
	N := r.N()
	rng := blake3.New()
	_, _ = rng.Write(seed)
	stream := rng.Digest()
	qByteLen := len(q.Bytes())

	pullBig := func() *big.Int {
		buf := make([]byte, qByteLen)
		if _, err := io.ReadFull(stream, buf); err != nil {
			panic(err)
		}
		v := new(big.Int).SetBytes(buf)
		return v.Mod(v, q)
	}

	shares := make(map[int]ring.Poly, n)
	for i := 1; i <= n; i++ {
		shares[i] = r.NewPoly()
	}

	coeffsBig := make([]*big.Int, N)
	r.PolyToBigint(s, 1, coeffsBig)

	// hash of the realized "a_i,j" polys — emitted so C++ port can replay the
	// exact same coefficient sequence. We commit to it implicitly by exposing
	// the seed (caller knows the algorithm).
	streamCommit := blake3.New()

	for k := 0; k < N; k++ {
		secret := coeffsBig[k]
		polyCoeffs := make([]*big.Int, t)
		polyCoeffs[0] = secret
		for j := 1; j < t; j++ {
			a := pullBig()
			polyCoeffs[j] = a
			ab := a.Bytes()
			pad := make([]byte, qByteLen-len(ab))
			_, _ = streamCommit.Write(pad)
			_, _ = streamCommit.Write(ab)
		}
		for partyIdx := 1; partyIdx <= n; partyIdx++ {
			x := big.NewInt(int64(partyIdx))
			val := big.NewInt(0)
			xPow := big.NewInt(1)
			for _, c := range polyCoeffs {
				term := new(big.Int).Mul(c, xPow)
				val.Add(val, term)
				val.Mod(val, q)
				xPow.Mul(xPow, x)
			}
			shares[partyIdx].Coeffs[0][k] = val.Uint64()
		}
	}
	return shares, streamCommit.Sum(nil)[:32]
}

// recoverShamir reconstructs the secret poly from t shares using Lagrange
// interpolation at x=0. Indices are 1-based party indices (the same x-values
// used during sharing).
func recoverShamir(r *ring.Ring, shares map[int]ring.Poly, indices []int) ring.Poly {
	q := r.Modulus()
	N := r.N()
	out := r.NewPoly()
	for k := 0; k < N; k++ {
		acc := big.NewInt(0)
		for _, i := range indices {
			xi := big.NewInt(int64(i))
			num := big.NewInt(1)
			den := big.NewInt(1)
			for _, j := range indices {
				if i == j {
					continue
				}
				xj := big.NewInt(int64(j))
				num.Mul(num, new(big.Int).Neg(xj))
				num.Mod(num, q)
				den.Mul(den, new(big.Int).Sub(xi, xj))
				den.Mod(den, q)
			}
			lambda := new(big.Int).Mul(num, new(big.Int).ModInverse(den, q))
			lambda.Mod(lambda, q)
			yi := new(big.Int).SetUint64(shares[i].Coeffs[0][k])
			acc.Add(acc, new(big.Int).Mul(yi, lambda))
			acc.Mod(acc, q)
		}
		out.Coeffs[0][k] = acc.Uint64()
	}
	return out
}

func emitShamir(outDir string) error {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		return err
	}
	cfgs := []struct{ t, n int }{
		{2, 3}, {3, 5}, {5, 7}, {7, 11},
	}
	root := derive("shamir")
	stream := expand(root, 1<<20)
	off := 0
	var q uint64 = sign.Q
	mask := r.SubRings[0].Mask
	pullCoeff := func() uint64 {
		for {
			if off+8 > len(stream) {
				stream = append(stream, expand(stream[len(stream)-32:], 1<<20)...)
			}
			v := binary.BigEndian.Uint64(stream[off:off+8]) & mask
			off += 8
			if v < q {
				return v
			}
		}
	}

	out := struct {
		Description string        `json:"description"`
		Modulus     uint64        `json:"modulus"`
		N           int           `json:"n"`
		Entries     []shamirEntry `json:"entries"`
	}{
		Description: "Shamir secret sharing of a single ring.Poly secret over R_q. " +
			"Polynomial coefficients (a_1..a_{t-1}) drawn from BLAKE3(seed=master||\"shamir\"||tn). " +
			"Shares evaluated at x=1..n. Recovery uses Lagrange interpolation at x=0 from the first t shares. " +
			"Coefficients are in standard (non-NTT) form, level 0, big-endian uint64.",
		Modulus: q,
		N:       r.N(),
	}

	for run := 0; run < 4; run++ {
		for _, cfg := range cfgs {
			secret := r.NewPoly()
			for i := 0; i < r.N(); i++ {
				secret.Coeffs[0][i] = pullCoeff()
			}
			shamirSeed := blake3.New()
			_, _ = shamirSeed.Write(root)
			_ = binary.Write(shamirSeed, binary.BigEndian, int32(run))
			_ = binary.Write(shamirSeed, binary.BigEndian, int32(cfg.t))
			_ = binary.Write(shamirSeed, binary.BigEndian, int32(cfg.n))
			seed := shamirSeed.Sum(nil)[:32]

			shares, _ := deterministicShamir(r, secret, cfg.t, cfg.n, seed)

			indices := make([]int, 0, cfg.t)
			for i := 1; i <= cfg.t; i++ {
				indices = append(indices, i)
			}
			recovered := recoverShamir(r, shares, indices)

			sharesHex := make([]string, cfg.n)
			keys := make([]int, 0, cfg.n)
			for k := range shares {
				keys = append(keys, k)
			}
			sort.Ints(keys)
			for i, k := range keys {
				sharesHex[i] = uint64SliceToHex(shares[k].Coeffs[0])
			}

			match := true
			for i := 0; i < r.N(); i++ {
				if recovered.Coeffs[0][i] != secret.Coeffs[0][i] {
					match = false
					break
				}
			}

			out.Entries = append(out.Entries, shamirEntry{
				T:            cfg.t,
				N:            cfg.n,
				SecretHex:    uint64SliceToHex(secret.Coeffs[0]),
				SharesHex:    sharesHex,
				Indices:      indices,
				RecoveredHex: uint64SliceToHex(recovered.Coeffs[0]),
				Match:        match,
			})
			if !match {
				return fmt.Errorf("shamir round-trip failed for t=%d n=%d run=%d", cfg.t, cfg.n, run)
			}
		}
	}
	return writeJSON(filepath.Join(outDir, "shamir_share.json"), out)
}

// ---------- KAT 7: Sign + Verify end-to-end ----------

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
	root := derive("sign_e2e")
	cfgs := []struct{ t, n int }{
		{2, 3}, {3, 5}, {5, 7}, {7, 11},
	}
	messages := []string{"alpha", "beta", "gamma", "delta"}

	out := struct {
		Description string      `json:"description"`
		Entries     []signEntry `json:"entries"`
	}{
		Description: "Full Ringtail Sign+Verify round-trip. For each (t,n,msg,seed): " +
			"Gen → SignRound1 (all parties) → SignRound2Preprocess+SignRound2 (all parties) → " +
			"SignFinalize → Verify. Note: ringtail/sign currently signs with K=Threshold=n " +
			"(see threshold.GenerateKeys). The n in this KAT is the total signer count; " +
			"the t is documented for the C++ port to validate threshold-aware sharing logic " +
			"once it is implemented downstream. SHA-256 hashes are used for large fields " +
			"(A, BTilde, sk shares, partial sigs) to keep file size finite while still " +
			"binding the C++ implementation byte-for-byte.",
	}

	var q uint64 = sign.Q
	for ci, cfg := range cfgs {
		for mi, msg := range messages {
			tag := fmt.Sprintf("cfg-%d-msg-%d", ci, mi)
			seed := expand(append(root, []byte(tag)...), 32)

			// Reset global stateful randomness to ensure determinism across calls.
			utils.PrecomputedRandomness = nil
			utils.RandomnessIndex = 0

			// Force K = n, Threshold = n so the optimized t=k Shamir path runs.
			// (sign.Gen requires global K+Threshold; the protocol assumes n parties sign.)
			sign.K = cfg.n
			sign.Threshold = cfg.n

			r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
			if err != nil {
				return err
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

			// Build parties.
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
					return fmt.Errorf("sign-e2e: MAC verify failed t=%d n=%d msg=%q", cfg.t, cfg.n, msg)
				}
				z[pid] = parties[pid].SignRound2(A, b, DSum, sid, msg, T, prfKey, hash)
			}

			final := parties[0]
			c, zSum, delta := final.SignFinalize(z, A, b)

			ok := sign.Verify(r, rXi, rNu, zSum, A, msg, b, c, delta)
			if !ok {
				return fmt.Errorf("sign-e2e: Verify returned false for cfg=(%d,%d) msg=%q", cfg.t, cfg.n, msg)
			}

			// Hash the bulky fields so the file stays under 1 MB. The hashes
			// are full commitments — any byte change in the C++ port flips them.
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
				ZHex:           hashVectorOne(zSum),
				DeltaHex:       hashVectorOne(delta),
				Verify:         ok,
			})
		}
	}
	return writeJSON(filepath.Join(outDir, "sign_verify_e2e.json"), out)
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

func hashVectorOne(v structs.Vector[ring.Poly]) string {
	return hashVector(v)
}

func hashVectors(m map[int]structs.Vector[ring.Poly], n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = hashVector(m[i])
	}
	return out
}

// ---------- main ----------

func main() {
	root := &cobra.Command{Use: "ringtail_oracle_v2"}
	emit := &cobra.Command{
		Use:   "emit",
		Short: "Emit all KAT JSON files",
		RunE: func(cmd *cobra.Command, _ []string) error {
			outDir, err := cmd.Flags().GetString("out")
			if err != nil {
				return err
			}
			return emitAll(outDir)
		},
	}
	emit.Flags().String("out", "", "output directory for KAT JSON files")
	_ = emit.MarkFlagRequired("out")
	root.AddCommand(emit)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// emitAll runs every KAT emitter into outDir, returning the first error.
func emitAll(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	type emitter struct {
		name string
		fn   func(string) error
	}
	emitters := []emitter{
		{"prng_blake2_xof", emitPRNG},
		{"discrete_gaussian", emitGaussian},
		{"montgomery_ntt", emitMontgomeryNTT},
		{"structs_matrix_wire", emitMatrixWire},
		{"transcript_hash", emitTranscripts},
		{"shamir_share", emitShamir},
		{"sign_verify_e2e", emitSignVerify},
	}
	for _, e := range emitters {
		if err := e.fn(outDir); err != nil {
			return fmt.Errorf("%s: %w", e.name, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s.json\n", e.name)
	}
	return nil
}
