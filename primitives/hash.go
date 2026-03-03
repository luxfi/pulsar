package primitives

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
	"github.com/zeebo/blake3"
)

const keySize = 32

// PRNGKey generates a key for PRNG using the secret key share.
//
// DEPRECATED: kept only for backward-byte-compat with prior KAT runs and
// callers outside the Sign protocol. The Round-1 PRNG seed MUST mix sid
// (and ideally μ) to prevent R/E reuse across signatures of the same
// party — see PRNGKeyForRound below and LP-073 §5.8 (paper amended
// 2026-05-03 in coordination with the C++ port at luxcpp/crypto).
func PRNGKey(skShare structs.Vector[ring.Poly]) []byte {
	hasher := blake3.New()
	buf := new(bytes.Buffer)
	if _, err := skShare.WriteTo(buf); err != nil {
		log.Fatalf("Error writing skShare: %v\n", err)
	}
	if _, err := hasher.Write(buf.Bytes()); err != nil {
		log.Fatalf("Error writing to hasher: %v\n", err)
	}

	skHash := hasher.Sum(nil)
	return skHash[:keySize]
}

// PRNGKeyForRound generates a per-round PRNG seed by domain-separating
// the secret-share material with the session id. CRIT-1 fix
// (red audit, 2026-05-03): without sid mixing, R/E/D are byte-identical
// across every Sign call of the same Setup — multi-Sign leaks R via
// (z_sum − Σ s_i·λ_i·c)·u^{-1} = R.
//
// Layout: BLAKE3(skShare.WriteTo bytes || "RingtailRoundV2" || be64(sid)).
// Domain tag distinguishes from any other future per-share keying.
func PRNGKeyForRound(skShare structs.Vector[ring.Poly], sid int64) []byte {
	hasher := blake3.New()
	buf := new(bytes.Buffer)
	if _, err := skShare.WriteTo(buf); err != nil {
		log.Fatalf("Error writing skShare: %v\n", err)
	}
	if _, err := hasher.Write(buf.Bytes()); err != nil {
		log.Fatalf("Error writing to hasher (sk): %v\n", err)
	}
	const tag = "RingtailRoundV2"
	if _, err := hasher.Write([]byte(tag)); err != nil {
		log.Fatalf("Error writing tag: %v\n", err)
	}
	if err := binary.Write(hasher, binary.BigEndian, sid); err != nil {
		log.Fatalf("Error writing sid: %v\n", err)
	}
	skHash := hasher.Sum(nil)
	return skHash[:keySize]
}

// GenerateMAC generates a MAC for a given TildeD matrix and mask
func GenerateMAC(TildeD structs.Matrix[ring.Poly], MACKey []byte, partyID int, sid int, T []int, otherParty int, verify bool) []byte {
	hasher := blake3.New()
	buf := new(bytes.Buffer)

	if verify {
		if err := binary.Write(buf, binary.BigEndian, int64(otherParty)); err != nil {
			log.Fatalf("Error writing otherParty: %v\n", err)
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, int64(partyID)); err != nil {
			log.Fatalf("Error writing partyID: %v\n", err)
		}
	}

	if err := binary.Write(buf, binary.BigEndian, MACKey); err != nil {
		log.Fatalf("Error writing MACKey: %v\n", err)
	}
	if _, err := TildeD.WriteTo(buf); err != nil {
		log.Fatalf("Error writing TildeD: %v\n", err)
	}
	if err := binary.Write(buf, binary.BigEndian, int64(sid)); err != nil {
		log.Fatalf("Error writing sid: %v\n", err)
	}
	// Write T array length and elements
	if err := binary.Write(buf, binary.BigEndian, int32(len(T))); err != nil {
		log.Fatalf("Error writing T length: %v\n", err)
	}
	for _, t := range T {
		if err := binary.Write(buf, binary.BigEndian, int32(t)); err != nil {
			log.Fatalf("Error writing T element: %v\n", err)
		}
	}

	if _, err := hasher.Write(buf.Bytes()); err != nil {
		log.Fatalf("Error writing to hasher: %v\n", err)
	}
	MAC := hasher.Sum(nil)
	return MAC[:keySize]
}

// Hashes parameters to a Gaussian distribution
func GaussianHash(r *ring.Ring, hash []byte, mu string, sigmaU float64, boundU float64, length int) structs.Vector[ring.Poly] {
	hasher := blake3.New()
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, hash); err != nil {
		log.Fatalf("Error writing hash: %v\n", err)
	}
	if _, err := buf.WriteString(mu); err != nil {
		log.Fatalf("Error writing mu: %v\n", err)
	}

	if _, err := hasher.Write(buf.Bytes()); err != nil {
		log.Fatalf("Error writing to hasher: %v\n", err)
	}
	hashOutput := hasher.Sum(nil)

	prng, _ := sampling.NewKeyedPRNG(hashOutput[:keySize])
	gaussianParams := ring.DiscreteGaussian{Sigma: sigmaU, Bound: boundU}
	hashGaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)

	return utils.SamplePolyVector(r, length, hashGaussianSampler, true, true)
}

// PRF generates pseudorandom ring elements
func PRF(r *ring.Ring, sd_ij []byte, PRFKey []byte, mu string, hash []byte, n int) structs.Vector[ring.Poly] {
	hasher := blake3.New()
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, PRFKey); err != nil {
		log.Fatalf("Error writing PRFKey: %v\n", err)
	}
	if err := binary.Write(buf, binary.BigEndian, sd_ij); err != nil {
		log.Fatalf("Error writing sd_ij: %v\n", err)
	}
	if err := binary.Write(buf, binary.BigEndian, hash); err != nil {
		log.Fatalf("Error writing hash: %v\n", err)
	}
	if _, err := buf.WriteString(mu); err != nil {
		log.Fatalf("Error writing mu: %v\n", err)
	}

	if _, err := hasher.Write(buf.Bytes()); err != nil {
		log.Fatalf("Error writing to hasher: %v\n", err)
	}
	hashOutput := hasher.Sum(nil)

	prng, _ := sampling.NewKeyedPRNG(hashOutput[:keySize])
	PRFUniformSampler := ring.NewUniformSampler(prng, r)
	mask := utils.SamplePolyVector(r, n, PRFUniformSampler, true, true)
	return mask
}

// Hashes precomputable values
func Hash(A structs.Matrix[ring.Poly], b structs.Vector[ring.Poly], D map[int]structs.Matrix[ring.Poly], sid int, T []int) []byte {
	hasher := blake3.New()
	buf := new(bytes.Buffer)

	if _, err := A.WriteTo(buf); err != nil {
		log.Fatalf("Error writing matrix A: %v\n", err)
	}

	if _, err := b.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector b: %v\n", err)
	}

	if err := binary.Write(buf, binary.BigEndian, int64(sid)); err != nil {
		log.Fatalf("Error writing sid: %v\n", err)
	}
	// Write T array length and elements
	if err := binary.Write(buf, binary.BigEndian, int32(len(T))); err != nil {
		log.Fatalf("Error writing T length: %v\n", err)
	}
	for _, t := range T {
		if err := binary.Write(buf, binary.BigEndian, int32(t)); err != nil {
			log.Fatalf("Error writing T element: %v\n", err)
		}
	}

	for i := 0; i < len(D); i++ {
		if _, err := D[i].WriteTo(buf); err != nil {
			log.Fatalf("Error writing matrix D_i: %v\n", err)
		}
	}

	if _, err := hasher.Write(buf.Bytes()); err != nil {
		log.Fatalf("Error writing to hasher: %v\n", err)
	}
	hashOutput := hasher.Sum(nil)
	return hashOutput[:keySize]
}

// Hashes to low norm ring elements
func LowNormHash(r *ring.Ring, A structs.Matrix[ring.Poly], b structs.Vector[ring.Poly], h structs.Vector[ring.Poly], mu string, kappa int) ring.Poly {
	hasher := blake3.New()
	buf := new(bytes.Buffer)

	if _, err := A.WriteTo(buf); err != nil {
		log.Fatalf("Error writing matrix A: %v\n", err)
	}

	if _, err := b.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector b: %v\n", err)
	}

	if _, err := h.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector h: %v\n", err)
	}

	if err := binary.Write(buf, binary.BigEndian, []byte(mu)); err != nil {
		log.Fatalf("Error writing mu: %v\n", err)
	}

	if _, err := hasher.Write(buf.Bytes()); err != nil {
		log.Fatalf("Error writing to hasher: %v\n", err)
	}
	hashOutput := hasher.Sum(nil)

	prng, _ := sampling.NewKeyedPRNG(hashOutput[:keySize])
	ternaryParams := ring.Ternary{H: kappa}
	ternarySampler, err := ring.NewTernarySampler(prng, r, ternaryParams, false)
	if err != nil {
		log.Fatalf("Error creating ternary sampler: %v", err)
	}
	c := ternarySampler.ReadNew()
	r.NTT(c, c)
	r.MForm(c, c)

	return c
}

// GenerateRandomSeed generates a random seed of length ell
func GenerateRandomSeed() []byte {
	return utils.GetRandomBytes(keySize)
}
