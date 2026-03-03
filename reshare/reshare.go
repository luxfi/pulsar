// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package reshare implements two distinct proactive secret-sharing
// primitives for Pulsar lattice threshold signatures over the ring
// R_q = Z_q[X]/(X^N+1):
//
//  1. Refresh — same-committee zero-polynomial proactive update
//     (Herzberg-Jakobsson-Jarecki-Krawczyk-Yung 1997, "PSS"). The committee
//     of parties is held FIXED; every party samples a random degree-(t-1)
//     polynomial z_i(X) with z_i(0) = 0 and contributes z_i(α_j) to each
//     other party j. Each party updates s'_j = s_j + Σ_i z_i(α_j). The
//     master secret is unchanged because Σ_i z_i(0) = 0. Use case:
//     periodic share-randomization within a stable validator set, to
//     defeat a mobile adversary that compromises < t parties per epoch
//     and accumulates shares across epochs.
//
//  2. Reshare — validator-set resharing. The OLD committee O and NEW
//     committee N are different (potentially disjoint, potentially
//     different threshold). The new committee has no old shares and so
//     cannot apply zero-polynomial deltas. Instead, a qualified subset
//     Q ⊆ O with |Q| ≥ t_old executes a one-shot Shamir-from-Lagrange
//     transformation: each i ∈ Q samples g_i(X) of degree t_new-1 over
//     R_q with g_i(0) = s_i (its OWN old share as the constant term),
//     and privately delivers g_i(β_j) to each new party j ∈ N. Each
//     new party j computes
//
//         s'_j = Σ_{i ∈ Q} λ^Q_i · g_i(β_j)
//
//     where λ^Q_i are the Lagrange coefficients for the quorum Q
//     evaluated at 0. Define G(X) = Σ_{i ∈ Q} λ^Q_i · g_i(X). Then
//     deg(G) = t_new − 1 with overwhelming probability, and
//
//         G(0) = Σ_{i ∈ Q} λ^Q_i · g_i(0) = Σ_{i ∈ Q} λ^Q_i · s_i = s
//
//     by Lagrange interpolation over Q at X=0. The {G(β_j) : j ∈ N}
//     are therefore valid (t_new, |N|)-Shamir shares of the SAME master
//     secret s. Use case: validator-set rotation at Quasar epoch
//     boundaries (`protocol/quasar/epoch.go: ReshareEpoch`).
//
// Both primitives leave the public key b = A·s + e (and its rounded
// form b̃) UNCHANGED. The genesis values (A, b, e) — and Pulsar's
// `bTilde` and Ringtail's `GroupKey` — are persistent for the entire
// group lineage. Only the share distribution changes. This is the
// fundamental property that lets Quasar avoid running a full DKG on
// every validator-set rotation.
//
// # Security model (kernel)
//
// The kernel APIs in this file (Refresh, Reshare) implement the
// arithmetic correctness of the two primitives, against a HONEST-BUT-
// CURIOUS adversary that may statically corrupt up to t-1 parties.
// Every share is in standard (non-NTT, non-Montgomery) form. Shamir is
// linear per Z_q coefficient slot, so the lattice ring structure is
// preserved trivially.
//
// # Verifiable Secret Resharing (VSR) — production deployment
//
// In a permissionless setting the kernel must be embedded in a full
// VSR protocol with the following components, implemented in sibling
// files in this package:
//
//   - commit.go       — Pedersen-style polynomial commitments to f_i
//                       (Refresh) and g_i (Reshare); recipients verify
//                       each share against the committed polynomial.
//   - transcript.go   — Domain-separated transcript binding all
//                       resharing messages, complaints, and the
//                       (chain_id, epoch, group_id, sets, thresholds,
//                       group_pk_hash) tuple.
//   - complaint.go    — Complaint format, signed evidence, complaint
//                       quorum logic, deterministic disqualification of
//                       misbehaving senders.
//   - keyshare.go     — Wraps reshared SkShare values into complete
//                       Ringtail/Pulsar `KeyShare` instances by
//                       regenerating Lambda, Seeds, MACKeys, and
//                       attaching the unchanged GroupKey pointer.
//   - pairwise.go     — Authenticated pairwise KEX (X25519 / ML-KEM
//                       hybrid) → KDF derivation of new Seeds, MACKeys
//                       under domain-separated tags.
//   - activation.go   — Post-reshare activation certificate: the new
//                       committee threshold-signs the resharing
//                       transcript hash under the unchanged GroupKey.
//                       The chain accepts the new epoch only when this
//                       activation cert verifies.
//
// All of the above MUST be wired together at the Quasar consensus
// layer (`protocol/quasar/epoch.go`) — see `quasar_integration.go` for
// the integration sketch.
//
// # References
//
//   - HJKY97. Amir Herzberg, Markus Jakobsson, Stanisław Jarecki, Hugo
//     Krawczyk, Moti Yung. "Proactive secret sharing or: How to cope
//     with perpetual leakage." CRYPTO 1995/1997. (Refresh.)
//
//   - Desmedt-Jajodia 1997. "Redistributing secret shares to new
//     access structures and its applications." (Reshare.)
//
//   - Wong-Wang-Wing 2002. "Verifiable secret redistribution for
//     archive systems." (VSR.)
//
//   - LP-073-pulsar §6 (papers/lp-073-pulsar/sections/06-resharing.tex)
//     — the canonical written specification, including the security
//     proof of public-key invariance and the VSR composition arguments.
package reshare

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// Errors returned by the package.
var (
	ErrInvalidThresholdOld = errors.New("reshare: t_old must be >= 1")
	ErrInvalidThresholdNew = errors.New("reshare: t_new must be >= 1")
	ErrTOldExceedsOldSet   = errors.New("reshare: t_old exceeds size of old committee")
	ErrTNewExceedsNewSet   = errors.New("reshare: t_new exceeds size of new committee")
	ErrEmptyOldShares      = errors.New("reshare: no old shares supplied")
	ErrEmptyNewSet         = errors.New("reshare: empty new committee")
	ErrZeroPartyID         = errors.New("reshare: party IDs must be 1-indexed (no 0)")
	ErrDuplicateNewID      = errors.New("reshare: duplicate ID in new committee")
	ErrShareDimMismatch    = errors.New("reshare: old shares have inconsistent vector dimension")
	ErrTOldShortfall       = errors.New("reshare: fewer than t_old shares supplied; cannot reconstruct s")
)

// Share is a single party's secret share. It is a vector of polynomials in
// R_q in standard (non-NTT, non-Montgomery) form, i.e. each Coeffs[0][k]
// is the k-th coefficient of the share polynomial in [0, q).
//
// Share index conventions match sign.Gen: party i's share evaluated at the
// 1-indexed point partyID = i+1 (so old_shares maps partyID → Share). A
// participant with partyID = 0 is forbidden because Shamir evaluation at
// X = 0 reveals the secret.
type Share = structs.Vector[ring.Poly]

// Reshare runs the proactive secret-resharing protocol described in the
// package doc. Inputs:
//
//   - r          — the canonical R_q ring (must match sign.Gen's r,
//     typically (LogN, Q) = (8, 0x1000000004A01)).
//   - oldShares  — partyID → share, where partyID is the 1-indexed
//     evaluation point. The map MUST contain at least t_old entries.
//   - tOld       — old reconstruction threshold (so any t_old of the
//     entries in oldShares jointly reconstruct s).
//   - newSet     — new committee, a slice of distinct 1-indexed party IDs.
//   - tNew       — new reconstruction threshold (must be ≤ |newSet|).
//   - randSource — randomness source for the fresh polynomial coefficients
//     (nil → crypto/rand.Reader).
//
// Returns the new share map, keyed by new partyID. The output share at
// partyID j satisfies the (t_new, |newSet|)-Shamir relation against the
// SAME master secret s as the input shares, but with fully fresh
// per-coordinate randomness in degrees 1..t_new-1.
//
// Reshare is deterministic given a deterministic randSource, which lets
// the cmd/reshare_oracle/main.go KAT path reproduce results across
// implementations (Go and luxcpp/crypto/pulsar/reshare).
func Reshare(
	r *ring.Ring,
	oldShares map[int]Share,
	tOld int,
	newSet []int,
	tNew int,
	randSource io.Reader,
) (map[int]Share, error) {
	if randSource == nil {
		randSource = rand.Reader
	}
	if tOld < 1 {
		return nil, ErrInvalidThresholdOld
	}
	if tNew < 1 {
		return nil, ErrInvalidThresholdNew
	}
	if len(oldShares) == 0 {
		return nil, ErrEmptyOldShares
	}
	if len(newSet) == 0 {
		return nil, ErrEmptyNewSet
	}
	if tOld > len(oldShares) {
		return nil, ErrTOldShortfall
	}
	if tNew > len(newSet) {
		return nil, ErrTNewExceedsNewSet
	}

	// Validate new committee: 1-indexed, distinct.
	seenNew := make(map[int]bool, len(newSet))
	for _, j := range newSet {
		if j == 0 {
			return nil, ErrZeroPartyID
		}
		if seenNew[j] {
			return nil, ErrDuplicateNewID
		}
		seenNew[j] = true
	}

	// Pick the smallest-ID t_old subset of oldShares as T* (the quorum
	// that will reshare). Any t_old subset works; we pick deterministi-
	// cally so the KAT is well-defined.
	tStar := selectQuorum(oldShares, tOld)

	// Establish vector dimension by inspecting the first share.
	var nVec int
	for _, sh := range oldShares {
		if len(sh) == 0 {
			return nil, ErrShareDimMismatch
		}
		nVec = len(sh)
		break
	}
	for id, sh := range oldShares {
		if len(sh) != nVec {
			return nil, fmt.Errorf("%w: party %d has dim %d, expected %d",
				ErrShareDimMismatch, id, len(sh), nVec)
		}
		if id == 0 {
			return nil, ErrZeroPartyID
		}
	}

	q := r.Modulus()

	// Lagrange coefficients λ_i^{T*} for the quorum, evaluated at X = 0.
	lambda := lagrangeAtZero(tStar, q) // map[int]*big.Int

	// For each i ∈ T*, sample its degree-(t_new-1) polynomial f_i over
	// R_q, with f_i(0) = λ_i · s_i (so Σ_i f_i(0) = Σ_i λ_i · s_i = s).
	// f_i is conceptually a vector of polynomials over R_q (one per
	// secret-vector index), each itself a Z_q-polynomial in X of degree
	// t_new-1; we represent it coefficient-wise as a [polyIdx][coordIdx]
	// matrix of *big.Int coefficient slices.
	//
	// Memory layout: poly[i] = list of (t_new) big.Int slices, each of
	// length r.N(), indexed [degree_in_X][coord_in_R].
	//
	// We then evaluate f_i at every j ∈ newSet and accumulate into
	// new_shares[j].

	N := r.N()
	newShares := make(map[int]Share, len(newSet))
	for _, j := range newSet {
		v := make(Share, nVec)
		for p := 0; p < nVec; p++ {
			v[p] = r.NewPoly()
		}
		newShares[j] = v
	}

	for _, i := range sortedKeys(tStar) {
		// f_i constant terms: λ_i · s_i (per polyIdx, per coord).
		// Higher-degree terms: fresh random in [0, q).
		c0 := scaleShare(r, oldShares[i], lambda[i], q) // []ring.Poly
		fi := make([][][]*big.Int, nVec)                // [polyIdx][degree][coord]
		for p := 0; p < nVec; p++ {
			fi[p] = make([][]*big.Int, tNew)
			// Degree 0 = c0 (the actual share contribution).
			deg0 := make([]*big.Int, N)
			for k := 0; k < N; k++ {
				deg0[k] = new(big.Int).SetUint64(c0[p].Coeffs[0][k])
			}
			fi[p][0] = deg0
			// Degrees 1..t_new-1: fresh uniform random mod q. Drawn
			// from randSource so the KAT can replay deterministically.
			for d := 1; d < tNew; d++ {
				row := make([]*big.Int, N)
				for k := 0; k < N; k++ {
					row[k] = sampleModQ(randSource, q)
				}
				fi[p][d] = row
			}
		}

		// Evaluate f_i at each j ∈ newSet, add into newShares[j].
		for _, j := range newSet {
			xj := big.NewInt(int64(j))
			contrib := evaluateAt(fi, xj, q, nVec, N, tNew) // []ring.Poly
			for p := 0; p < nVec; p++ {
				for k := 0; k < N; k++ {
					sum := new(big.Int).SetUint64(newShares[j][p].Coeffs[0][k])
					sum.Add(sum, new(big.Int).SetUint64(contrib[p].Coeffs[0][k]))
					sum.Mod(sum, q)
					newShares[j][p].Coeffs[0][k] = sum.Uint64()
				}
			}
		}
	}

	return newShares, nil
}

// Refresh runs the HJKY97 same-committee proactive update on a fixed
// committee. The set of party IDs and the threshold are unchanged:
// only the share values are rotated to fresh independent randomness
// while preserving Σ_j λ^T_j · s_j = s for every threshold subset T.
//
// Algorithm (per HJKY97 §3, "zero-polynomial" form):
//
//  1. Each party i samples a random degree-(t-1) polynomial z_i(X)
//     over R_q^{Nvec} with z_i(0) = 0 (i.e. z_i has no constant term;
//     coefficients of degree 1..t-1 are uniformly random).
//  2. Each party i privately delivers z_i(α_j) to every party j in the
//     committee, where α_j is the Shamir evaluation point of party j
//     (here α_j = j, the 1-indexed party ID).
//  3. Each party j updates its share:
//
//         s'_j = s_j + Σ_i z_i(α_j) (mod q)
//
// Correctness. Define Z(X) = Σ_i z_i(X). Z is a degree-(t-1) random
// polynomial over R_q with Z(0) = 0. The new shares are evaluations of
// the polynomial S'(X) = S(X) + Z(X) at the original points, where
// S(X) is the (implicit) original Shamir polynomial. Hence S'(0) =
// S(0) + 0 = s, so the master secret is preserved; and the
// distribution of S' is independent of S (subject only to S'(0) = s)
// because Z's degree-1..t-1 coefficients are uniform and independent
// of S.
//
// Inputs:
//
//   - r          — the canonical R_q ring (must match sign.Gen).
//   - shares     — partyID → share, the current committee's shares.
//                  The map MUST contain every party in the committee
//                  (refresh has no quorum semantics; ALL parties must
//                  participate, since the zero-polynomial deltas must
//                  be computed at every evaluation point).
//   - threshold  — the unchanged reconstruction threshold t.
//   - randSource — randomness source for the fresh polynomial
//                  coefficients (nil → crypto/rand.Reader).
//
// Returns the refreshed share map, keyed by the SAME party IDs as the
// input. The output shares are valid (threshold, |committee|)-Shamir
// shares of the SAME master secret s, with fully fresh per-coordinate
// randomness in degrees 1..t-1.
//
// Refresh is deterministic given a deterministic randSource, which
// lets KAT replay reproduce results across implementations.
//
// Production deployment. Refresh's kernel here is the arithmetic core.
// The full VSR composition (commitments to z_i, complaints, etc.)
// applies to Refresh exactly as it applies to Reshare — see commit.go
// and complaint.go in this package. The activation certificate
// (activation.go) MUST also be produced after a Refresh, even though
// the validator set is unchanged: it establishes that the new shares
// are operational and the old shares may be erased.
func Refresh(
	r *ring.Ring,
	shares map[int]Share,
	threshold int,
	randSource io.Reader,
) (map[int]Share, error) {
	if randSource == nil {
		randSource = rand.Reader
	}
	if threshold < 1 {
		return nil, ErrInvalidThresholdOld
	}
	if len(shares) == 0 {
		return nil, ErrEmptyOldShares
	}
	if threshold > len(shares) {
		return nil, ErrTOldShortfall
	}

	// Validate committee: 1-indexed, distinct (already enforced by map
	// key uniqueness — but reject the zero key, which would make
	// z_i(α_j) collapse to z_i(0) = 0 and reveal s_j to a passive
	// observer who saw the deltas).
	var nVec int
	for id, sh := range shares {
		if id == 0 {
			return nil, ErrZeroPartyID
		}
		if len(sh) == 0 {
			return nil, ErrShareDimMismatch
		}
		if nVec == 0 {
			nVec = len(sh)
		} else if len(sh) != nVec {
			return nil, fmt.Errorf("%w: party %d has dim %d, expected %d",
				ErrShareDimMismatch, id, len(sh), nVec)
		}
	}

	q := r.Modulus()
	N := r.N()
	parties := sortedMapKeys(shares)

	// Initialize new shares as a copy of the old shares; we will add
	// Σ_i z_i(j) into each in place.
	out := make(map[int]Share, len(shares))
	for _, j := range parties {
		v := make(Share, nVec)
		for p := 0; p < nVec; p++ {
			v[p] = r.NewPoly()
			copy(v[p].Coeffs[0], shares[j][p].Coeffs[0])
		}
		out[j] = v
	}

	// Degenerate case: threshold = 1 means every share IS the secret,
	// so any "refresh" that preserves s must be the identity. A
	// degree-0 zero-polynomial is identically 0; nothing to add. Bail
	// after the copy.
	if threshold == 1 {
		return out, nil
	}

	// For each party i (in canonical order), sample the zero-poly
	// z_i (degree-(t-1), constant term forced to 0), evaluate at every
	// α_j, and add the contribution into out[j].
	//
	// NOTE: in a distributed deployment, party i would compute z_i
	// LOCALLY and ship z_i(α_j) to party j over a private channel.
	// In this kernel we simulate that by drawing all z_i in one place
	// from the supplied randSource — the byte-stream order is i = 1,
	// 2, ..., n, and within i we draw the (t-1) high-degree coefficient
	// vectors c_{i,1} ... c_{i,t-1} in increasing degree order, and
	// within each c_{i,d} we draw the nVec polynomials in 0..nVec-1
	// order, and within each polynomial we draw the N coefficients in
	// 0..N-1 order. This iteration order is locked by the Go reference
	// and the C++ port at luxcpp/crypto/pulsar/reshare/.
	for _, i := range parties {
		_ = i
		// z_i has degree (t-1) and constant term 0. We store
		// coefficients of degree 1..t-1 explicitly; degree 0 is implicit
		// zero and contributes nothing.
		// zHigh[degree-1][polyIdx][coordIdx] = z_i's degree-d coeff,
		// for degree ∈ 1..t-1.
		zHigh := make([][][]*big.Int, threshold-1)
		for d := 0; d < threshold-1; d++ {
			zHigh[d] = make([][]*big.Int, nVec)
			for p := 0; p < nVec; p++ {
				row := make([]*big.Int, N)
				for k := 0; k < N; k++ {
					row[k] = sampleModQ(randSource, q)
				}
				zHigh[d][p] = row
			}
		}

		// Evaluate z_i at each α_j ∈ committee. z_i(x) = Σ_{d=1..t-1}
		// zHigh[d-1] · x^d (no constant term). Equivalent to Horner
		// over (t-1) high-degree coefficients with an extra final
		// multiply by x:
		//
		//   acc = zHigh[t-2]; for d = t-3 downto 0: acc = acc * x +
		//   zHigh[d]; acc = acc * x.
		for _, j := range parties {
			xj := big.NewInt(int64(j))
			for p := 0; p < nVec; p++ {
				for k := 0; k < N; k++ {
					acc := new(big.Int).Set(zHigh[threshold-2][p][k])
					for d := threshold - 3; d >= 0; d-- {
						acc.Mul(acc, xj)
						acc.Add(acc, zHigh[d][p][k])
						acc.Mod(acc, q)
					}
					acc.Mul(acc, xj) // final multiplication for the implicit constant term 0
					acc.Mod(acc, q)
					sum := new(big.Int).SetUint64(out[j][p].Coeffs[0][k])
					sum.Add(sum, acc)
					sum.Mod(sum, q)
					out[j][p].Coeffs[0][k] = sum.Uint64()
				}
			}
		}
	}

	return out, nil
}

// selectQuorum picks a deterministic t-element subset of oldShares (the
// t entries with the smallest party IDs) and returns it. This makes
// Reshare's behaviour reproducible across implementations even when the
// caller hands in more than t_old shares.
func selectQuorum(oldShares map[int]Share, t int) map[int]Share {
	keys := sortedMapKeys(oldShares)
	out := make(map[int]Share, t)
	for i := 0; i < t; i++ {
		out[keys[i]] = oldShares[keys[i]]
	}
	return out
}

// lagrangeAtZero returns λ_i^{T} ∈ Z_q for each i ∈ T, the standard
// Lagrange basis coefficient at X=0:
//
//	λ_i = Π_{j ∈ T, j ≠ i} (-x_j) / (x_i - x_j) mod q
//
// where x_i = i (the party ID, 1-indexed evaluation point).
func lagrangeAtZero(quorum map[int]Share, q *big.Int) map[int]*big.Int {
	ids := sortedMapKeys(quorum)
	out := make(map[int]*big.Int, len(ids))
	for _, i := range ids {
		xi := big.NewInt(int64(i))
		num := big.NewInt(1)
		den := big.NewInt(1)
		for _, j := range ids {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(j))
			num.Mul(num, new(big.Int).Neg(xj))
			num.Mod(num, q)
			den.Mul(den, new(big.Int).Sub(xi, xj))
			den.Mod(den, q)
		}
		denInv := new(big.Int).ModInverse(den, q)
		coeff := new(big.Int).Mul(num, denInv)
		coeff.Mod(coeff, q)
		out[i] = coeff
	}
	return out
}

// scaleShare returns λ · share as a []ring.Poly in standard form. The
// input share's Coeffs[0][k] are interpreted as Z_q coefficients (level
// 0 only — Shamir results live entirely on level 0).
func scaleShare(r *ring.Ring, share Share, lambda *big.Int, q *big.Int) []ring.Poly {
	nVec := len(share)
	N := r.N()
	out := make([]ring.Poly, nVec)
	for p := 0; p < nVec; p++ {
		out[p] = r.NewPoly()
		for k := 0; k < N; k++ {
			v := new(big.Int).SetUint64(share[p].Coeffs[0][k])
			v.Mul(v, lambda)
			v.Mod(v, q)
			out[p].Coeffs[0][k] = v.Uint64()
		}
	}
	return out
}

// evaluateAt returns f_i(x) ∈ R_q^{nVec}: for each polyIdx and each
// coordinate, evaluate the degree-(tNew-1) polynomial f_i[polyIdx][·][k]
// at X = x using Horner's method, mod q.
func evaluateAt(fi [][][]*big.Int, x *big.Int, q *big.Int, nVec, N, tNew int) []ring.Poly {
	out := make([]ring.Poly, nVec)
	for p := 0; p < nVec; p++ {
		// Allocate a poly with the same shape as the surrounding ring.
		// We construct it standalone here (no ring r in scope); the
		// caller will copy into a r-allocated poly. To keep the API
		// simple, we re-use ring.Poly{Coeffs: [][]uint64{coeffs}}.
		coeffs := make([]uint64, N)
		for k := 0; k < N; k++ {
			// Horner: acc = ((a_{tNew-1} * x + a_{tNew-2}) * x + ...) * x + a_0.
			acc := new(big.Int).Set(fi[p][tNew-1][k])
			for d := tNew - 2; d >= 0; d-- {
				acc.Mul(acc, x)
				acc.Add(acc, fi[p][d][k])
				acc.Mod(acc, q)
			}
			if acc.Sign() < 0 {
				acc.Add(acc, q)
			}
			coeffs[k] = acc.Uint64()
		}
		out[p] = ring.Poly{Coeffs: [][]uint64{coeffs}}
	}
	return out
}

// sampleModQ returns a uniform sample in [0, q). It uses the standard
// rejection-sampling technique: draw len(q.Bytes()) bytes; reject if the
// resulting integer is ≥ q · ⌊2^{8·len}/q⌋. (For q = 0x1000000004A01,
// the rejection probability per draw is < 2^-49, so this terminates
// in expected ~1 draw.)
func sampleModQ(rs io.Reader, q *big.Int) *big.Int {
	qByteLen := len(q.Bytes())
	buf := make([]byte, qByteLen)
	for {
		if _, err := io.ReadFull(rs, buf); err != nil {
			panic(fmt.Errorf("reshare: rng read failed: %w", err))
		}
		v := new(big.Int).SetBytes(buf)
		// Convert top byte's overflow bits into rejection: keep the value
		// only if it is < q. Most q values used here are tightly packed
		// (q occupies almost all 49 bits of qByteLen=7), so the loop
		// rarely iterates.
		if v.Cmp(q) < 0 {
			return v
		}
	}
}

// Verify is a debugging helper: it Lagrange-interpolates the input
// shares at X=0 (using the smallest-ID t-subset) and returns the
// reconstructed master secret as []ring.Poly in standard form.
//
// IMPORTANT: This recovers s, so it MUST NOT be used in production —
// only in tests and KAT verification. Calling it gives the caller the
// secret.
func Verify(r *ring.Ring, shares map[int]Share, t int) ([]ring.Poly, error) {
	if t > len(shares) {
		return nil, ErrTOldShortfall
	}
	q := r.Modulus()
	N := r.N()

	// Pick the smallest-ID t shares.
	quorum := selectQuorum(shares, t)
	lambda := lagrangeAtZero(quorum, q)

	var nVec int
	for _, sh := range quorum {
		nVec = len(sh)
		break
	}

	out := make([]ring.Poly, nVec)
	for p := 0; p < nVec; p++ {
		out[p] = r.NewPoly()
		for k := 0; k < N; k++ {
			acc := big.NewInt(0)
			for _, i := range sortedKeys(quorum) {
				yi := new(big.Int).SetUint64(quorum[i][p].Coeffs[0][k])
				term := new(big.Int).Mul(lambda[i], yi)
				acc.Add(acc, term)
			}
			acc.Mod(acc, q)
			out[p].Coeffs[0][k] = acc.Uint64()
		}
	}
	return out, nil
}

// sortedKeys returns the keys of m sorted ascending (canonical order
// for protocol determinism).
func sortedKeys(m map[int]Share) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Hand-rolled insertion sort; len(keys) is always small (≤ committee
	// size, typically ≤ 21 for Quasar).
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

// sortedMapKeys is sortedKeys but typed for any map[int]V.
func sortedMapKeys[V any](m map[int]V) []int {
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
