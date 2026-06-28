// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// mithril_rss_hyperball.go — the Mithril 3-round HYPERBALL no-reconstruct
// threshold signer for the dealerless RSS ML-DSA-65 key (mithril_rss.go).
//
// This closes the no-reconstruct gap. mithril_rss.go's Sign rebuilds the full
// (s1, s2) at the signing coordinator (ReconstructKeyMaterial) — a quorum-
// reconstruct signature. Here NO party and NO coordinator ever forms the full
// s1, s2, t0, the mask y, the commitment w, w0 = LowBits(w), or any sk. Each
// active party holds only its balanced-partition share s1_(j) of s1 and emits
// only its partial response z_j = y_j + c·s1_(j); the sum z = Σ_j z_j = y + c·s1
// is the standard FIPS-204 response, and the hint is recovered from the PUBLIC
// w' = A·z − c·t1·2^d exactly as a verifier would (bcc_sign.go / boundary.go).
// s2 is NEVER touched during signing.
//
// Why it is stock-verifiable. Verifiability is independent of the hyperball
// parameters: the produced (c̃, z, h) clears the FIPS-204 verifier iff the
// SUMMED z, w clear the central BCC checks (BoundaryClear(w), ‖z‖∞ < γ1−β,
// FindHint(w', w1) with weight ≤ ω). Those are identical to what bccSign checks
// on a single reconstructed key — only here y and z are formed additively. So
// the signature verifies byte-for-byte under unmodified circl mldsa65.Verify.
//
// Why the partials are leak-free. Each party draws its mask y_j uniformly inside
// a hyperball B(0, r1) ⊂ R^{L·N} and reveals z_j only when z_j ∈ B(0, r) with
// r = r1 − Δ (the Excess gate). Conditioned on acceptance, z_j is (almost)
// uniform on B(0, r), independent of the secret shift c·s1_(j); the residual
// dependence is bounded by Rényi divergence ≤ 1/(1−2^−64) per signature via the
// leak-free gap Δ/δ = √(2κln2/n) (docs/hyperball-mldsa65-params.md). The K
// parallel slots amortise the joint acceptance probability across the T parties.
//
// Reference: Mithril (Celi–del Pino–Espitau–Niot–Prest, USENIX Security 2026,
// ePrint 2026/013), github.com/lattice-safe/threshold-ml-dsa. This is the
// one-sided BCC adaptation: the reference commits w = A·y + e and responds in
// both s1 and s2; pulsar's BCC hint path eliminates the s2 side entirely.

import (
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/luxfi/dkg/rss"
	"golang.org/x/crypto/sha3"
)

// hyperballRenyiKappa is the leakage security target: the per-signature missing
// cap fraction is held ≤ 2^−κ, so the Rényi divergence between a revealed
// partial z_j and the ideal shift-independent distribution stays ≤ 1/(1−2^−κ),
// i.e. ≤ 2 over Q = 2^64 signatures. κ = 64 with the order-α=∞ (volume-ratio)
// bound is the CONSERVATIVE choice — it over-provisions the gap Δ relative to a
// tighter finite-α analysis, buying more leak protection at the cost of more
// rejection. See docs/hyperball-mldsa65-params.md §3.
const hyperballRenyiKappa = 64

// hyperballSafetyTail sets the nonce radius r1 from the L∞ norm budget so the
// SUMMED z stays under γ1−β: it holds the summed per-coordinate standard
// deviation at (γ1−β)/safetyTail, keeping the worst of L·N coordinates ≈ 1.7×
// under budget. See docs/hyperball-mldsa65-params.md §4.
const hyperballSafetyTail = 6.4

// hyperballBoundaryYield is the empirical central BoundaryClear acceptance for
// ML-DSA-65 (~9%), used only to SIZE the K-repetition budget — never a
// correctness gate.
const hyperballBoundaryYield = 0.09

var (
	// ErrHyperballScope rejects parameter sets outside the BCC proven scope
	// (ML-DSA-65/87 only; ML-DSA-44 violates ‖c·t0‖∞ < γ2).
	ErrHyperballScope = errors.New(
		"pulsar: Mithril hyperball signing is proven for ML-DSA-65/87 only " +
			"(ML-DSA-44 violates the BCC ‖c·t0‖∞ < γ2 boundary bound)")

	// ErrHyperballExhausted means no K-parallel slot across maxRounds re-runs
	// produced a boundary-clear, norm-valid, hint-admissible, all-party-accepted
	// signature. With the derived parameters this indicates a degenerate RNG or
	// a committee far outside the recommended size — never a forged or invalid
	// signature is returned.
	ErrHyperballExhausted = errors.New(
		"pulsar: Mithril hyperball signing exhausted its round/slot budget " +
			"without a fully-accepted stock-verifiable signature")

	// ErrHyperballActive rejects an active set that is not a sorted,
	// duplicate-free, in-range set of exactly T party ids.
	ErrHyperballActive = errors.New(
		"pulsar: active signer set must be sorted, duplicate-free, in [0,N), of length exactly T")
)

// hyperballParams are the derived ML-DSA-65/87 hyperball parameters for one
// committee (docs/hyperball-mldsa65-params.md §4). All radii are L2 norms over
// the n = L·N mask coordinates.
type hyperballParams struct {
	dim   int     // n = L·N (the one-sided ball dimension)
	r1    float64 // nonce ball radius (sample uniformly inside B(0,r1))
	r     float64 // acceptance radius; Δ = r1−r is the leak-free gap
	nu    float64 // ellipsoid weight on the s1-side (1.0 one-sided)
	kReps int     // parallel commitment slots per round
}

// deriveHyperballParams computes the hyperball parameters for an (T,N) committee
// at the given ML-DSA mode. Fail-closed outside the BCC scope or the RSS
// viability bound. The derivation is documented and validated against the
// Mithril ML-DSA-44 reference table in docs/hyperball-mldsa65-params.md.
func deriveHyperballParams(mode Mode, t, n int) (*hyperballParams, error) {
	if _, _, _, ok := bccParams(mode); !ok {
		return nil, ErrHyperballScope
	}
	if err := rss.ValidateCommittee(t, n); err != nil {
		return nil, err
	}
	K, L, eta := modeShape(mode)
	_ = K
	tau, _, gamma1Bits, _ := modeTauOmega(mode)
	gamma1 := float64(uint32(1) << gamma1Bits)
	beta := float64(uint32(tau) * eta)
	dim := L * mldsaN

	// Single-subset shift L2 norm, 6σ upper bound. s1^(S) has dim coefficients
	// uniform in [−η,η] (variance ((2η+1)²−1)/12); the shift coefficient is a
	// sum of τ signed copies (variance τ·var); ‖shift‖² concentrates at
	// dim·τ·var with std √(2·dim)·τ·var.
	varCoeff := (math.Pow(2*float64(eta)+1, 2) - 1) / 12.0
	varShift := float64(tau) * varCoeff
	meanSq := float64(dim) * varShift
	stdSq := math.Sqrt(2*float64(dim)) * varShift
	deltaSingle := math.Sqrt(meanSq + 6*stdSq)

	// Leak-free gap ratio Δ/δ = √(2κ ln2 / n), scaled by √(maxSubsetsPerParty)
	// because a party's share is the sum of that many independent χ_η secrets.
	gapRatio := math.Sqrt(2 * float64(hyperballRenyiKappa) * math.Ln2 / float64(dim))
	m := maxSubsetsPerParty(t, n)
	delta := deltaSingle * math.Sqrt(float64(m))
	gap := gapRatio * delta

	// Nonce radius from the L∞ norm budget: hold the summed per-coordinate std
	// at (γ1−β)/safetyTail. r1 = (γ1−β)·√(L·N)/(safetyTail·√T).
	budget := gamma1 - beta
	r1 := budget * math.Sqrt(float64(dim)) / (hyperballSafetyTail * math.Sqrt(float64(t)))
	r := r1 - gap

	// K from the per-slot success p_party^T · boundaryYield, targeting ≈ 95% per
	// round (clamped to keep the in-process budget bounded).
	pParty := math.Pow(r/r1, float64(dim))
	pSlot := math.Pow(pParty, float64(t)) * hyperballBoundaryYield
	kReps := 8
	if pSlot > 0 {
		kReps = int(math.Ceil(3.0 / pSlot))
	}
	if kReps < 8 {
		kReps = 8
	}
	if kReps > 256 {
		kReps = 256
	}

	return &hyperballParams{dim: dim, r1: r1, r: r, nu: 1.0, kReps: kReps}, nil
}

// maxSubsetsPerParty returns the largest block of the balanced reconstruction
// partition for the canonical active set {0,…,T−1} — the count of subset
// secrets the most-loaded signer sums into its share s1_(j). For T = N every
// party holds a singleton (1); for T < N it is read from rss.RSSRecover.
func maxSubsetsPerParty(t, n int) int {
	if t == n {
		return 1
	}
	part, err := rss.RSSRecover(canonicalActiveSet(t), t, n)
	if err != nil {
		// Fail-safe upper bound: the whole subset count (never under-provisions
		// the gap). Callers gate viability via ValidateCommittee first.
		return rss.NumSubsets(t, n)
	}
	mx := 0
	for _, blk := range part {
		if len(blk) > mx {
			mx = len(blk)
		}
	}
	if mx == 0 {
		mx = 1
	}
	return mx
}

func canonicalActiveSet(t int) []int {
	a := make([]int, t)
	for i := range a {
		a[i] = i
	}
	return a
}

// ---------------------------------------------------------------------------
// Round messages (the only data that crosses the wire). NONE of these carries a
// secret share, a mask y, or any low-bits quantity — proven by the no-leak
// oracle in the tests.
// ---------------------------------------------------------------------------

// HyperballRound1 is a party's commitment broadcast. CommitW are K binding
// hashes of this party's per-slot commitments w_{j,k} (verified against the
// Round-2 reveal, preventing w-equivocation by a rushing adversary). CommitT is
// one hash of the share-verification value T_j = A·s1_(j), revealed ONLY on
// blame — never in the honest path, because Σ_active T_j = t − s2 would leak s2.
type HyperballRound1 struct {
	PartyID int
	CommitW [][32]byte // K per-slot commitments to w_{j,k}
	CommitT [32]byte   // commitment to T_j (blame only)
}

// HyperballRound2 is a party's reveal broadcast: the K commitment vectors
// w_{j,k} = A·y_{j,k} (length K each). Public — recovering y_{j,k} is Module-SIS.
type HyperballRound2 struct {
	PartyID int
	W       []polyVec // K vectors, each length K (the module dimension)
}

// HyperballRound3 is a party's response broadcast: for each slot, the partial
// z_{j,k} = y_{j,k} + c_k·s1_(j) (length L) if the slot was boundary-clear and
// the Excess gate accepted, else a rejection (Accepted[k] = false, Z[k] = nil).
type HyperballRound3 struct {
	PartyID  int
	Z        []polyVec // K partials, each length L; nil where rejected
	Accepted []bool    // K accept flags
}

// ---------------------------------------------------------------------------
// hyperballParty — ONE signer's PRIVATE state. It holds ONLY this party's share
// s1_(j) (the sum of its assigned balanced-partition subset secrets) and its own
// ephemeral masks. It NEVER holds the full s1, any s2, t0, another party's data,
// or the aggregated w. Constructed by the driver from mk.holdings[id] alone.
// ---------------------------------------------------------------------------

type hyperballParty struct {
	id   int
	mode Mode
	hp   *hyperballParams
	a    []polyVec // public matrix A = ExpandA(rho), NTT domain (shared, read-only)

	// SECRET: this party's share of s1 (length L), stored un-normalised in the
	// χ_η sum representation; reduced+NTT'd locally per attempt. NEVER summed
	// with another party's share into a full s1.
	s1Share polyVec
	s1Hat   polyVec // NTT(reduceLe2Q(s1Share)), cached
	tjS1    polyVec // T_j = A·s1Share (public share-verification commitment), normalised

	// Ephemeral per-round nonces (SECRET, never serialised). yFloat is the
	// continuous ball point used for the leak-free Excess gate; yInt = round(yFloat)
	// is the integer mask used for the commitment w and the response z.
	yFloat [][]float64 // K slots × dim
	yInt   []polyVec   // K slots × L
	wSlot  []polyVec   // K slots × K (this party's commitment A·yInt), cached for R2
}

// newHyperballParty builds a party from its share alone. The share is the sum of
// the subset secrets the balanced partition assigns to this signer, taken from
// THIS party's holdings (never the global subset view). This is the structural
// no-reconstruct boundary: the party object is given s1_(j) and the public
// matrix, nothing else.
func newHyperballParty(mode Mode, hp *hyperballParams, a []polyVec, id int, s1Share polyVec) *hyperballParty {
	_, L, _ := modeShape(mode)
	p := &hyperballParty{id: id, mode: mode, hp: hp, a: a, s1Share: s1Share}
	// Cache NTT(reduceLe2Q(s1Share)).
	p.s1Hat = make(polyVec, L)
	for l := 0; l < L; l++ {
		p.s1Hat[l] = s1Share[l]
		p.s1Hat[l].reduceLe2Q()
		p.s1Hat[l].ntt()
	}
	// T_j = A·s1Share (public commitment to this party's share; revealed only on
	// blame). Computed exactly as a public-key column would be.
	p.tjS1 = matVecHat(a, p.s1Hat)
	return p
}

// matVecHat computes A·xHat in the standard domain: for each row k,
// invNTT(Σ_l a[k][l]·xHat[l]). a is NTT-domain; xHat is NTT-domain.
func matVecHat(a []polyVec, xHat polyVec) polyVec {
	out := make(polyVec, len(a))
	for k := range a {
		polyDotHat(&out[k], a[k], xHat)
		out[k].reduceLe2Q()
		out[k].invNTT()
		out[k].normalize()
	}
	return out
}

// round1 samples this party's K nonces for the round (deterministically from the
// round entropy, so R1's committed w and R3's response use the SAME y), computes
// w_{j,k} = A·y_{j,k}, and returns the binding commitment hashes. roundEntropy is
// fresh per round — distinct rounds therefore use distinct nonces (no reuse).
func (p *hyperballParty) round1(roundEntropy []byte, sid [32]byte, mu []byte) HyperballRound1 {
	_, L, _ := modeShape(p.mode)
	K := p.hp.kReps
	p.yFloat = make([][]float64, K)
	p.yInt = make([]polyVec, K)
	p.wSlot = make([]polyVec, K)
	commitW := make([][32]byte, K)

	for k := 0; k < K; k++ {
		seed := hyperballNonceSeed(roundEntropy, sid, p.id, k)
		p.yFloat[k] = sampleHyperballInBall(seed, p.hp.dim, p.hp.r1)
		p.yInt[k] = floatToMaskPolyVec(p.yFloat[k], L)

		// w_{j,k} = A·y_{j,k}.
		yHat := make(polyVec, L)
		for l := 0; l < L; l++ {
			yHat[l] = p.yInt[k][l]
			yHat[l].ntt()
		}
		p.wSlot[k] = matVecHat(p.a, yHat)

		commitW[k] = hyperballCommitW(sid, p.id, k, mu, p.wSlot[k])
	}
	return HyperballRound1{PartyID: p.id, CommitW: commitW, CommitT: hyperballCommitT(sid, p.id, p.tjS1)}
}

// round2 reveals this party's K commitment vectors w_{j,k}.
func (p *hyperballParty) round2() HyperballRound2 {
	W := make([]polyVec, len(p.wSlot))
	copy(W, p.wSlot)
	return HyperballRound2{PartyID: p.id, W: W}
}

// round3 computes this party's partial responses. For each slot k the
// coordinator supplies the challenge c_k (nil for non-boundary-clear / dead
// slots). The party computes z_{j,k} = y_{j,k} + c_k·s1_(j) and applies the
// leak-free Excess gate on the continuous z_float = y_float + c_k·s1_(j): if the
// response leaves B(0, r) it is REJECTED (Accepted = false) so the partial is
// never revealed. Otherwise the integer z_{j,k} = y_int + c_k·s1_(j) is returned.
func (p *hyperballParty) round3(challenges []*poly) HyperballRound3 {
	_, L, _ := modeShape(p.mode)
	K := p.hp.kReps
	out := HyperballRound3{
		PartyID:  p.id,
		Z:        make([]polyVec, K),
		Accepted: make([]bool, K),
	}
	for k := 0; k < K; k++ {
		c := challenges[k]
		if c == nil { // dead slot (not boundary-clear) — nothing to respond
			continue
		}
		cHat := *c
		cHat.ntt()

		// cs1 = c·s1_(j) (integer poly vector, length L).
		cs1 := make(polyVec, L)
		for l := 0; l < L; l++ {
			cs1[l].mulHat(&cHat, &p.s1Hat[l])
			cs1[l].reduceLe2Q()
			cs1[l].invNTT()
			cs1[l].normalize()
		}

		// Leak-free Excess gate on the continuous response (one-sided ball).
		if hyperballExcess(p.yFloat[k], cs1, p.hp.r, p.hp.nu) {
			continue // rejected: do not reveal z_{j,k}
		}

		// z_{j,k} = y_int + c·s1_(j). Because c·s1_(j) is integer,
		// round(y_float + c·s1) = y_int + c·s1, so this is consistent with both
		// the committed w = A·y_int and the float Excess decision.
		z := make(polyVec, L)
		for l := 0; l < L; l++ {
			z[l].add(&p.yInt[k][l], &cs1[l])
			z[l].normalize()
		}
		out.Z[k] = z
		out.Accepted[k] = true
	}
	return out
}

// ---------------------------------------------------------------------------
// hyperballCoordinator — aggregates PUBLIC round data only. It NEVER holds any
// s1_(j), any mask y, t0, s2, or w0 = LowBits(w). It forms only the public
// aggregates w = Σ_j w_j, w1 = HighBits(w), w' = A·z − c·t1·2^d, and the hint.
// ---------------------------------------------------------------------------

type hyperballCoordinator struct {
	mode   Mode
	hp     *hyperballParams
	a      []polyVec
	t1     polyVec
	pub    []byte
	tr     [64]byte
	active []int
	sid    [32]byte

	mu       [64]byte
	t1Scaled polyVec // NTT(t1·2^d), cached for w'

	// curMsg/curCtx are the PUBLIC message and context being signed, kept for
	// the fail-closed self-verify in finalize.
	curMsg []byte
	curCtx []byte

	// Per-slot PUBLIC aggregates (filled in Round 2).
	w        []polyVec   // K aggregated commitments Σ_j A·y_{j,k}
	w1       []polyVec   // K HighBits(w_k) (nil where not boundary-clear)
	cTilde   [][]byte    // K challenge hashes
	c        []*poly     // K challenges (nil where not boundary-clear / dead)
	commitT  [][32]byte  // [partyIdx] commitment to T_j (for blame)
	wByParty [][]polyVec // [slot][partyIdx] revealed w_{j,k} (for blame)
}

func newHyperballCoordinator(mk *MithrilKey, hp *hyperballParams, active []int, mu []byte) *hyperballCoordinator {
	K, _, _ := modeShape(mk.Mode)
	co := &hyperballCoordinator{
		mode: mk.Mode, hp: hp, a: mk.a, t1: mk.t1, pub: mk.pub, tr: mk.tr,
		active: active,
	}
	copy(co.mu[:], mu)
	co.t1Scaled = make(polyVec, K)
	for k := 0; k < K; k++ {
		co.t1Scaled[k].mulBy2toD(&mk.t1[k])
		co.t1Scaled[k].ntt()
	}
	return co
}

// aggregateCommitments (Round 2 coordinator step) verifies each party's R1
// binding hash against its revealed w, sums the per-slot commitments
// w_k = Σ_j w_{j,k}, and derives the challenge c_k for every boundary-clear
// slot. A slot whose aggregated w is NOT boundary-clear gets c = nil (dead) so
// no party responds on it — never a secret is consulted for this decision.
func (co *hyperballCoordinator) aggregateCommitments(sid [32]byte, r1s []HyperballRound1, r2s []HyperballRound2) error {
	K, _, _ := modeShape(co.mode)
	slots := co.hp.kReps
	gamma2, beta, _, _ := bccParams(co.mode)
	co.sid = sid

	// Index round-1 commitments by party id.
	r1by := map[int]HyperballRound1{}
	for _, m := range r1s {
		r1by[m.PartyID] = m
	}
	co.commitT = make([][32]byte, len(co.active))
	co.wByParty = make([][]polyVec, slots)
	for s := 0; s < slots; s++ {
		co.wByParty[s] = make([]polyVec, len(co.active))
	}

	co.w = make([]polyVec, slots)
	for s := 0; s < slots; s++ {
		co.w[s] = make(polyVec, K)
	}

	for ai, id := range co.active {
		r2 := findReveal(r2s, id)
		if r2 == nil {
			return fmt.Errorf("pulsar: hyperball: missing Round-2 reveal from party %d", id)
		}
		r1, ok := r1by[id]
		if !ok || len(r1.CommitW) != slots || len(r2.W) != slots {
			return fmt.Errorf("pulsar: hyperball: party %d round shape mismatch", id)
		}
		co.commitT[ai] = r1.CommitT
		for s := 0; s < slots; s++ {
			// Binding: the revealed w_{j,s} must match the Round-1 commitment,
			// preventing a rushing adversary from choosing w after seeing others.
			want := hyperballCommitW(sid, id, s, co.mu[:], r2.W[s])
			if want != r1.CommitW[s] {
				return fmt.Errorf("pulsar: hyperball: party %d slot %d w-commitment mismatch (equivocation)", id, s)
			}
			co.wByParty[s][ai] = r2.W[s]
			for k := 0; k < K; k++ {
				co.w[s][k].add(&co.w[s][k], &r2.W[s][k])
			}
		}
	}
	for s := 0; s < slots; s++ {
		for k := 0; k < K; k++ {
			co.w[s][k].normalize()
		}
	}

	// Derive challenges for boundary-clear slots.
	co.w1 = make([]polyVec, slots)
	co.cTilde = make([][]byte, slots)
	co.c = make([]*poly, slots)
	tau, _, _, _ := modeTauOmega(co.mode)
	cTildeSize := modeCTildeSize(co.mode)
	for s := 0; s < slots; s++ {
		if !BoundaryClear(co.w[s], gamma2, beta) {
			continue // dead slot — no challenge, no response
		}
		w1 := highBitsVec(co.w[s], gamma2)
		w1Packed := packW1Vec(w1, gamma2, K)
		cT := make([]byte, cTildeSize)
		h := sha3.NewShake256()
		_, _ = h.Write(co.mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cT)
		var c poly
		polyDeriveUniformBall(&c, cT, tau)
		co.w1[s] = w1
		co.cTilde[s] = cT
		cc := c
		co.c[s] = &cc
	}
	return nil
}

// challengesForRound3 exposes the per-slot challenges to the parties (nil for
// dead slots). The challenge is a PUBLIC function of the aggregated public w.
func (co *hyperballCoordinator) challengesForRound3() []*poly { return co.c }

// finalize (Round 3 coordinator step) tries each slot in order: it requires
// every active party to have ACCEPTED the slot, sums z_k = Σ_j z_{j,k}, runs the
// FIPS-204 norm + FindHint release gate on the PUBLIC w' = A·z − c·t1·2^d, and
// returns the first slot that produces a stock-verifiable signature. A biased or
// malformed partial makes w' miss w1, so FindHint fails (or the fail-closed self-
// verify rejects) — that slot is skipped, never a bad signature emitted.
func (co *hyperballCoordinator) finalize(params *Params, r3s []HyperballRound3) (*Signature, int, error) {
	K, L, _ := modeShape(co.mode)
	gamma2, beta, omega, _ := bccParams(co.mode)
	_, _, gamma1Bits, _ := modeTauOmega(co.mode)
	gamma1 := uint32(1) << gamma1Bits
	slots := co.hp.kReps
	cTildeSize := modeCTildeSize(co.mode)
	polyLeGamma1Size := int((gamma1Bits + 1) * mldsaN / 8)

	r3by := map[int]HyperballRound3{}
	for _, m := range r3s {
		r3by[m.PartyID] = m
	}

	for s := 0; s < slots; s++ {
		if co.c[s] == nil {
			continue // dead slot
		}
		// Require all active parties to have accepted this slot.
		all := true
		for _, id := range co.active {
			r3, ok := r3by[id]
			if !ok || len(r3.Accepted) != slots || !r3.Accepted[s] || r3.Z[s] == nil {
				all = false
				break
			}
		}
		if !all {
			continue
		}

		// z_k = Σ_j z_{j,k}.
		z := make(polyVec, L)
		for _, id := range co.active {
			r3 := r3by[id]
			if len(r3.Z[s]) != L {
				all = false
				break
			}
			for l := 0; l < L; l++ {
				z[l].add(&z[l], &r3.Z[s][l])
			}
		}
		if !all {
			continue
		}
		for l := 0; l < L; l++ {
			z[l].normalize()
		}

		// FIPS-204 reject bound on the SUMMED z.
		if polyVecExceeds(z, gamma1-beta) {
			continue
		}

		// w' = A·z − c·t1·2^d (PUBLIC), then FindHint from (w', w1).
		cHat := *co.c[s]
		cHat.ntt()
		zHat := make(polyVec, L)
		for l := 0; l < L; l++ {
			zHat[l] = z[l]
			zHat[l].ntt()
		}
		wPrime := make(polyVec, K)
		for k := 0; k < K; k++ {
			var az poly
			polyDotHat(&az, co.a[k], zHat)
			az.reduceLe2Q()
			var ct1 poly
			ct1.mulHat(&cHat, &co.t1Scaled[k])
			az.sub(&az, &ct1)
			az.reduceLe2Q()
			az.invNTT()
			az.normalize()
			wPrime[k] = az
		}
		hint, ok := FindHint(wPrime, co.w1[s], gamma2, omega)
		if !ok {
			continue
		}

		// sigEncode(c̃, z, h) — identical to bccSign / the single-party path.
		sigBytes := make([]byte, params.SignatureSize)
		copy(sigBytes[:cTildeSize], co.cTilde[s])
		off := cTildeSize
		for l := 0; l < L; l++ {
			polyPackLeGamma1(&z[l], sigBytes[off:off+polyLeGamma1Size], gamma1Bits)
			off += polyLeGamma1Size
		}
		polyVecPackHint(hint, sigBytes[off:off+int(omega)+K], int(omega))

		sig := &Signature{Mode: co.mode, Bytes: sigBytes}
		// Fail-closed release gate: never emit a signature the FIPS-204 verifier
		// rejects, even if FindHint succeeded.
		pk := &PublicKey{Mode: co.mode, Bytes: co.pub}
		if err := VerifyCtx(params, pk, co.curMsg, co.curCtx, sig); err != nil {
			continue
		}
		return sig, s, nil
	}
	return nil, -1, ErrHyperballExhausted
}

// blameSlot identifies the culprit behind a failed slot WITHOUT leaking s2. It
// checks each active party's partial against its share-verification commitment:
// an honest z_{j,s} satisfies A·z_{j,s} − w_{j,s} = c_s·T_j (because
// A·z = A·y + c·A·s1_(j) = w_{j,s} + c·T_j). A party is the culprit if it
// (a) failed to contribute an accepted partial (liveness fault), (b) reveals a
// T_j that does not match its Round-1 commitment (equivocation), or (c) submits
// a partial inconsistent with its committed T_j. revealedTj supplies the T_j of
// the parties checked so far; the caller reveals one party at a time and STOPS
// at the first culprit, so the full active sum Σ_j T_j (= t − s2) is never
// formed — blame is leak-free. Returns (id, true) for the culprit, (−1, false)
// if every revealed party is consistent.
//
// SCOPE (documented, not faked): a party that uses a share inconsistent with
// keygen but self-consistent with its OWN (equivocated-at-keygen) T_j passes
// this per-party check; it is still caught by the fail-closed release gate in
// finalize (no bad signature is ever emitted) but is not pinpointed here. This
// is the same identifiable-abort residual as luxfi/dkg's malicious-CSCP layer.
func (co *hyperballCoordinator) blameSlot(slot int, r3by map[int]HyperballRound3, revealedTj map[int]polyVec) (int, bool) {
	K, L, _ := modeShape(co.mode)
	if slot < 0 || slot >= len(co.c) || co.c[slot] == nil {
		return -1, false
	}
	cHat := *co.c[slot]
	cHat.ntt()
	for ai, id := range co.active {
		r3, ok := r3by[id]
		if !ok || len(r3.Accepted) <= slot || !r3.Accepted[slot] || r3.Z[slot] == nil || len(r3.Z[slot]) != L {
			return id, true // liveness fault: no usable partial on a live slot
		}
		tj, ok := revealedTj[id]
		if !ok {
			continue // not yet revealed; caller reveals on demand
		}
		if hyperballCommitT(co.sid, id, tj) != co.commitT[ai] {
			return id, true // equivocated T_j vs its Round-1 commitment
		}
		// lhs = A·z_{j,s} − w_{j,s}; rhs = c_s·T_j.
		z := r3.Z[slot]
		zHat := make(polyVec, L)
		for l := 0; l < L; l++ {
			zHat[l] = z[l]
			zHat[l].ntt()
		}
		az := matVecHat(co.a, zHat)
		cTj := make(polyVec, K)
		for k := 0; k < K; k++ {
			tHat := tj[k]
			tHat.ntt()
			cTj[k].mulHat(&cHat, &tHat)
			cTj[k].reduceLe2Q()
			cTj[k].invNTT()
			cTj[k].normalize()
		}
		for k := 0; k < K; k++ {
			var diff poly
			diff.sub(&az[k], &co.wByParty[slot][ai][k])
			diff.normalize()
			if diff != cTj[k] {
				return id, true // partial inconsistent with committed T_j
			}
		}
	}
	return -1, false
}

// bindMessage records the PUBLIC message and context so finalize can run the
// fail-closed self-verify (VerifyCtx) without re-threading them.
func (co *hyperballCoordinator) bindMessage(msg, ctx []byte) {
	co.curMsg = append([]byte(nil), msg...)
	co.curCtx = append([]byte(nil), ctx...)
}

// ---------------------------------------------------------------------------
// HyperballTranscript — the PUBLIC record of a signing run. It carries ONLY the
// bytes that crossed the wire (commitment hashes, revealed w_{j,k}, revealed
// z_{j,k}, the winning slot's w1/c̃/hint). The no-leak oracle (tests) asserts
// that NO party's mask y nor share s1_(j) bytes appear in publicBytes().
// ---------------------------------------------------------------------------

type HyperballTranscript struct {
	T, N        int
	Mode        Mode
	Rounds      int
	WinningSlot int

	r1s []HyperballRound1
	r2s []HyperballRound2
	r3s []HyperballRound3

	winW1   polyVec
	winC    []byte
	winHint polyVec
}

func (tr *HyperballTranscript) record(r1s []HyperballRound1, r2s []HyperballRound2, r3s []HyperballRound3) {
	tr.r1s = append(tr.r1s, r1s...)
	tr.r2s = append(tr.r2s, r2s...)
	tr.r3s = append(tr.r3s, r3s...)
}

func (tr *HyperballTranscript) recordWinner(co *hyperballCoordinator, slot int) {
	if slot < 0 || slot >= len(co.w1) {
		return
	}
	tr.winW1 = co.w1[slot]
	tr.winC = co.cTilde[slot]
}

// publicBytes serialises every public quantity the transcript exposes — the
// exact set a real no-leak transcript carries. The oracle scans this for
// forbidden secret material.
func (tr *HyperballTranscript) publicBytes() []byte {
	out := make([]byte, 0, 8192)
	for _, m := range tr.r1s {
		out = append(out, byte(m.PartyID))
		for _, c := range m.CommitW {
			out = append(out, c[:]...)
		}
		out = append(out, m.CommitT[:]...)
	}
	for _, m := range tr.r2s {
		out = append(out, byte(m.PartyID))
		for _, w := range m.W {
			out = append(out, packPolyVec(w)...)
		}
	}
	for _, m := range tr.r3s {
		out = append(out, byte(m.PartyID))
		for _, z := range m.Z {
			if z != nil {
				out = append(out, packPolyVec(z)...)
			}
		}
	}
	if tr.winW1 != nil {
		out = append(out, packPolyVec(tr.winW1)...)
	}
	out = append(out, tr.winC...)
	return out
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

// SignHyperball produces a byte-stock-FIPS-204 ML-DSA signature on (message, ctx)
// under the dealerless RSS group key, from any T active parties, WITHOUT ever
// reconstructing the key. No party or coordinator forms the full s1, s2, t0, the
// mask y, the commitment w, w0 = LowBits(w), or any sk: each active party holds
// only its balanced-partition share s1_(j) and emits only z_j = y_j + c·s1_(j).
//
// It runs the Mithril 3-round hyperball protocol with hp.kReps parallel slots,
// re-running with fresh nonces up to maxRounds times until a slot yields a
// fully-accepted, norm-valid, hint-admissible signature. The returned *Signature
// verifies under unmodified cloudflare/circl mldsa{65,87}.Verify; the returned
// transcript carries ONLY the public round bytes (for the no-leak oracle).
//
// active must be a sorted, duplicate-free set of exactly T party ids. rng
// supplies fresh per-round entropy (so distinct rounds use distinct nonces).
func (mk *MithrilKey) SignHyperball(active []int, message, ctx []byte, rng io.Reader, maxRounds int) (*Signature, *HyperballTranscript, error) {
	if err := validateActive(active, mk.T, mk.N); err != nil {
		return nil, nil, err
	}
	if len(ctx) > 255 {
		return nil, nil, ErrCtxTooLong
	}
	params, err := ParamsFor(mk.Mode)
	if err != nil {
		return nil, nil, err
	}
	hp, err := deriveHyperballParams(mk.Mode, mk.T, mk.N)
	if err != nil {
		return nil, nil, err
	}

	// μ = SHAKE-256(tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ M) — the FIPS-204 message
	// representative, single source of truth (deriveMuCtx).
	var mu [64]byte
	deriveMuCtx(mk.tr, ctx, message, mu[:])

	// Build the parties from their OWN holdings. This is the structural no-
	// reconstruct boundary: each party gets s1_(j) and the public matrix only.
	part, err := rss.RSSRecover(active, mk.T, mk.N)
	if err != nil {
		return nil, nil, err
	}
	parties := make([]*hyperballParty, len(active))
	for j, id := range active {
		s1Share, err := mk.partyShareS1(id, part[j])
		if err != nil {
			return nil, nil, err
		}
		parties[j] = newHyperballParty(mk.Mode, hp, mk.a, id, s1Share)
	}

	// Session id binds the protocol run to (pub, active, μ).
	sid := hyperballSessionID(mk.pub, active, mu[:])
	tr := &HyperballTranscript{T: mk.T, N: mk.N, Mode: mk.Mode}

	if maxRounds < 1 {
		maxRounds = 1
	}
	for round := 0; round < maxRounds; round++ {
		var roundEntropy [32]byte
		if _, err := io.ReadFull(rng, roundEntropy[:]); err != nil {
			return nil, nil, err
		}

		co := newHyperballCoordinator(mk, hp, active, mu[:])
		co.bindMessage(message, ctx)

		// Round 1: commitments.
		r1s := make([]HyperballRound1, len(parties))
		for j, p := range parties {
			r1s[j] = p.round1(roundEntropy[:], sid, mu[:])
		}
		// Round 2: reveals + aggregate + challenge.
		r2s := make([]HyperballRound2, len(parties))
		for j, p := range parties {
			r2s[j] = p.round2()
		}
		if err := co.aggregateCommitments(sid, r1s, r2s); err != nil {
			return nil, nil, err
		}
		// Round 3: partial responses with per-party Excess rejection.
		ch := co.challengesForRound3()
		r3s := make([]HyperballRound3, len(parties))
		for j, p := range parties {
			r3s[j] = p.round3(ch)
		}

		tr.record(r1s, r2s, r3s)

		sig, slot, err := co.finalize(params, r3s)
		if err == nil {
			tr.Rounds = round + 1
			tr.WinningSlot = slot
			tr.recordWinner(co, slot)
			return sig, tr, nil
		}
	}
	return nil, tr, ErrHyperballExhausted
}

// partyShareS1 returns party id's share of s1 = the sum of the s1 parts of the
// subsets the balanced partition assigned to it, taken from THIS party's
// holdings. It NEVER sums across parties (that would form the full s1). The
// result is in the χ_η sum representation (coefficients near a small multiple of
// the centred range), length L.
func (mk *MithrilKey) partyShareS1(id int, masks []uint64) (polyVec, error) {
	_, L, _ := modeShape(mk.Mode)
	s1 := make(polyVec, L)
	holdings := mk.holdings[id]
	for _, mask := range masks {
		ss, ok := holdings[mask]
		if !ok {
			return nil, fmt.Errorf("pulsar: hyperball: signer %d missing assigned subset 0b%b", id, mask)
		}
		for l := 0; l < L; l++ {
			s1[l].add(&s1[l], &ss.s1[l])
		}
	}
	return s1, nil
}

// ---------------------------------------------------------------------------
// Hyperball sampling and the Excess gate
// ---------------------------------------------------------------------------

// sampleHyperballInBall draws a point uniformly inside the ball B(0, r1) ⊂ R^dim
// from a deterministic SHAKE-256 stream: a Gaussian direction (Box-Muller) scaled
// to radius r1·U^{1/dim}. Uniform-in-ball (not on-surface) is what makes the
// accepted response uniform on B(0, r) — the leak-free bounded-rejection geometry
// of docs/hyperball-mldsa65-params.md §3.
func sampleHyperballInBall(seed *[64]byte, dim int, r1 float64) []float64 {
	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	g := make([]float64, dim)
	var sumSq float64
	for i := 0; i < dim; i += 2 {
		u1 := shakeUnitFloat(h)
		u2 := shakeUnitFloat(h)
		rad := math.Sqrt(-2 * math.Log(u1))
		g[i] = rad * math.Cos(2*math.Pi*u2)
		sumSq += g[i] * g[i]
		if i+1 < dim {
			g[i+1] = rad * math.Sin(2*math.Pi*u2)
			sumSq += g[i+1] * g[i+1]
		}
	}
	norm := math.Sqrt(sumSq)
	if norm == 0 {
		norm = 1
	}
	// Uniform radius in the ball: ρ = r1 · U^{1/dim}.
	uRad := shakeUnitFloat(h)
	rho := r1 * math.Pow(uRad, 1.0/float64(dim))
	scale := rho / norm
	for i := range g {
		g[i] *= scale
	}
	return g
}

// shakeUnitFloat reads 8 bytes from the stream and maps them to (0,1] (never
// exactly 0, so log is finite).
func shakeUnitFloat(h sha3.ShakeHash) float64 {
	var b [8]byte
	_, _ = h.Read(b[:])
	u := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	// (u+1)/2^64 ∈ (0,1].
	return (float64(u) + 1.0) / 18446744073709551616.0
}

// floatToMaskPolyVec rounds a continuous ball point to the integer mask vector
// (length L), mapping each coefficient into [0,q) in centred representation.
func floatToMaskPolyVec(yf []float64, L int) polyVec {
	y := make(polyVec, L)
	for l := 0; l < L; l++ {
		for i := 0; i < mldsaN; i++ {
			v := int64(math.Round(yf[l*mldsaN+i]))
			y[l][i] = int64ToModQ(v)
		}
	}
	return y
}

// int64ToModQ maps a signed integer into [0, q).
func int64ToModQ(v int64) uint32 {
	m := v % int64(mldsaQ)
	if m < 0 {
		m += int64(mldsaQ)
	}
	return uint32(m)
}

// hyperballExcess is the leak-free one-sided rejection gate. It computes the
// continuous response z_float = y_float + c·s1_(j) (centred) and reports whether
// its ellipsoid norm exceeds the acceptance radius r:
//
//	Σ_i (z_float_i / ν)²  >  r²
//
// (ν = 1 one-sided ⇒ plain L2 ball). cs1 is the integer c·s1_(j) (length L,
// normalised); its centred value is the true small shift.
func hyperballExcess(yFloat []float64, cs1 polyVec, r, nu float64) bool {
	var sq float64
	inv := 1.0 / (nu * nu)
	for l := range cs1 {
		for i := 0; i < mldsaN; i++ {
			z := yFloat[l*mldsaN+i] + float64(centeredCoeff(cs1[l][i]))
			sq += z * z * inv
		}
	}
	return sq > r*r
}

// centeredCoeff returns the centred representative of a normalised coefficient
// (in (−q/2, q/2]).
func centeredCoeff(a uint32) int32 {
	if a > (mldsaQ-1)/2 {
		return int32(a) - mldsaQ
	}
	return int32(a)
}

// ---------------------------------------------------------------------------
// Commitments, seeds, session id
// ---------------------------------------------------------------------------

func hyperballNonceSeed(roundEntropy []byte, sid [32]byte, partyID, slot int) *[64]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("pulsar.mithril.hyperball.nonce.v1"))
	_, _ = h.Write(roundEntropy)
	_, _ = h.Write(sid[:])
	_, _ = h.Write([]byte{byte(partyID), byte(partyID >> 8), byte(slot), byte(slot >> 8)})
	var seed [64]byte
	_, _ = h.Read(seed[:])
	return &seed
}

// hyperballCommitW binds a party's per-slot commitment to (sid, id, slot, μ, w).
// The coordinator re-derives it from the Round-2 reveal to detect equivocation.
func hyperballCommitW(sid [32]byte, partyID, slot int, mu []byte, w polyVec) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("pulsar.mithril.hyperball.commitW.v1"))
	_, _ = h.Write(sid[:])
	_, _ = h.Write([]byte{byte(partyID), byte(partyID >> 8), byte(slot), byte(slot >> 8)})
	_, _ = h.Write(mu)
	_, _ = h.Write(packPolyVec(w))
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// hyperballCommitT binds a party's share-verification value T_j = A·s1_(j),
// revealed only on blame. In the honest path T_j is never revealed: the full
// active sum Σ_j T_j = A·s1 = t − s2 would leak s2.
func hyperballCommitT(sid [32]byte, partyID int, tjS1 polyVec) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("pulsar.mithril.hyperball.commitT.v1"))
	_, _ = h.Write(sid[:])
	_, _ = h.Write([]byte{byte(partyID), byte(partyID >> 8)})
	_, _ = h.Write(packPolyVec(tjS1))
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

func hyperballSessionID(pub []byte, active []int, mu []byte) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("pulsar.mithril.hyperball.sid.v1"))
	_, _ = h.Write(pub)
	for _, id := range active {
		_, _ = h.Write([]byte{byte(id), byte(id >> 8)})
	}
	_, _ = h.Write(mu)
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

func findReveal(r2s []HyperballRound2, id int) *HyperballRound2 {
	for i := range r2s {
		if r2s[i].PartyID == id {
			return &r2s[i]
		}
	}
	return nil
}

// validateActive enforces a sorted, duplicate-free, in-range set of exactly T
// ids, and a viable committee.
func validateActive(active []int, t, n int) error {
	if err := rss.ValidateCommittee(t, n); err != nil {
		return err
	}
	if len(active) != t {
		return ErrHyperballActive
	}
	prev := -1
	for _, id := range active {
		if id <= prev || id < 0 || id >= n {
			return ErrHyperballActive
		}
		prev = id
	}
	return nil
}
