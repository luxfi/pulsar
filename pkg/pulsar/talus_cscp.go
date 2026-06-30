// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_cscp.go — the REAL CarryCompare secure-comparison MPC circuit (CSCP):
// the closing move for PULSAR-V13-W-LEAK. It realises the ideal functionality
// cefIdealSecureHighBits with an actual secure comparison so that NO node ever
// forms the aggregate low sum A0 = Σ a0_i, the low part w0 = LowBits(w), or the
// full commitment w — not even transiently in one process. Only w1 = HighBits(w)
// is ever opened.
//
// ────────────────────────────────────────────────────────────────────────────
// WHY A SECURE COMPARISON IS THE IRREDUCIBLE STEP.
//
// After the dealerless nonce DKG + CEF commitment step, the quorum holds an
// ADDITIVE sharing {g_i} of the commitment w (party i holds g_i ∈ Z_q^K,
// Σ_i g_i ≡ w = A·ȳ mod q). Recovering w1 = HighBits(w) by the carry-elimination
// identity (cefReconstructW1FromShares) needs the aggregate low sum A0 = Σ a0_i to
// resolve the α-carry — and A0 IS w0 up to that carry, so forming it in the clear
// leaks the long-term key (w = w1·α + w0; the verifier-public w' − w = c·t0 − c·s2).
// The α-rounding / HighBits boundary is non-linear, so it cannot be done by share
// arithmetic alone: it needs a secure COMPARISON. This file builds that comparison
// exactly, semi-honestly, honest-majority, over the BGW substrate (talus_mpc.go).
//
// ────────────────────────────────────────────────────────────────────────────
// THE CIRCUIT (exact, leak-free, semi-honest honest-majority).
//
// Per commitment coefficient (the 256·K coefficients are independent):
//
//  1. ADDITIVE → SHAMIR. Each party Shamir-shares its own additive part g_i over
//     GF(q) at degree T−1; the quorum sums the received shares into a degree-(T−1)
//     Shamir sharing ⟨w⟩ of w = Σ g_i mod q (the Shamir field IS the ML-DSA prime
//     q, so the GF(q) reduction equals the ring reduction — no q-overflow handling).
//     ⟨w⟩ is NEVER opened.
//
//  2. SECURE HighBits. With γ2 = (q−1)/32, α = 2γ2, m = (q−1)/α = 16 (a power of
//     two for ML-DSA-65/87 — the BCC-proven scope), HighBits over Z_q is the
//     bucket index, exactly
//
//          w1 = ( Σ_{k=1..16} [ w > (2k−1)·γ2 ] ) mod 16,
//
//     validated coefficient-exact against FIPS Decompose
//     (TestCSCP_BoundaryCountFormula_MatchesDecompose). Each indicator
//     [ (2k−1)γ2 < w ] is one secure comparison of the shared ⟨w⟩ against a PUBLIC
//     boundary; the 16 indicators are summed and reduced mod 16 (the "==16" fold is
//     a single AND of the 16 indicator bits). The only non-linear work is the
//     comparison, which reduces to ONE bit-decomposition of ⟨w⟩ (reused by all 16
//     comparisons) plus a bitwise prefix less-than.
//
//  3. BIT-DECOMPOSITION (the carry-save core). ⟨w⟩'s bits are extracted by the
//     standard mask-open: draw a shared random ⟨r⟩ ∈ [0,q) with KNOWN shared bits,
//     open c = (w − r) mod q (uniform ⇒ leak-free), then recover the bits of
//     w = (c + r) mod q by a bitwise add (carry-save adder) of the public c and the
//     shared bits of r, followed by a conditional subtract of q (the mod-q fold,
//     decided by one bitwise less-than). This is the "Carry-Save-Adder reduction +
//     prefix comparison" the obstruction (assessCSCP) names.
//
// LEAK-FREENESS. The ONLY values ever reconstructed are: the random-bitwise
// VALIDITY bit (∈{0,1}, independent of any secret), the per-coefficient mask-open
// c = (w − r) mod q (uniform over Z_q, independent of w by perfect masking), and
// the final w1. The shared ⟨w⟩, the bits of w, A0, and w0 are never opened and
// never assembled in the clear on any node. The transcript recorder (cscpTranscript)
// captures every opened value so the test can assert exactly this set, and that w0
// is never among them.
//
// SCOPE (semi-honest). The substrate (BGW mult, shared bits) is semi-honest
// honest-majority and enforces N ≥ 2T−1 (TALUS Theorem 10.1). The malicious-secure,
// identifiable-abort hardening (committed shares + verified openings + complaint
// round, TALUS Phase B) is the orthogonal residual scoped in CSCPMaliciousResidual;
// the leak-free property proven here holds for the semi-honest adversary and does
// NOT depend on that layer.

import (
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrCSCPShape rejects malformed share / eval-point / commitment input.
	ErrCSCPShape = errors.New("pulsar: CSCP share / eval-point / commitment shape mismatch")
	// ErrCSCPParamSet rejects parameter sets outside the BCC-proven scope (the
	// m = (q−1)/α = 16 power-of-two HighBits-bucket assumption holds only for
	// ML-DSA-65/87).
	ErrCSCPParamSet = errors.New("pulsar: CSCP is proven for ML-DSA-65/87 (m=16 buckets) only")
	// ErrCSCPRandBits is returned when the random-bitwise generator fails to draw
	// a valid r < q within the retry budget (astronomically unlikely; ~0.1% reject).
	ErrCSCPRandBits = errors.New("pulsar: CSCP random-bitwise generation exhausted retries")
)

// cscpBitLen is the GF(q) bit length: q = 8380417 < 2^23, so a residue in [0,q)
// fits in 23 bits, and a sum c+r < 2q fits in 24.
const cscpBitLen = 23

// shareVec is a degree-(T−1) GF(q) Shamir sharing of one scalar, indexed by party
// (parallel to evalPoints). A "shared bit" is a shareVec whose secret is in {0,1}.
type shareVec = []uint32

// cscpTranscript records every value OPENED (reconstructed) during a CSCP run,
// tagged by purpose, so a test can prove that only the leak-free set is ever
// revealed (validity bits, the uniform mask-open, the final w1) and that w0/w/A0
// never appear.
type cscpTranscript struct {
	mu      sync.Mutex
	Valid   []uint32 // random-bitwise validity bits (each ∈ {0,1})
	MaskC   []uint32 // per-coefficient mask-open c = (w − r) mod q (uniform)
	W1      []uint32 // the per-coefficient final w1 (the intended public output)
	otherCt int      // count of any open NOT in the three sanctioned tags (must stay 0)
}

func (tr *cscpTranscript) record(tag string, v uint32) {
	if tr == nil {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	switch tag {
	case "valid":
		tr.Valid = append(tr.Valid, v)
	case "maskC":
		tr.MaskC = append(tr.MaskC, v)
	case "w1":
		tr.W1 = append(tr.W1, v)
	default:
		tr.otherCt++
	}
}

// cscpCtx carries the honest-majority MPC parameters and the (optional) transcript.
// It is the simulation harness for the per-secret share-vector arithmetic: every
// method operates on degree-(T−1) GF(q) sharings and never materialises a secret.
type cscpCtx struct {
	evalPoints []uint32
	threshold  int
	n          int
	gamma2     uint32
	rng        io.Reader
	tr         *cscpTranscript
}

func newCSCPCtx(mode Mode, evalPoints []uint32, threshold int, rng io.Reader, tr *cscpTranscript) (*cscpCtx, error) {
	gamma2, _, _, ok := bccParams(mode)
	if !ok {
		return nil, ErrCSCPParamSet
	}
	// The m=16 power-of-two bucket assumption is exactly the ML-DSA-65/87 scope.
	if gamma2 != mldsaGamma2P65 {
		return nil, ErrCSCPParamSet
	}
	n := len(evalPoints)
	if threshold < 1 || n < threshold {
		return nil, ErrInvalidThreshold
	}
	if n < 2*threshold-1 {
		return nil, ErrBGWNotEnoughParties
	}
	return &cscpCtx{evalPoints: evalPoints, threshold: threshold, n: n, gamma2: gamma2, rng: rng, tr: tr}, nil
}

// ───────────────────────── share-vector linear algebra ─────────────────────────

// constShare returns the degree-(T−1) sharing of the public constant c: every
// party holds c (f(x)=c), and Σ λ_i·c = c·Σλ_i = c (Lagrange weights sum to 1).
func (c *cscpCtx) constShare(v uint32) shareVec {
	out := make(shareVec, c.n)
	r := uint32(uint64(v) % shamirPrimeQ)
	for i := range out {
		out[i] = r
	}
	return out
}

// add / sub / scalarMul are local, free, degree-preserving (no interaction).
func (c *cscpCtx) add(a, b shareVec) shareVec {
	out := make(shareVec, c.n)
	for i := 0; i < c.n; i++ {
		out[i] = uint32((uint64(a[i]) + uint64(b[i])) % shamirPrimeQ)
	}
	return out
}

func (c *cscpCtx) sub(a, b shareVec) shareVec {
	out := make(shareVec, c.n)
	for i := 0; i < c.n; i++ {
		out[i] = uint32((uint64(a[i]) + (shamirPrimeQ - uint64(b[i]))) % shamirPrimeQ)
	}
	return out
}

func (c *cscpCtx) scalarMul(s uint32, a shareVec) shareVec {
	out := make(shareVec, c.n)
	sm := uint64(s) % shamirPrimeQ
	for i := 0; i < c.n; i++ {
		out[i] = uint32((uint64(a[i]) * sm) % shamirPrimeQ)
	}
	return out
}

// mul is the one interactive primitive: one BGW secure multiplication. It is the
// substrate gate that enforces N ≥ 2T−1.
func (c *cscpCtx) mul(a, b shareVec) (shareVec, error) {
	return bgwMulShares(a, b, c.evalPoints, c.threshold, c.rng)
}

// open reconstructs a sharing at X=0 from the first T shares and records the value
// under tag. This is the ONLY place a value leaves the shared domain; the protocol
// calls it on EXACTLY three kinds of value: a random-bitwise validity bit, the
// uniform mask-open c, and the final w1.
func (c *cscpCtx) open(tag string, a shareVec) (uint32, error) {
	v, err := reconstructScalarGFq(c.evalPoints[:c.threshold], a[:c.threshold])
	if err != nil {
		return 0, err
	}
	c.tr.record(tag, v)
	return v, nil
}

// ───────────────────────────── shared-bit gadgets ──────────────────────────────

// notBit returns ⟨1−a⟩ for a shared bit a (linear).
func (c *cscpCtx) notBit(a shareVec) shareVec { return c.sub(c.constShare(1), a) }

// xorBit returns ⟨a⊕b⟩ = ⟨a+b−2ab⟩ for shared bits a,b (one multiplication).
func (c *cscpCtx) xorBit(a, b shareVec) (shareVec, error) {
	ab, err := c.mul(a, b)
	if err != nil {
		return nil, err
	}
	return c.sub(c.add(a, b), c.scalarMul(2, ab)), nil
}

// xorPubBit returns ⟨p⊕a⟩ for a PUBLIC bit p and shared bit a (linear: a or 1−a).
func (c *cscpCtx) xorPubBit(p uint32, a shareVec) shareVec {
	if p&1 == 0 {
		return a
	}
	return c.notBit(a)
}

// andBit returns ⟨a∧b⟩ (one multiplication).
func (c *cscpCtx) andBit(a, b shareVec) (shareVec, error) { return c.mul(a, b) }

// randomSharedBit draws one shared uniform bit via the substrate's XOR-folded
// SharedRandomBit, feeding one fresh private bit per party.
func (c *cscpCtx) randomSharedBit() (shareVec, error) {
	bits := make([]bool, c.n)
	for i := range bits {
		b, err := randBitFromReader(c.rng)
		if err != nil {
			return nil, err
		}
		bits[i] = b
	}
	return SharedRandomBit(c.evalPoints, c.threshold, bits, c.rng)
}

// randomBitwise produces a shared ⟨r⟩ ∈ [0,q) uniform together with its shared
// bits ⟨r_0⟩..⟨r_{L−1}⟩ (LSB-first, L = cscpBitLen). It draws L shared random bits,
// assembles ⟨r⟩ = Σ 2^j⟨r_j⟩, and rejects (opening ONLY a validity bit, which is
// independent of r's value) when r ≥ q so the accepted r is uniform over [0,q).
func (c *cscpCtx) randomBitwise() (shareVec, []shareVec, error) {
	const maxRetry = 64
	for attempt := 0; attempt < maxRetry; attempt++ {
		bits := make([]shareVec, cscpBitLen)
		rShare := c.constShare(0)
		for j := 0; j < cscpBitLen; j++ {
			bj, err := c.randomSharedBit()
			if err != nil {
				return nil, nil, err
			}
			bits[j] = bj
			rShare = c.add(rShare, c.scalarMul(uint32(uint64(1)<<uint(j)), bj))
		}
		// Validity: r < q. bitLTSharedPub(bits, q) opens to 1 iff r < q.
		ltShare, err := c.bitLTSharedPub(bits, uint32(shamirPrimeQ))
		if err != nil {
			return nil, nil, err
		}
		valid, err := c.open("valid", ltShare)
		if err != nil {
			return nil, nil, err
		}
		if valid == 1 {
			return rShare, bits, nil
		}
	}
	return nil, nil, ErrCSCPRandBits
}

// bitLTPubShared returns ⟨[x < y]⟩ for a PUBLIC x and shared bits yBits (LSB-first).
// Sequential MSB→LSB: at the most-significant differing bit, x<y iff x_j=0 (so
// y_j=1). One multiplication per bit (the "still-undecided" gate).
func (c *cscpCtx) bitLTPubShared(x uint32, yBits []shareVec) (shareVec, error) {
	lt := c.constShare(0)
	decided := c.constShare(0)
	for j := len(yBits) - 1; j >= 0; j-- {
		xj := (x >> uint(j)) & 1
		yj := yBits[j]
		diff := c.xorPubBit(xj, yj) // x_j ⊕ y_j
		nd, err := c.mul(diff, c.notBit(decided))
		if err != nil {
			return nil, err
		}
		if xj == 0 {
			// first differing bit with x_j=0 ⇒ y_j=1 ⇒ x<y.
			lt = c.add(lt, nd)
		}
		decided = c.add(decided, nd)
	}
	return lt, nil
}

// bitLTSharedPub returns ⟨[y < x]⟩ for shared bits yBits (LSB-first) and PUBLIC x.
func (c *cscpCtx) bitLTSharedPub(yBits []shareVec, x uint32) (shareVec, error) {
	lt := c.constShare(0)
	decided := c.constShare(0)
	for j := len(yBits) - 1; j >= 0; j-- {
		xj := (x >> uint(j)) & 1
		yj := yBits[j]
		diff := c.xorPubBit(xj, yj)
		nd, err := c.mul(diff, c.notBit(decided))
		if err != nil {
			return nil, err
		}
		if xj == 1 {
			// first differing bit with x_j=1 ⇒ y_j=0 ⇒ y<x.
			lt = c.add(lt, nd)
		}
		decided = c.add(decided, nd)
	}
	return lt, nil
}

// bitAdd computes the shared bits of s = cPub + r where cPub is PUBLIC and rBits
// are shared (LSB-first). Ripple carry-save adder; result has len(rBits)+1 bits.
func (c *cscpCtx) bitAdd(cPub uint32, rBits []shareVec) ([]shareVec, error) {
	L := len(rBits)
	out := make([]shareVec, L+1)
	carry := c.constShare(0)
	for j := 0; j < L; j++ {
		cj := (cPub >> uint(j)) & 1
		rj := rBits[j]
		t1 := c.xorPubBit(cj, rj) // c_j ⊕ r_j  (linear)
		sj, err := c.xorBit(t1, carry)
		if err != nil {
			return nil, err
		}
		out[j] = sj
		// carry_out = MAJ(c_j, r_j, carry) = c_j·r_j + carry·(c_j⊕r_j).
		var cjrj shareVec
		if cj == 1 {
			cjrj = rj
		} else {
			cjrj = c.constShare(0)
		}
		ct1, err := c.mul(carry, t1)
		if err != nil {
			return nil, err
		}
		carry = c.add(cjrj, ct1)
	}
	out[L] = carry
	return out, nil
}

// bitSubBetaQ computes the shared bits of w = s − β·q where sBits are shared
// (LSB-first), β is a shared bit, and q is PUBLIC. Ripple borrow subtractor; since
// β·q ≤ s (β=1 only when s≥q) the result is non-negative and < q.
func (c *cscpCtx) bitSubBetaQ(sBits []shareVec, beta shareVec, q uint32) ([]shareVec, error) {
	L := len(sBits)
	out := make([]shareVec, L)
	borrow := c.constShare(0)
	for j := 0; j < L; j++ {
		sj := sBits[j]
		qj := (q >> uint(j)) & 1
		if qj == 1 {
			dj := beta // d_j = β·1
			t1, err := c.xorBit(sj, dj)
			if err != nil {
				return nil, err
			}
			wj, err := c.xorBit(t1, borrow)
			if err != nil {
				return nil, err
			}
			out[j] = wj
			// borrow_out = (¬s_j·d_j) + borrow·(¬(s_j⊕d_j)).
			b1, err := c.mul(c.notBit(sj), dj)
			if err != nil {
				return nil, err
			}
			b2, err := c.mul(borrow, c.notBit(t1))
			if err != nil {
				return nil, err
			}
			borrow = c.add(b1, b2)
		} else {
			// d_j = 0: w_j = s_j ⊕ borrow; borrow_out = ¬s_j·borrow.
			wj, err := c.xorBit(sj, borrow)
			if err != nil {
				return nil, err
			}
			out[j] = wj
			nb, err := c.mul(c.notBit(sj), borrow)
			if err != nil {
				return nil, err
			}
			borrow = nb
		}
	}
	return out, nil
}

// bitDecompose extracts the shared bits ⟨w_0⟩..⟨w_{L−1}⟩ (LSB-first, L=cscpBitLen)
// of a shared ⟨w⟩ ∈ [0,q) WITHOUT opening w. It masks with a random ⟨r⟩ (known
// shared bits), opens the uniform c = (w − r) mod q, reconstructs w = (c + r) mod q
// bitwise (carry-save add + conditional q-subtract), and returns w's bits. The mask
// open is the only secret-derived reveal and it is perfectly hiding.
func (c *cscpCtx) bitDecompose(wShare shareVec) ([]shareVec, error) {
	rShare, rBits, err := c.randomBitwise()
	if err != nil {
		return nil, err
	}
	cVal, err := c.open("maskC", c.sub(wShare, rShare)) // c = (w − r) mod q, uniform
	if err != nil {
		return nil, err
	}
	sBits, err := c.bitAdd(cVal, rBits) // s = c + r, len cscpBitLen+1 (24)
	if err != nil {
		return nil, err
	}
	ltShare, err := c.bitLTSharedPub(sBits, uint32(shamirPrimeQ)) // [s < q]
	if err != nil {
		return nil, err
	}
	beta := c.notBit(ltShare) // [s ≥ q]
	wBits, err := c.bitSubBetaQ(sBits, beta, uint32(shamirPrimeQ))
	if err != nil {
		return nil, err
	}
	return wBits[:cscpBitLen], nil
}

// secureHighBitsShared returns the shared ⟨w1⟩ = ⟨HighBits(w)⟩ from a shared ⟨w⟩,
// via the boundary-count identity: w1 = (Σ_{k=1..16}[w > (2k−1)γ2]) mod 16. The
// 16 indicators reuse one bit-decomposition of ⟨w⟩; the mod-16 fold subtracts
// 16·[count==16] (an AND of all 16 indicator bits). ⟨w⟩ and ⟨w1⟩ are never opened
// here — the caller opens only ⟨w1⟩.
func (c *cscpCtx) secureHighBitsShared(wShare shareVec) (shareVec, error) {
	wBits, err := c.bitDecompose(wShare)
	if err != nil {
		return nil, err
	}
	count := c.constShare(0)
	inds := make([]shareVec, 16)
	for k := 1; k <= 16; k++ {
		b := (2*uint32(k) - 1) * c.gamma2 // public boundary (2k−1)·γ2
		ind, err := c.bitLTPubShared(b, wBits)
		if err != nil {
			return nil, err
		}
		inds[k-1] = ind
		count = c.add(count, ind)
	}
	allOne := inds[0]
	for k := 1; k < 16; k++ {
		allOne, err = c.andBit(allOne, inds[k])
		if err != nil {
			return nil, err
		}
	}
	// w1 = count − 16·[count==16]  (count ∈ [0,16]; ==16 ⇔ all indicators 1).
	return c.sub(count, c.scalarMul(16, allOne)), nil
}

// shareCommitCoeff is the additive→Shamir reshare for one commitment coefficient:
// each party Shamir-shares its own additive part g_i[coeff] at degree T−1, and the
// quorum sums the shares into a degree-(T−1) Shamir sharing ⟨w⟩ of w = Σ g_i mod q
// (the Shamir field IS q, so this is exact). ⟨w⟩ is never opened.
func (c *cscpCtx) shareCommitCoeff(parts []uint32) (shareVec, error) {
	wShare := c.constShare(0)
	for i := 0; i < c.n; i++ {
		sh, err := shamirShareScalarGFq(parts[i], c.evalPoints, c.threshold, c.rng)
		if err != nil {
			return nil, err
		}
		wShare = c.add(wShare, sh)
	}
	return wShare, nil
}

// secureHighBitsCoeff runs the full per-coefficient CSCP: additive shares (one per
// party) → ⟨w⟩ → secure HighBits → opened w1. NO node ever forms w, w0, or A0.
func (c *cscpCtx) secureHighBitsCoeff(parts []uint32) (uint32, error) {
	wShare, err := c.shareCommitCoeff(parts)
	if err != nil {
		return 0, err
	}
	w1Share, err := c.secureHighBitsShared(wShare)
	if err != nil {
		return 0, err
	}
	return c.open("w1", w1Share)
}

// ───────────────────── full-vector driver + per-node state ──────────────────────

// CSCPParticipant is one validator's persistent state for the CarryCompare step.
// Its ONLY private field is its own additive commitment share g_i (a length-K
// poly-vector). It deliberately carries no joint nonce, joint commitment, low sum,
// or low-bits field — a node never holds w, w0, or A0 (enforced by the
// forbidden-field reflection guard). The secure HighBits over the quorum's {g_i}
// forms none of those in the clear either; this struct just pins the per-node
// custody boundary.
type CSCPParticipant struct {
	mode      Mode
	nodeID    NodeID
	evalPoint uint32
	gShare    polyVec // g_i = A·(λ_i·y_i): this node's OWN additive commitment share
}

// NewCSCPParticipant builds one node's CSCP state from its single nonce share y_i
// and its public Lagrange weight over the CEF participant set. It computes the
// node's local commitment contribution g_i = A·(λ_i·y_i) and stores ONLY that.
func NewCSCPParticipant(setup *AlgSetup, nodeID NodeID, evalPoint, lambda uint32, yShare polyVec) (*CSCPParticipant, error) {
	if setup == nil {
		return nil, ErrCSCPShape
	}
	if _, _, _, ok := bccParams(setup.Mode); !ok {
		return nil, ErrCSCPParamSet
	}
	g, err := CEFCommitmentShare(setup, lambda, yShare)
	if err != nil {
		return nil, err
	}
	return &CSCPParticipant{mode: setup.Mode, nodeID: nodeID, evalPoint: evalPoint, gShare: g}, nil
}

// NodeID returns this participant's identity.
func (p *CSCPParticipant) NodeID() NodeID { return p.nodeID }

// CommitmentShare returns this node's own additive commitment share g_i — its
// private input to the CarryCompare MPC. Contributing g_i to the secure circuit is
// NOT "forming w": an additive share is independent of w.
func (p *CSCPParticipant) CommitmentShare() polyVec { return p.gShare }

// cscpSecureHighBitsVec is the REAL CarryCompare: it computes w1 = HighBits(Σ_i g_i
// mod q) coefficient-wise from the per-party additive commitment shares via the
// secure circuit, with NO node (and no driver process) ever forming w, w0, or A0 in
// the clear. commitShares[i] is party i's g_i (length K); evalPoints is parallel
// (N = len ≥ 2T−1 for honest majority). The 256·K coefficients are independent and
// run in parallel; each draws a CSPRNG stream derived from a master seed read from
// rng, so the result is reproducible and the workers are race-free. tr (optional)
// records every opened value for the leak-free proof.
func cscpSecureHighBitsVec(mode Mode, commitShares []polyVec, evalPoints []uint32, threshold int, rng io.Reader, tr *cscpTranscript) (polyVec, error) {
	gamma2, _, _, ok := bccParams(mode)
	if !ok || gamma2 != mldsaGamma2P65 {
		return nil, ErrCSCPParamSet
	}
	n := len(commitShares)
	if n == 0 || len(evalPoints) != n {
		return nil, ErrCSCPShape
	}
	if threshold < 1 || n < 2*threshold-1 {
		return nil, ErrBGWNotEnoughParties
	}
	K, _, _ := modeShape(mode)
	if K == 0 {
		return nil, ErrCSCPParamSet
	}
	for _, sh := range commitShares {
		if len(sh) != K {
			return nil, ErrCSCPShape
		}
	}
	var master [32]byte
	if _, err := io.ReadFull(rng, master[:]); err != nil {
		return nil, err
	}

	out := make(polyVec, K)
	type coeff struct{ k, j int }
	total := K * mldsaN
	jobs := make(chan coeff, total)
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			jobs <- coeff{k, j}
		}
	}
	close(jobs)

	workers := runtime.NumCPU()
	if workers > total {
		workers = total
	}
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parts := make([]uint32, n)
			for c := range jobs {
				for i := 0; i < n; i++ {
					parts[i] = commitShares[i][c.k][c.j] % mldsaQ
				}
				// Independent CSPRNG stream per coefficient (race-free, reproducible).
				var tag [8]byte
				binary.BigEndian.PutUint32(tag[0:4], uint32(c.k))
				binary.BigEndian.PutUint32(tag[4:8], uint32(c.j))
				rd := newCSCPSeedReader(append(append([]byte{}, master[:]...), tag[:]...))
				ctx, err := newCSCPCtx(mode, evalPoints, threshold, rd, tr)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				v, err := ctx.secureHighBitsCoeff(parts)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				out[c.k][c.j] = v
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errCh:
		return nil, err
	default:
	}
	return out, nil
}

// cscpSeedReader is a domain-separated SHAKE-256 CSPRNG stream used to give each
// independent coefficient its own re-sharing-randomness source from one master seed
// (so the parallel workers are race-free and the whole computation is reproducible
// from the master seed read out of the caller's secure rng).
type cscpSeedReader struct {
	seed []byte
	buf  []byte
	off  int
	ctr  uint64
}

func newCSCPSeedReader(seed []byte) *cscpSeedReader { return &cscpSeedReader{seed: seed} }

func (r *cscpSeedReader) Read(p []byte) (int, error) {
	for n := 0; n < len(p); {
		if r.off >= len(r.buf) {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			h := sha3.NewShake256()
			_, _ = h.Write([]byte("PULSAR-TALUS/cscp-stream/v1"))
			_, _ = h.Write(r.seed)
			_, _ = h.Write(c[:])
			r.buf = make([]byte, 4096)
			_, _ = h.Read(r.buf)
			r.off = 0
		}
		copied := copy(p[n:], r.buf[r.off:])
		n += copied
		r.off += copied
	}
	return len(p), nil
}

// ───────────────────── malicious-hardening residual (scoped) ────────────────────

// CSCPMaliciousResidual is the COMPUTED scope of the malicious-secure /
// identifiable-abort hardening that sits ORTHOGONALLY above the semi-honest CSCP
// built here. The leak-free + correctness properties proven in this file hold for
// the semi-honest honest-majority adversary; this descriptor states exactly what a
// malicious adversary could still do and which standard layer closes it, so the
// residual is precise, not hand-waved.
type CSCPMaliciousResidual struct {
	Mode      Mode
	Threshold int
	Parties   int

	// What the semi-honest CSCP already guarantees.
	SemiHonestLeakFree bool // no node forms w/w0/A0; only {valid, maskC (uniform), w1} open
	SemiHonestExact    bool // output == FIPS HighBits(Σ g_i) (proven on real shares)

	// What a MALICIOUS party could still do without the hardening, and the effect.
	Deviations []string

	// The standard layer that closes each deviation (TALUS Phase B).
	Hardening []string

	// Whether a wrong w1 is CAUGHT (never produces a bad signature) even semi-honest:
	// the downstream FindHint + mandatory stock-FIPS release gate reject a wrong w1,
	// so a malicious CSCP deviation is at worst a liveness fault (retry), never a
	// forged signature or a key leak.
	WrongW1IsCaughtDownstream bool
}

// AssessCSCPMalicious computes the malicious-hardening residual for a committee. It
// is the single source of truth for what the semi-honest CSCP does NOT yet cover and
// exactly how it is closed, mirroring assessCSCP / assessDealerlessFIPS.
func AssessCSCPMalicious(mode Mode, threshold, parties int) (*CSCPMaliciousResidual, error) {
	if _, _, _, ok := bccParams(mode); !ok {
		return nil, ErrBCCParamSet
	}
	minN := TalusMinPartiesMPC(threshold)
	return &CSCPMaliciousResidual{
		Mode:               mode,
		Threshold:          threshold,
		Parties:            parties,
		SemiHonestLeakFree: parties >= minN,
		SemiHonestExact:    parties >= minN,
		Deviations: []string{
			"a malicious party feeds an inconsistent re-share (degree > T−1) into a BGW multiplication, biasing an intermediate bit",
			"a malicious party contributes a non-{0,1} value as a 'random bit', skewing the mask r",
			"a malicious party opens a wrong reconstruction value for the mask c (equivocation), forcing a wrong w1",
		},
		Hardening: []string{
			"Feldman/Pedersen-committed shares with verified openings: every re-share carries a commitment; receivers check it lies on a degree-(T−1) polynomial before use (VSS)",
			"a bit-validity proof (b·(b−1)=0) on each contributed random bit, batched, with a complaint round",
			"identifiable abort: a mismatched opening names the deviating party via its signed share commitment; the honest majority excludes it and re-runs",
		},
		// Even WITHOUT the hardening, a wrong w1 cannot forge or leak: FindHint rejects
		// a w1 that no public hint reaches, and TalusReleaseGate runs mandatory stock
		// FIPS-204 verification before any signature is emitted. A malicious CSCP
		// deviation is therefore at worst a liveness fault (nonce consumed, retry).
		WrongW1IsCaughtDownstream: true,
	}, nil
}
