// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// mldsa_lattice.go — FIPS 204 lattice primitives used by the threshold
// path (threshold.go) and the single-key BCC signer (bcc_sign.go).
//
// This file is a self-contained re-implementation of the polynomial-
// ring arithmetic needed for FIPS 204 ML-DSA signing. It mirrors the
// cloudflare/circl implementation byte-for-byte at the value level so
// that the threshold signer can produce signatures byte-identical to
// single-party mldsa{44,65,87}.SignTo. The reference for these
// constructions is FIPS 204 (NIST PQC Round 4 ML-DSA spec).
//
// Why re-implement instead of importing circl/internal/dilithium: the
// circl internal package is intentionally not exported. The threshold
// signer needs to operate on polynomial shares directly — the circl
// public API only exposes seed-derived signing, which is exactly what
// the threshold path must avoid. Re-implementing the primitives here
// gives us a single auditable surface within the pulsar package.
//
// All primitives in this file are package-private; the public signing
// surface lives in threshold.go and bcc_sign.go.
//
// The FIPS 204 SHAKE samplers (ExpandA/ExpandS/ExpandMask/SampleInBall)
// that formerly lived here are now consumed from the canonical
// github.com/luxfi/mlwe/sample/shake copy via the adapters in
// mldsa_sample.go — byte-identical, since mlwe was lifted from this file.

// Ring parameters per FIPS 204 §4. These are fixed across all three
// parameter sets (Pulsar-44, Pulsar-65, Pulsar-87).
const (
	mldsaN            = 256        // ring degree
	mldsaQ            = 8380417    // 2²³ - 2¹³ + 1
	mldsaQinv         = 4236238847 // -(q⁻¹) mod 2³²
	mldsaROver256     = 41978      // (256)⁻¹ · R² mod q, R = 2³²
	mldsaD            = 13         // dropped low bits
	mldsaTRSize       = 64         // FIPS 204 ML-DSA SHAKE-256 hash of pk
	mldsaCTildeSize   = 48         // ML-DSA-65 c̃ length (λ=192 ⇒ λ/4)
	mldsaCTildeSize44 = 32         // ML-DSA-44 c̃ length (λ=128 ⇒ λ/4)
	mldsaCTildeSize87 = 64         // ML-DSA-87 c̃ length (λ=256 ⇒ λ/4)
	mldsaGamma2P65    = 261888     // (q-1)/32 for ML-DSA-65/87
	mldsaGamma2P44    = 95232      // (q-1)/88 for ML-DSA-44
)

// poly is the ML-DSA polynomial in R_q = Z_q[X]/(X^256 + 1). Coefficients
// are stored mod q (or mod 2q in transient states); per-coefficient
// arithmetic is performed in either Montgomery form (during NTT-domain
// work) or standard form.
type poly [mldsaN]uint32

// vecK and vecL hold the FIPS 204 module vectors of length K and L for
// each parameter set. Sized via slices since K and L vary by mode.
type polyVec []poly

// reduceLe2Q computes y < 2q with y ≡ x (mod q).
//
// Identical to circl's ReduceLe2Q. Constant-time (no data-dependent
// branches; the shift-and-add operates on the full machine word).
func reduceLe2Q(x uint32) uint32 {
	x1 := x >> 23
	x2 := x & 0x7FFFFF
	return x2 + (x1 << 13) - x1
}

// le2qModQ computes x mod q for 0 ≤ x < 2q.
func le2qModQ(x uint32) uint32 {
	x -= mldsaQ
	mask := uint32(int32(x) >> 31)
	return x + (mask & mldsaQ)
}

// modQ computes x mod q. Two-step reduction.
func modQ(x uint32) uint32 { return le2qModQ(reduceLe2Q(x)) }

// montReduceLe2Q reduces x · R⁻¹ mod q assuming x · R ≤ q · 2³². The
// result is in [0, 2q).
func montReduceLe2Q(x uint64) uint32 {
	m := (x * mldsaQinv) & 0xffffffff
	return uint32((x + m*uint64(mldsaQ)) >> 32)
}

// power2round returns a₀ + q and a₁ with a = a₁·2^D + a₀ and -2^(D-1)
// < a₀ ≤ 2^(D-1). Used for the FIPS 204 Power2Round step in keygen.
func power2round(a uint32) (a0plusQ, a1 uint32) {
	a0 := a & ((1 << mldsaD) - 1)
	a0 -= (1 << (mldsaD - 1)) + 1
	a0 += uint32(int32(a0)>>31) & (1 << mldsaD)
	a0 -= (1 << (mldsaD - 1)) - 1
	a0plusQ = mldsaQ + a0
	a1 = (a - a0) >> mldsaD
	return
}

// Decompose splits 0 ≤ a < q into a₀, a₁ with a = a₁α + a₀ for α = 2γ₂.
//
// For Pulsar-65/87 (γ₂ = (q-1)/32 = 261888, α = 523776, a₁ ∈ [0, 16)).
// For Pulsar-44 (γ₂ = (q-1)/88 = 95232, α = 190464, a₁ ∈ [0, 44)).
//
// Returns a₀ + q (always in [1, q) for normalized input) and a₁.
func decompose(a uint32, gamma2 uint32) (a0plusQ, a1 uint32) {
	a1 = (a + 127) >> 7
	if gamma2 == mldsaGamma2P65 {
		// α = 523776 = (q-1)/16 · 2, a₁ ∈ [0,16)
		a1 = (a1*1025 + (1 << 21)) >> 22
		a1 &= 15
	} else if gamma2 == mldsaGamma2P44 {
		a1 = (a1*11275 + (1 << 23)) >> 24
		a1 ^= uint32(int32(43-a1)>>31) & a1
	} else {
		// Unsupported γ₂ — caller's responsibility to gate.
		return 0, 0
	}
	alpha := 2 * gamma2
	a0plusQ = a - a1*alpha
	a0plusQ += uint32(int32(a0plusQ-(mldsaQ-1)/2)>>31) & mldsaQ
	return
}

// polyReduceLe2Q normalises all coefficients of p to < 2q in place.
func (p *poly) reduceLe2Q() {
	for i := 0; i < mldsaN; i++ {
		p[i] = reduceLe2Q(p[i])
	}
}

// polyNormalize reduces each coefficient to [0, q).
func (p *poly) normalize() {
	for i := 0; i < mldsaN; i++ {
		p[i] = modQ(p[i])
	}
}

// polyAdd sets p = a + b (per-coefficient, no reduction).
func (p *poly) add(a, b *poly) {
	for i := 0; i < mldsaN; i++ {
		p[i] = a[i] + b[i]
	}
}

// polySub sets p = a - b mod 2q assuming coefficients of b are < 2q.
func (p *poly) sub(a, b *poly) {
	for i := 0; i < mldsaN; i++ {
		p[i] = a[i] + (2*mldsaQ - b[i])
	}
}

// polyMulHat sets p = a · b pointwise (NTT-domain pointwise mul).
// Assumes a and b are in Montgomery form and coefficients sufficiently
// small that a[i]·b[i] < 2³² · q.
func (p *poly) mulHat(a, b *poly) {
	for i := 0; i < mldsaN; i++ {
		p[i] = montReduceLe2Q(uint64(a[i]) * uint64(b[i]))
	}
}

// polyExceeds reports whether the "supnorm" of p (max central-rep
// absolute coefficient value) is ≥ bound. Assumes p is normalised.
// Constant-time over WHICH coefficient breaks (the FIPS 204 spec
// explicitly allows leaking position-of-break under rejection
// sampling, but not the value).
func (p *poly) exceeds(bound uint32) bool {
	for i := 0; i < mldsaN; i++ {
		x := int32((mldsaQ-1)/2) - int32(p[i])
		x ^= x >> 31
		x = int32((mldsaQ-1)/2) - x
		if uint32(x) >= bound {
			return true
		}
	}
	return false
}

// polyMulBy2toD sets p = 2^D · q. Caller must ensure coefficients fit
// in 32 bits after shift (i.e. < 2^(32-D)).
func (p *poly) mulBy2toD(q *poly) {
	for i := 0; i < mldsaN; i++ {
		p[i] = q[i] << mldsaD
	}
}

// polyPower2Round splits p into p0PlusQ and p1 per FIPS 204
// Power2Round. Requires p normalised.
func (p *poly) power2Round(p0PlusQ, p1 *poly) {
	for i := 0; i < mldsaN; i++ {
		p0PlusQ[i], p1[i] = power2round(p[i])
	}
}

// polyDotHat sets p = Σ_i a[i] · b[i] pointwise in Montgomery form.
// Coefficients of result bounded by 2|a|·q.
func polyDotHat(p *poly, a, b polyVec) {
	if len(a) != len(b) {
		// caller's contract — panic acceptable at this internal call site
		panic("pulsar: polyDotHat length mismatch")
	}
	var t poly
	*p = poly{}
	for i := range a {
		t.mulHat(&a[i], &b[i])
		p.add(&t, p)
	}
}

// nttZetas / nttInvZetas: powers of the 512th root of unity zeta=1753
// in Montgomery form per FIPS 204 §3.6. These are the canonical FIPS
// 204 NTT constants, byte-identical to circl/internal/dilithium.Zetas
// and InvZetas.
var nttZetas = [mldsaN]uint32{
	4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169,
	466468, 1826347, 2353451, 8021166, 6288512, 3119733, 5495562,
	3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929,
	7260833, 2619752, 6271868, 6262231, 4520680, 6980856, 5102745,
	1757237, 8360995, 4010497, 280005, 2706023, 95776, 3077325,
	3530437, 6718724, 4788269, 5842901, 3915439, 4519302, 5336701,
	3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150,
	6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
	811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892,
	5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950,
	2176455, 6795196, 7122806, 1939314, 4296819, 7380215, 5190273,
	5223087, 4747489, 126922, 3412210, 7396998, 2147896, 2715295,
	5412772, 4686924, 7969390, 5903370, 7709315, 7151892, 8357436,
	7072248, 7998430, 1349076, 1852771, 6949987, 5037034, 264944,
	508951, 3097992, 44288, 7280319, 904516, 3958618, 4656075,
	8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561,
	189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589,
	1341330, 1285669, 6795489, 7567685, 6940675, 5361315, 4499357,
	4751448, 3839961, 2091667, 3407706, 2316500, 3817976, 5037939,
	2244091, 5933984, 4817955, 266997, 2434439, 7144689, 3513181,
	4860065, 4621053, 7183191, 5187039, 900702, 1859098, 909542,
	819034, 495491, 6767243, 8337157, 7857917, 7725090, 5257975,
	2031748, 3207046, 4823422, 7855319, 7611795, 4784579, 342297,
	286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
	2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353,
	1595974, 4613401, 1250494, 2635921, 4832145, 5386378, 1869119,
	1903435, 7329447, 7047359, 1237275, 5062207, 6950192, 7929317,
	1312455, 3306115, 6417775, 7100756, 1917081, 5834105, 7005614,
	1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241,
	6533464, 5796124, 4656147, 594136, 4603424, 6366809, 2432395,
	2454455, 8215696, 1957272, 3369112, 185531, 7173032, 5196991,
	162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310,
	5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735,
	472078, 7953734, 1723600, 6577327, 1910376, 6712985, 7276084,
	8119771, 4546524, 5441381, 6144432, 7959518, 6094090, 183443,
	7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208,
	3937738, 1400424, 7534263, 1976782,
}

var nttInvZetas = [mldsaN]uint32{
	6403635, 846154, 6979993, 4442679, 1362209, 48306, 4460757,
	554416, 3545687, 6767575, 976891, 8196974, 2286327, 420899,
	2235985, 2939036, 3833893, 260646, 1104333, 1667432, 6470041,
	1803090, 6656817, 426683, 7908339, 6662682, 975884, 6167306,
	8110657, 4513516, 4856520, 3038916, 1799107, 3694233, 6727783,
	7570268, 5366416, 6764025, 8217573, 3183426, 1207385, 8194886,
	5011305, 6423145, 164721, 5925962, 5948022, 2013608, 3776993,
	7786281, 3724270, 2584293, 1846953, 1671176, 2831860, 542412,
	4974386, 6144537, 7603226, 6880252, 1374803, 2546312, 6463336,
	1279661, 1962642, 5074302, 7067962, 451100, 1430225, 3318210,
	7143142, 1333058, 1050970, 6476982, 6511298, 2994039, 3548272,
	5744496, 7129923, 3767016, 6784443, 5894064, 7132797, 4325093,
	7115408, 2590150, 5688936, 5538076, 8177373, 6644538, 3342277,
	4943130, 4272102, 2437823, 8093429, 8038120, 3595838, 768622,
	525098, 3556995, 5173371, 6348669, 3122442, 655327, 522500,
	43260, 1613174, 7884926, 7561383, 7470875, 6521319, 7479715,
	3193378, 1197226, 3759364, 3520352, 4867236, 1235728, 5945978,
	8113420, 3562462, 2446433, 6136326, 3342478, 4562441, 6063917,
	4972711, 6288750, 4540456, 3628969, 3881060, 3019102, 1439742,
	812732, 1584928, 7094748, 7039087, 7064828, 177440, 2409325,
	1851402, 5220671, 3553272, 8190869, 1316856, 7620448, 210977,
	5991061, 3249728, 6727353, 8578, 3724342, 4421799, 7475901,
	1100098, 8336129, 5282425, 7871466, 8115473, 3343383, 1430430,
	6527646, 7031341, 381987, 1308169, 22981, 1228525, 671102,
	2477047, 411027, 3693493, 2967645, 5665122, 6232521, 983419,
	4968207, 8253495, 3632928, 3157330, 3190144, 1000202, 4083598,
	6441103, 1257611, 1585221, 6203962, 4904467, 1452451, 3041255,
	3677745, 1528703, 3930395, 2797779, 6308525, 2556880, 4479693,
	4499374, 7426187, 7849063, 7568473, 4680821, 1600420, 2140649,
	4873154, 3821735, 4874723, 1643818, 1699267, 539299, 6031717,
	300467, 4840449, 2867647, 4805995, 3043716, 3861115, 4464978,
	2537516, 3592148, 1661693, 4849980, 5303092, 8284641, 5674394,
	8100412, 4369920, 19422, 6623180, 3277672, 1399561, 3859737,
	2118186, 2108549, 5760665, 1119584, 549488, 4794489, 1079900,
	7356305, 5654953, 5700314, 5268920, 2884855, 5260684, 2091905,
	359251, 6026966, 6554070, 7913949, 876248, 777960, 8143293,
	518909, 2608894, 8354570, 4186625,
}

// polyNTT executes the in-place forward NTT on p. Assumes coefficients
// are in Montgomery representation and bounded by 2q. Output coefficients
// bounded by 18q.
func (p *poly) ntt() {
	k := 0
	for l := uint(mldsaN / 2); l > 0; l >>= 1 {
		for offset := uint(0); offset < mldsaN-l; offset += 2 * l {
			k++
			zeta := uint64(nttZetas[k])
			for j := offset; j < offset+l; j++ {
				t := montReduceLe2Q(zeta * uint64(p[j+l]))
				p[j+l] = p[j] + (2*mldsaQ - t)
				p[j] += t
			}
		}
	}
}

// polyInvNTT executes the in-place inverse NTT on p and multiplies by
// the Montgomery factor R. Coefficients in Montgomery form, bounded by
// 2q.
func (p *poly) invNTT() {
	k := 0
	for l := uint(1); l < mldsaN; l <<= 1 {
		for offset := uint(0); offset < mldsaN-l; offset += 2 * l {
			zeta := uint64(nttInvZetas[k])
			k++
			for j := offset; j < offset+l; j++ {
				t := p[j]
				p[j] = t + p[j+l]
				t += 256*mldsaQ - p[j+l]
				p[j+l] = montReduceLe2Q(zeta * uint64(t))
			}
		}
	}
	for j := 0; j < mldsaN; j++ {
		p[j] = montReduceLe2Q(mldsaROver256 * uint64(p[j]))
	}
}

// polyPackLeGamma1 packs p (coefficients in (-γ₁, γ₁]) into buf using
// gamma1Bits+1 bits per coefficient.
func polyPackLeGamma1(p *poly, buf []byte, gamma1Bits uint32) {
	gamma1 := uint32(1) << gamma1Bits
	if gamma1Bits == 17 {
		j := 0
		size := 18 * mldsaN / 8
		for i := 0; i+9 <= size; i += 9 {
			p0 := gamma1 - p[j]
			p0 += uint32(int32(p0)>>31) & mldsaQ
			p1 := gamma1 - p[j+1]
			p1 += uint32(int32(p1)>>31) & mldsaQ
			p2 := gamma1 - p[j+2]
			p2 += uint32(int32(p2)>>31) & mldsaQ
			p3 := gamma1 - p[j+3]
			p3 += uint32(int32(p3)>>31) & mldsaQ
			buf[i+0] = byte(p0)
			buf[i+1] = byte(p0 >> 8)
			buf[i+2] = byte(p0>>16) | byte(p1<<2)
			buf[i+3] = byte(p1 >> 6)
			buf[i+4] = byte(p1>>14) | byte(p2<<4)
			buf[i+5] = byte(p2 >> 4)
			buf[i+6] = byte(p2>>12) | byte(p3<<6)
			buf[i+7] = byte(p3 >> 2)
			buf[i+8] = byte(p3 >> 10)
			j += 4
		}
	} else if gamma1Bits == 19 {
		j := 0
		size := 20 * mldsaN / 8
		for i := 0; i+5 <= size; i += 5 {
			p0 := gamma1 - p[j]
			p0 += uint32(int32(p0)>>31) & mldsaQ
			p1 := gamma1 - p[j+1]
			p1 += uint32(int32(p1)>>31) & mldsaQ
			buf[i+0] = byte(p0)
			buf[i+1] = byte(p0 >> 8)
			buf[i+2] = byte(p0>>16) | byte(p1<<4)
			buf[i+3] = byte(p1 >> 4)
			buf[i+4] = byte(p1 >> 12)
			j += 2
		}
	}
}

// polyPackT1 packs p (coefficients ≤ 2^(QBits-D) = 2^10) into buf at
// 10 bits per coefficient. PolyT1Size = N · (QBits-D) / 8 = N · 10/8 = 320.
func polyPackT1(p *poly, buf []byte) {
	for i := 0; i < mldsaN/4; i++ {
		buf[5*i+0] = byte(p[4*i+0])
		buf[5*i+1] = byte(p[4*i+0]>>8) | byte(p[4*i+1]<<2)
		buf[5*i+2] = byte(p[4*i+1]>>6) | byte(p[4*i+2]<<4)
		buf[5*i+3] = byte(p[4*i+2]>>4) | byte(p[4*i+3]<<6)
		buf[5*i+4] = byte(p[4*i+3] >> 2)
	}
}

// polyPackT0 packs p (centred-rep coefficients in (-2^(D-1), 2^(D-1)])
// into buf at D=13 bits per coefficient. PolyT0Size = N · D / 8 = 416.
func polyPackT0(p *poly, buf []byte) {
	const halfD = 1 << (mldsaD - 1)
	for i := 0; i < mldsaN/8; i++ {
		var t [8]uint32
		for j := 0; j < 8; j++ {
			t[j] = halfD - p[8*i+j] + mldsaQ
			t[j] = ((t[j] >> 31) & mldsaQ) + t[j]
			// Now t[j] is in [0, 2^D)
		}
		buf[13*i+0] = byte(t[0])
		buf[13*i+1] = byte(t[0]>>8) | byte(t[1]<<5)
		buf[13*i+2] = byte(t[1] >> 3)
		buf[13*i+3] = byte(t[1]>>11) | byte(t[2]<<2)
		buf[13*i+4] = byte(t[2]>>6) | byte(t[3]<<7)
		buf[13*i+5] = byte(t[3] >> 1)
		buf[13*i+6] = byte(t[3]>>9) | byte(t[4]<<4)
		buf[13*i+7] = byte(t[4] >> 4)
		buf[13*i+8] = byte(t[4]>>12) | byte(t[5]<<1)
		buf[13*i+9] = byte(t[5]>>7) | byte(t[6]<<6)
		buf[13*i+10] = byte(t[6] >> 2)
		buf[13*i+11] = byte(t[6]>>10) | byte(t[7]<<3)
		buf[13*i+12] = byte(t[7] >> 5)
	}
}

// polyPackW1 packs the high-bits polynomial p into buf for the
// challenge hash. The packing width depends on γ₂.
//
//	γ₂ = 261888: 4-bit packing (PolyW1Size = N/2 = 128 bytes/poly).
//	γ₂ =  95232: 6-bit packing (PolyW1Size = N · 6 / 8 = 192).
func polyPackW1(p *poly, buf []byte, gamma2 uint32) {
	if gamma2 == mldsaGamma2P65 {
		for i := 0; i < mldsaN/2; i++ {
			buf[i] = byte(p[2*i]) | byte(p[2*i+1]<<4)
		}
	} else if gamma2 == mldsaGamma2P44 {
		for i := 0; i < mldsaN/4; i++ {
			buf[3*i+0] = byte(p[4*i+0]) | byte(p[4*i+1]<<6)
			buf[3*i+1] = byte(p[4*i+1]>>2) | byte(p[4*i+2]<<4)
			buf[3*i+2] = byte(p[4*i+2]>>4) | byte(p[4*i+3]<<2)
		}
	}
}

// polyVecPackHint packs the K-vector hint into buf of length omega+K.
func polyVecPackHint(v polyVec, buf []byte, omega int) {
	off := uint8(0)
	for i := range v {
		for j := uint16(0); j < mldsaN; j++ {
			if v[i][j] != 0 {
				buf[off] = uint8(j)
				off++
			}
		}
		buf[omega+i] = off
	}
	for ; off < uint8(omega); off++ {
		buf[off] = 0
	}
}
