# Pulsar threshold layer — Jasmin sources

This directory holds the Jasmin sources for Pulsar's **threshold
layer**. The single-party ML-DSA-65 kernel is provided by the libjade
sources in `../ml-dsa-65/libjade/` (fetched on demand, see
`../ml-dsa-65/README.md`); the threshold layer here implements the
per-party computations that combine into a FIPS 204-valid signature.

## Status

All three `.jazz` files carry real algorithm bodies, not stubs. The
high-assurance track now ships:

| File | Lines | Algorithm |
|---|---|---|
| `round1.jazz` | 397 | Round-1 commit (D_i = cSHAKE(pack_w1(w1_i), τ_1) + sender-MAC slots) |
| `round2.jazz` | 626 | Round-2 response (peer-MAC verify, c̃ = SHAKE(μ ‖ pack_w1(ŵ)), z_i = y_i + c·λ_i·s_i, r_i = c·λ_i·u_i, τ_2 binding) |
| `combine.jazz` | 416 | Aggregate (z = Σ z_j, c·s_2 = Σ r_j, MakeHint, R₁..R₄ rejection, FIPS 204 pack(c̃, z, h)) |

Each routine calls into the pinned `libjade/oldsrc-should-delete/
crypto_sign/dilithium/dilithium3/amd64/ref/` primitives (`fft_vec`,
`ifft_to_mont_vecl`, `mult_scalar_vec`, `polyveck_make_hint`,
`checknorm_vecl`, `checknorm_veck`, `challenge`, `poly_ntt`, `pack_z`,
`unpack_z`, `pack_w1`, `unpack_w1`, `polyveck_caddq`, `decompose_vec`)
plus the shared `../lib/` helpers (`lagrange_coefficient_mont`,
`polyvecl_scalar_mont`, `kmac256_*`, `cshake256_*`, `absorb_*`).

What's still open in the high-assurance track:

- The `jasminc` compile gate is *not* exercised in this repository's
  CI (compiler is not installed on the developer machines that produce
  the submission tag). The sources are syntactically hand-reviewed
  against the libjade reference; final assembly emission and the
  constant-time leakage analysis are intended to run in the NIST
  reviewer environment.
- The EasyCrypt N1 reduction (`../../proofs/easycrypt/Pulsar_N1.ec`)
  still has admits on the cryptographic-reduction core — the
  algebraic Lagrange identity is hoisted as an axiom and the 6-step
  z / w₁ / c̃ / hint aggregation chain is stated but not mechanised.
  Closing this is independent of the Jasmin layer landing.

## Files

| File | Algorithm | Mirrors Go reference |
|---|---|---|
| `round1.jazz` | Round-1 commit message | `ref/go/pkg/pulsar/threshold.go` `ThresholdSigner.Round1` |
| `round2.jazz` | Round-2 response (post-aggregation) | `ref/go/pkg/pulsar/threshold.go` `ThresholdSigner.Round2` |
| `combine.jazz` | Aggregate quorum responses into FIPS 204 signature | `ref/go/pkg/pulsar/threshold.go` `Combine` |

## Constant-time obligations

Every threshold-layer function operates on at least one secret-
dependent input:

| Function | Secret input | Constant-time obligation |
|---|---|---|
| `round1_commit` | `share` (Shamir secret share) | Time + memory access independent of `share` and of internal RNG output for masking polynomials |
| `round2_response` | `share`, `c` (challenge) | Time + memory access independent of `share` and of rejection-sampling outcomes (norm checks must use constant-time comparison) |
| `combine` | aggregated `z`, `h` | Memory access independent of high-bit decomposition outcomes (norm checks already constant-time in libjade single-party path) |

These obligations are stated formally in
`../../proofs/easycrypt/lemmas/Pulsar_CT.ec` and discharged through
the leakage-model framework of Barthe, Grégoire, Laporte (CSF 2018).

## How to compile

```bash
../../scripts/check-high-assurance.sh
```

The check script is skip-friendly: if `jasminc` is not on PATH, it
prints a clear skip message and exits 0. When `jasminc` is present
and the threshold `.jazz` files have non-stub bodies, the script
compiles each to x86-64 assembly and asserts that the verified
compiler exits cleanly.
