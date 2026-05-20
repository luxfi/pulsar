/* SPDX-License-Identifier: Apache-2.0 OR ISC
 *
 * Thin C bridge from the cgo binding to the pq-crystals/dilithium
 * reference FIPS 204 verifier. The actual verification is the
 * unmodified upstream `pqcrystals_dilithium{2,3,5}_ref_verify`
 * routine; this file only renames the per-parameter-set symbols
 * to a stable surface so cgo does not need to know the namespacing
 * convention.
 *
 * Each parameter set lives in the static archive built by fetch.sh:
 *   libpqcrystals_dilithium.a
 * which packs sign.c / packing.c / polyvec.c / poly.c / ntt.c /
 * reduce.c / rounding.c at DILITHIUM_MODE=2,3,5, plus
 * fips202.c + symmetric-shake.c shared.
 *
 * The upstream API:
 *
 *   int pqcrystals_dilithium{N}_ref_verify(
 *           const uint8_t *sig, size_t siglen,
 *           const uint8_t *m,   size_t mlen,
 *           const uint8_t *ctx, size_t ctxlen,
 *           const uint8_t *pk);
 *
 * Returns 0 on accept, non-zero on reject. We pass it through
 * unchanged with the argument order rearranged so the Go-side
 * caller can pass (pk, sig, msg, ctx) in the same order it does
 * for the cloudflare/circl verifier.
 */

#include <stddef.h>
#include <stdint.h>

#include "pq_crystals_verify.h"

/* Forward declarations for the namespaced upstream symbols. We
 * deliberately do NOT include pq-crystals' api.h here — that header
 * carries the upstream parameter macros, but the symbol declarations
 * with their unambiguous size assumptions are clearer when stated
 * directly. The pq-crystals header would also drag in `<stddef.h>`
 * and platform-shape includes that are not needed here.
 */
extern int pqcrystals_dilithium2_ref_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk);
extern int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk);
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk);

int lux_pulsar_pqc_verify_mldsa44(const uint8_t *pk,
                                  const uint8_t *sig, size_t siglen,
                                  const uint8_t *msg, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen) {
    if (siglen != LUX_PULSAR_MLDSA44_SIG_BYTES) {
        return -1;
    }
    return pqcrystals_dilithium2_ref_verify(sig, siglen,
                                            msg, mlen,
                                            ctx, ctxlen,
                                            pk);
}

int lux_pulsar_pqc_verify_mldsa65(const uint8_t *pk,
                                  const uint8_t *sig, size_t siglen,
                                  const uint8_t *msg, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen) {
    if (siglen != LUX_PULSAR_MLDSA65_SIG_BYTES) {
        return -1;
    }
    return pqcrystals_dilithium3_ref_verify(sig, siglen,
                                            msg, mlen,
                                            ctx, ctxlen,
                                            pk);
}

int lux_pulsar_pqc_verify_mldsa87(const uint8_t *pk,
                                  const uint8_t *sig, size_t siglen,
                                  const uint8_t *msg, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen) {
    if (siglen != LUX_PULSAR_MLDSA87_SIG_BYTES) {
        return -1;
    }
    return pqcrystals_dilithium5_ref_verify(sig, siglen,
                                            msg, mlen,
                                            ctx, ctxlen,
                                            pk);
}
