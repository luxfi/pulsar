/* SPDX-License-Identifier: Apache-2.0 OR ISC
 *
 * Thin C wrapper exposing pq-crystals/dilithium reference FIPS 204
 * verification under stable, non-namespaced symbol names that the
 * cgo binding in verifier.go can call without redeclaring every
 * pq-crystals symbol.
 *
 * Each function returns 0 on a verified signature, non-zero on
 * rejection. This is the same return convention as upstream
 * crypto_sign_verify (FIPS 204 ML-DSA.Verify accept = return 0).
 *
 * The wrapper bridges only the verification surface — keygen and
 * sign live in the underlying static archive but are not exposed
 * here. The "independent verifier" discipline requires this
 * binding to be incapable of producing signatures of its own;
 * it can only accept or reject the byte string under inspection.
 */

#ifndef LUX_PULSAR_PQ_CRYSTALS_VERIFY_H
#define LUX_PULSAR_PQ_CRYSTALS_VERIFY_H

#include <stddef.h>
#include <stdint.h>

/* Public key sizes per FIPS 204 §3.5.5.
 * ML-DSA-44 = 1312, ML-DSA-65 = 1952, ML-DSA-87 = 2592.
 * Signature sizes per FIPS 204 §3.5.5.
 * ML-DSA-44 = 2420, ML-DSA-65 = 3309, ML-DSA-87 = 4627.
 */
#define LUX_PULSAR_MLDSA44_PK_BYTES   1312
#define LUX_PULSAR_MLDSA44_SIG_BYTES  2420
#define LUX_PULSAR_MLDSA65_PK_BYTES   1952
#define LUX_PULSAR_MLDSA65_SIG_BYTES  3309
#define LUX_PULSAR_MLDSA87_PK_BYTES   2592
#define LUX_PULSAR_MLDSA87_SIG_BYTES  4627

#ifdef __cplusplus
extern "C" {
#endif

/* Verify an ML-DSA-44 signature under the pq-crystals/dilithium
 * reference FIPS 204 verifier (DILITHIUM_MODE=2).
 *
 *   pk         FIPS 204 §3.5.5 public key, must be LUX_PULSAR_MLDSA44_PK_BYTES.
 *   sig        signature, must be LUX_PULSAR_MLDSA44_SIG_BYTES.
 *   msg, mlen  message bytes.
 *   ctx, ctxlen ML-DSA context string (may be NULL with ctxlen=0).
 *
 * Returns 0 if the signature verifies, non-zero otherwise.
 */
int lux_pulsar_pqc_verify_mldsa44(const uint8_t *pk,
                                  const uint8_t *sig, size_t siglen,
                                  const uint8_t *msg, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen);

/* Verify an ML-DSA-65 signature (DILITHIUM_MODE=3). See above. */
int lux_pulsar_pqc_verify_mldsa65(const uint8_t *pk,
                                  const uint8_t *sig, size_t siglen,
                                  const uint8_t *msg, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen);

/* Verify an ML-DSA-87 signature (DILITHIUM_MODE=5). See above. */
int lux_pulsar_pqc_verify_mldsa87(const uint8_t *pk,
                                  const uint8_t *sig, size_t siglen,
                                  const uint8_t *msg, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen);

#ifdef __cplusplus
}
#endif

#endif /* LUX_PULSAR_PQ_CRYSTALS_VERIFY_H */
