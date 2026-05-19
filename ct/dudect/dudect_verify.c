/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_verify.c — dudect main loop driving pulsarm.Verify through
 * the cgo bridge in verify_ct.go.
 *
 * dudect API contract: the user provides do_one_computation(data) and
 * prepare_inputs(cfg, input, classes); dudect's `dudect_main` invokes
 * them via the extern declarations at the bottom of dudect.h. See
 * https://github.com/oreparaz/dudect/blob/master/src/dudect.h
 *
 * We define DUDECT_IMPLEMENTATION exactly once before including the
 * header so the whole library compiles into this translation unit.
 *
 * dudect_compat.h is `-include`-d by the Makefile on AArch64 hosts;
 * on x86 it is a no-op.
 */

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exported by libpulsar_verify (verify_ct.go). */
extern int    pulsar_verify_ct_setup(void);
extern size_t pulsar_verify_ct_sig_size(void);
extern size_t pulsar_verify_ct_pool_size(void);
extern int    pulsar_verify_ct_copy_pool(size_t idx, uint8_t *dst);
extern void   pulsar_verify_ct(uint8_t *data);

/* Per-sample input width. Filled in main() after setup. */
static size_t g_chunk_size = 0;
static size_t g_pool_size  = 0;

/*
 * dudect API hook: populate cfg->number_measurements samples of
 * cfg->chunk_size bytes each, and assign each sample a binary class
 * label (0 = fixed class A, 1 = random class B). dudect supplies
 * randombytes() / randombit() for us — same RNG it uses internally,
 * so the class assignment is uncorrelated with anything Verify could
 * see.
 *
 * Both classes are VALID signatures on the same (pk, message) —
 * this is the OPERATIONALLY MEANINGFUL CT population for Verify
 * (valid sigs are what an attacker can observe in a real
 * exchange; Verify holds no secret, so timing differences over
 * attacker-supplied garbage are not a confidentiality property).
 * The valid-sig framing is a test-design choice, not a FIPS 204
 * standard mandate — see verify_ct.go header for the full
 * framing. Class A is always pool[0] (byte-identical across
 * class-A samples as Welch's t-test requires); class B is
 * pool[rand % pool_size] (varying valid sigs, drawn uniformly
 * from the precomputed pool).
 *
 * Any timing difference detected by dudect under this design is a
 * REAL data-dependent path in pulsar.Verify (i.e., circl's
 * mldsa65.Verify), not a rejection-path artifact.
 */
void prepare_inputs(dudect_config_t *cfg, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < cfg->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *slot = input_data + (size_t)i * cfg->chunk_size;
        if (classes[i] == 0) {
            /* Class A: pool[0] every time (Welch's t-test requires
             * identical class-A inputs). */
            (void)pulsar_verify_ct_copy_pool(0, slot);
        } else {
            /* Class B: a uniformly-drawn valid sig from the pool.
             * dudect's randombit() / randombytes() are independent
             * of anything Verify can observe. */
            uint8_t pick_buf[8];
            randombytes(pick_buf, sizeof pick_buf);
            uint64_t pick = 0;
            for (size_t k = 0; k < sizeof pick_buf; k++) {
                pick = (pick << 8) | pick_buf[k];
            }
            (void)pulsar_verify_ct_copy_pool((size_t)(pick % g_pool_size), slot);
        }
    }
}

/*
 * dudect API hook: one measurement sample. Must depend on `data` (so
 * the compiler cannot dead-code-eliminate the body), must NOT branch
 * on `data` (or we measure our own branch, not Verify's), and must
 * return a uint8_t that flows out of the function so the result is
 * observed.
 */
uint8_t do_one_computation(uint8_t *data) {
    pulsar_verify_ct(data);
    uint8_t acc = 0;
    for (size_t i = 0; i < g_chunk_size; i++) acc ^= data[i];
    return acc;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    int rc = pulsar_verify_ct_setup();
    if (rc != 0) {
        fprintf(stderr, "pulsar_verify_ct_setup failed: rc=%d\n", rc);
        return 1;
    }
    g_chunk_size = pulsar_verify_ct_sig_size();
    if (g_chunk_size == 0) {
        fprintf(stderr, "pulsar_verify_ct_sig_size returned 0\n");
        return 1;
    }
    g_pool_size = pulsar_verify_ct_pool_size();
    if (g_pool_size == 0) {
        fprintf(stderr, "pulsar_verify_ct_pool_size returned 0\n");
        return 1;
    }

    /*
     * SMOKE-TEST default (10 000 samples per batch). The full NIST
     * submission run uses ~10^9 samples on a quiet, CPU-pinned host.
     * Override per-batch sample count with DUDECT_SAMPLES, and limit
     * total batches with DUDECT_MAX_BATCHES so smoke tests terminate
     * even when the t-test stays under threshold.
     */
    size_t number_measurements = 10000;
    const char *env_n = getenv("DUDECT_SAMPLES");
    if (env_n) {
        long n = strtol(env_n, NULL, 10);
        if (n > 0) number_measurements = (size_t)n;
    }
    size_t max_batches = 4;
    const char *env_b = getenv("DUDECT_MAX_BATCHES");
    if (env_b) {
        long b = strtol(env_b, NULL, 10);
        if (b > 0) max_batches = (size_t)b;
    }

    dudect_config_t cfg = {
        .chunk_size = g_chunk_size,
        .number_measurements = number_measurements,
    };
    dudect_ctx_t ctx;
    if (dudect_init(&ctx, &cfg) != 0) {
        fprintf(stderr, "dudect_init failed\n");
        return 1;
    }

    fprintf(stderr, "dudect_verify: ML-DSA-65, chunk=%zu bytes, batch=%zu samples, max_batches=%zu, pool=%zu valid sigs\n",
            g_chunk_size, number_measurements, max_batches, g_pool_size);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    for (size_t batch = 0; batch < max_batches; batch++) {
        state = dudect_main(&ctx);
        if (state == DUDECT_LEAKAGE_FOUND) break;
    }
    dudect_free(&ctx);

    if (state == DUDECT_LEAKAGE_FOUND) {
        fprintf(stderr, "dudect_verify: LEAKAGE FOUND (t-statistic exceeded threshold)\n");
        return 2;
    }
    fprintf(stderr, "dudect_verify: no leakage evidence after %zu batches of %zu samples\n",
            max_batches, number_measurements);
    return 0;
}
