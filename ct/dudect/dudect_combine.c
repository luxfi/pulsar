/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_combine.c — dudect main loop driving pulsar.Combine
 * through the cgo bridge in combine_ct.go.
 *
 * Same structure as dudect_verify.c. Both dudect classes are
 * VALID Combine inputs drawn from a pre-built K-entry tape pool:
 *   class A: tape[0] (fixed)
 *   class B: tape[rand % K] (varying valid tapes)
 * Per-sample input is a 4-byte tape index (big-endian uint32).
 *
 * Earlier versions used class A = zero-bytes, class B = random
 * bytes — same anti-pattern as the old verify-side test (both
 * inputs INVALID, on different rejection paths). The valid-pool
 * design eliminates the rejection-path artifact; any timing
 * difference detected here is a real data-dependent path in
 * Combine, not a commit-mismatch artifact.
 */

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int    pulsar_combine_ct_setup(void);
extern size_t pulsar_combine_ct_pool_size(void);
extern size_t pulsar_combine_ct_input_size(void);
extern void   pulsar_combine_ct(uint8_t *data);

static size_t g_chunk_size = 0;
static size_t g_pool_size  = 0;

/*
 * Populate input_data + classes for one batch. Each per-sample
 * input is a 4-byte big-endian uint32 tape index.
 *   class A: index 0 (every sample)
 *   class B: random uniform index in [0, pool_size)
 */
void prepare_inputs(dudect_config_t *cfg, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < cfg->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *slot = input_data + (size_t)i * cfg->chunk_size;
        if (classes[i] == 0) {
            /* Class A: tape[0] (Welch's t-test requires identical
             * class-A inputs). Encode index 0 big-endian. */
            slot[0] = slot[1] = slot[2] = slot[3] = 0;
        } else {
            /* Class B: random index — the bridge reduces mod
             * pool_size. randombytes draws from dudect's RNG,
             * which is uncorrelated with anything Combine sees. */
            randombytes(slot, cfg->chunk_size);
        }
    }
}

uint8_t do_one_computation(uint8_t *data) {
    pulsar_combine_ct(data);
    uint8_t acc = 0;
    for (size_t i = 0; i < g_chunk_size; i++) acc ^= data[i];
    return acc;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    int rc = pulsar_combine_ct_setup();
    if (rc != 0) {
        fprintf(stderr, "pulsar_combine_ct_setup failed: rc=%d\n", rc);
        return 1;
    }
    g_chunk_size = pulsar_combine_ct_input_size();
    g_pool_size  = pulsar_combine_ct_pool_size();
    if (g_chunk_size == 0 || g_pool_size == 0) {
        fprintf(stderr, "pulsar_combine_ct setup returned 0 sizes\n");
        return 1;
    }

    /* Combine is heavier than Verify (full FIPS 204 Sign on the
     * reconstructed seed), so the default batch is smaller — keeps
     * the smoke test under a minute on a laptop. */
    size_t number_measurements = 2000;
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

    fprintf(stderr, "dudect_combine: ML-DSA-65 (n=3,t=2), chunk=%zu bytes, batch=%zu samples, max_batches=%zu, pool=%zu valid tapes\n",
            g_chunk_size, number_measurements, max_batches, g_pool_size);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    for (size_t batch = 0; batch < max_batches; batch++) {
        state = dudect_main(&ctx);
        if (state == DUDECT_LEAKAGE_FOUND) break;
    }
    dudect_free(&ctx);

    if (state == DUDECT_LEAKAGE_FOUND) {
        fprintf(stderr, "dudect_combine: LEAKAGE FOUND (t-statistic exceeded threshold)\n");
        return 2;
    }
    fprintf(stderr, "dudect_combine: no leakage evidence after %zu batches of %zu samples\n",
            max_batches, number_measurements);
    return 0;
}
