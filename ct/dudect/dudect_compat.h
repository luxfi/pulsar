/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_compat.h — minimal x86-intrinsic compatibility shim for
 * AArch64 hosts.
 *
 * Upstream dudect.h (https://github.com/oreparaz/dudect) hard-codes
 * x86 intrinsics for cycle counting:
 *
 *   _mm_mfence()  — memory barrier
 *   __rdtsc()     — read time-stamp counter
 *
 * On AArch64 hosts (Apple Silicon, AWS Graviton, etc.), these are
 * not available. This shim supplies equivalents.
 *
 * Counter source by OS:
 *   - Linux/AArch64: CNTVCT_EL0 — the AArch64 generic timer counter.
 *     Readable from EL0 on every supported kernel. Monotonic.
 *     Frequency from CNTFRQ_EL0 (typically 50-100 MHz; the resulting
 *     resolution is coarser than RDTSC but the t-test is dimensionless
 *     in counter units so the constant-time verdict is unchanged.)
 *   - Darwin/AArch64 (Apple Silicon): CNTVCT_EL0 is exposed but reads
 *     in user mode have been observed to return non-monotonic values
 *     (the timer is virtualised differently per-process). We use
 *     mach_absolute_time() instead, which the XNU kernel guarantees is
 *     monotonic and high-resolution. The tick frequency is exposed via
 *     mach_timebase_info but we don't normalise — dudect operates on
 *     raw deltas only.
 *
 * The shim is included BEFORE dudect.h via -include, so it intercepts
 * the x86 headers (<emmintrin.h>, <x86intrin.h>) by providing the
 * symbols dudect needs without ever pulling in the SSE/AVX
 * headerset.
 */

#ifndef DUDECT_COMPAT_H
#define DUDECT_COMPAT_H

#if defined(__aarch64__)

#include <stdint.h>

/*
 * Replace x86 intrinsic headers with empty stubs on ARM64 so dudect.h
 * can include them as written.
 */
#define _EMMINTRIN_H_INCLUDED
#define __EMMINTRIN_H
#define _IMMINTRIN_H_INCLUDED
#define _X86INTRIN_H_INCLUDED
#define __X86INTRIN_H

/*
 * Full data + instruction barrier. dudect calls this immediately
 * before reading the cycle counter to keep memory operations ordered
 * with respect to the counter read.
 */
static inline void _mm_mfence(void) {
    __asm__ __volatile__("dsb sy" ::: "memory");
}

#if defined(__APPLE__)

#include <mach/mach_time.h>

/*
 * Apple Silicon: use mach_absolute_time(). High-resolution, monotonic,
 * kernel-virtualised. Resolution is typically 1 ns (24 MHz timer with
 * 41.667 ns per tick × scaler — varies by Mac model; XNU normalises
 * via mach_timebase_info).
 *
 * mach_absolute_time() is observably free of the non-monotonic
 * artefacts CNTVCT_EL0 has in EL0 on macOS.
 */
static inline uint64_t __rdtsc(void) {
    return mach_absolute_time();
}

#else  /* Linux / *BSD on AArch64 */

/*
 * Read the AArch64 virtual count register (CNTVCT_EL0). Readable
 * from EL0 by default on Linux. ISB before the read ensures the
 * counter read is not speculated past the preceding fence.
 */
static inline uint64_t __rdtsc(void) {
    uint64_t v;
    __asm__ __volatile__("isb; mrs %0, cntvct_el0" : "=r" (v));
    return v;
}

#endif /* __APPLE__ */

#endif /* __aarch64__ */

#endif /* DUDECT_COMPAT_H */
