/*
 ==================================================================
 * @file    bb84_sidecar.h
 * @version 2.1
 * @brief   Shared context, barriers, abort flag, RNG, bit-array,
 *          permutation helpers
 *
 * Barrier ordering -- correct BB84 phase sequence:
 *
 *   FRONT --[fl]--> LEAD --[lr]--> REAR(QBER) --[rq]--> RECONCILE --[rc]--> REAR(PA)
 *
 *   barrier_fl  count=2  FRONT + LEAD
 *   barrier_lr  count=3  LEAD + REAR + RECONCILE
 *                        All three wait here for LEAD to seal sifted_key.
 *                        REAR does QBER on raw sifted_key after this.
 *                        RECONCILE waits for REAR at barrier_rq.
 *   barrier_rq  count=2  REAR + RECONCILE
 *                        REAR signals after writing sample_sift_idx
 *                        and qber_e_num to store. RECONCILE reads them
 *                        then runs Cascade on non-sample positions.
 *   barrier_rc  count=2  RECONCILE + REAR
 *                        REAR waits here for Cascade to complete,
 *                        then runs PA.
 *
 * Thread barrier participation:
 *   FRONT      : fl
 *   LEAD       : fl, lr
 *   REAR       : lr, rq, rc
 *   RECONCILE  : lr, rq, rc
 *
 * Gate-X propagation -- atomic abort_flag:
 *   Any sidecar on fatal condition:
 *     1. ctx_abort() -- atomic_store relaxed
 *     2. Reaches ALL remaining barriers in sequence (no skipping)
 *     3. Returns GR_X
 *   Every sidecar after each barrier:
 *     ctx_aborted() -- atomic_load acquire -- stops if set
 *   Ensures no barrier deadlock, no partial RAMStore write.
 *
 * rng_u64 / coin_flip separation:
 *   rng_u64   : [[nodiscard]] GateResult -- IO, can fail
 *   coin_flip : pure -- takes pre-obtained rng value, no IO
 ==================================================================
 */
#pragma once
#ifndef BB84_SIDECAR_H
#define BB84_SIDECAR_H

#define _GNU_SOURCE
#include <pthread.h>
#include <sys/random.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include "bb84_types.h"

/*
 ==================================================================
 * SHARED SESSION CONTEXT
 ==================================================================
 */
typedef struct {
    RAMStore              *store;
    pthread_barrier_t      barrier_fl;    /* FRONT -> LEAD                  */
    pthread_barrier_t      barrier_lr;    /* LEAD + REAR + RECONCILE        */
    pthread_barrier_t      barrier_rq;    /* REAR(QBER done) -> RECONCILE   */
    pthread_barrier_t      barrier_rc;    /* RECONCILE done -> REAR(PA)     */
    _Atomic uint32_t       abort_flag;    /* 0=ok, 1=Gate-X                 */
} BB84Ctx;

/*
 ==================================================================
 * ABORT FLAG HELPERS
 ==================================================================
 */

/*
 * ctx_abort -- set abort_flag; called before reaching barrier
 *
 * FRONT: fatal condition in calling sidecar (AS)
 * LEAD:  atomic_store(relaxed) -- all subsequent load(acquire)
 *        see the flag (Pivot)
 * REAR:  abort_flag == 1 -- downstream sidecars observe and stop (IS)
 *
 * Contract: {{0 [ BB84Ctx* (AS/.\IS) abort_flag=1 ] 1}}
 */
/* Defined in bb84_sidecar.c */
void ctx_abort(BB84Ctx *ctx);
[[nodiscard]] bool ctx_aborted(BB84Ctx *ctx);

/*
 ==================================================================
 * THREAD ENTRY POINTS
 *
 * Each thread:
 *   - Allocates GateResult* on heap, owns it, main frees it
 *   - Always reaches ALL barriers in sequence (abort or not)
 *   - Sets abort_flag BEFORE its barrier on fatal error
 *   - Returns GR_X if ctx_aborted() after any barrier
 *
 * Contract (all four):
 *   {{0 [ BB84Ctx* (AS/.\IS) GateResult* ] 1}}
 ==================================================================
 */
void *bb84_front(void *ctx);
void *bb84_lead(void *ctx);
void *bb84_reconcile(void *ctx);
void *bb84_rear(void *ctx);

/*
 ==================================================================
 * RNG PRIMITIVES
 ==================================================================
 */

/*
 * rng_u64 -- getrandom wrapper, single uint64_t
 *
 * FRONT: out -- pointer to receive random value (AS)
 * LEAD:  getrandom(2) -- kernel CSPRNG (Pivot)
 * REAR:  *out -- cryptographic random uint64_t (IS)
 *   X: getrandom returned short read or error
 *   1: *out contains 8 random bytes
 *
 * Contract: {{0 [ uint64_t* (AS/.\IS) *out filled ] 1}}
 */
/* Defined in bb84_sidecar.c */
[[nodiscard]] GateResult rng_u64(uint64_t *out);
[[nodiscard]] GateResult rng_bytes(void *buf, size_t n);
[[nodiscard]] bool       coin_flip(uint64_t rng_val, uint64_t n);

/*
 ==================================================================
 * BIT ARRAY HELPERS
 * Packed uint64_t, LSB-first within each word.
 * words_for_bits() is defined in bb84_types.h.
 ==================================================================
 */

/*
 * bit_set -- set bit i in packed array
 *
 * FRONT: arr[i/64] word -- current packed state (AS)
 * LEAD:  arr[i/64] |= (1ULL << (i%64)) -- bitwise OR (Pivot)
 * REAR:  bit i == 1; bit_get(arr,i) == 1 round-trips (IS)
 *   Z: never
 *   1: always (pure bit operation)
 * Contract: {{0 [ (arr,i) (AS/.\IS) arr[i]=1 ] 1}}
 */
static inline void bit_set(uint64_t *arr, size_t i)
{
    arr[i / 64u] |= (1ULL << (i % 64u));
}

/*
 * bit_clr -- clear bit i in packed array
 *
 * FRONT: arr[i/64] word -- current packed state (AS)
 * LEAD:  arr[i/64] &= ~(1ULL << (i%64)) -- bitwise AND-NOT (Pivot)
 * REAR:  bit i == 0; bit_get(arr,i) == 0 round-trips (IS)
 *   Z: never
 *   1: always
 * Contract: {{0 [ (arr,i) (AS/.\IS) arr[i]=0 ] 1}}
 */
static inline void bit_clr(uint64_t *arr, size_t i)
{
    arr[i / 64u] &= ~(1ULL << (i % 64u));
}

/*
 * bit_get -- read bit i from packed array
 *
 * FRONT: arr[i/64] word -- packed state to inspect (AS)
 * LEAD:  (arr[i/64] >> (i%64)) & 1 -- extraction shift (Pivot)
 * REAR:  uint8_t in {0,1} -- extracted bit value (IS)
 *   Z: never
 *   1: always; result in {0,1} by mask guarantee
 * Contract: {{0 [ (arr,i) (AS/.\IS) uint8_t{0|1} ] 1}}
 */
[[nodiscard]]
static inline uint8_t bit_get(const uint64_t *arr, size_t i)
{
    return (uint8_t)((arr[i / 64u] >> (i % 64u)) & 1u);
}

/*
 * bit_flip -- invert bit i in packed array
 *
 * FRONT: arr[i/64] word -- current packed state (AS)
 * LEAD:  arr[i/64] ^= (1ULL << (i%64)) -- bitwise XOR (Pivot)
 * REAR:  bit i inverted; XOR is self-inverse, round-trip holds (IS)
 *   Z: never
 *   1: always; bit_get(arr,i) == 1 - prior_value
 * Contract: {{0 [ (arr,i) (AS/.\IS) arr[i] XOR= 1 ] 1}}
 */
static inline void bit_flip(uint64_t *arr, size_t i)
{
    arr[i / 64u] ^= (1ULL << (i % 64u));
}

/*
 ==================================================================
 * FISHER-YATES PARTIAL SHUFFLE
 *
 * Produces a random permutation of [0, n) in place.
 * Used by RECONCILE for per-pass scattering of bit positions.
 * Used by REAR for random QBER sample selection.
 *
 * Correctness:
 *   Fisher-Yates is a bijection on permutation space -- every
 *   ordering of n elements is produced with equal probability
 *   1/n! given a uniform source. getrandom provides this.
 *
 * FRONT: arr[0..n) -- initial index sequence (AS)
 * LEAD:  getrandom per swap -- unbiased random selection (Pivot)
 * REAR:  arr[0..n) -- uniformly random permutation (IS)
 *
 * Contract: {{0 [ (arr,n) (AS/.\IS) arr permuted ] 1}}
 *   X: rng_u64 failure -- arr partially shuffled; caller checks
 *   1: arr is a uniform random permutation
 ==================================================================
 */
/* Defined in bb84_sidecar.c */
[[nodiscard]] GateResult fisher_yates(size_t *arr, size_t n);

#endif /* BB84_SIDECAR_H */
