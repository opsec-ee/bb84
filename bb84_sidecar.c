/*
 ==================================================================
 * @file    bb84_sidecar.c
 * @version 2.1
 * @author  H. Overman (ee)
 * @brief   Sidecar context helpers, RNG wrappers, Fisher-Yates
 *
 * All function definitions from bb84_sidecar.h that are not
 * trivial single-expression bit operations.
 *
 * Bit operations (bit_set, bit_clr, bit_get, bit_flip) remain
 * as static inline in bb84_sidecar.h -- they are single bitwise
 * expressions that must inline at every call site for performance,
 * matching Linux kernel coding style for micro-ops.
 ==================================================================
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include "bb84_sidecar.h"

/*
 ==================================================================
 * ctx_abort -- set session abort flag before reaching barrier
 *
 * FRONT: fatal condition in calling sidecar (AS)
 * LEAD:  atomic_store(relaxed) -- all subsequent acquire loads
 *        will see abort_flag == 1 (Pivot)
 * REAR:  abort_flag == 1 -- downstream sidecars observe and stop (IS)
 *   Z: never
 *   1: always; flag is set, relaxed ordering sufficient because
 *      the barrier that follows provides the full fence
 * Contract: {{0 [ BB84Ctx* (AS/.\IS) abort_flag=1 ] 1}}
 ==================================================================
 */
void ctx_abort(BB84Ctx *ctx)
{
    atomic_store_explicit(&ctx->abort_flag, 1u, memory_order_relaxed);
}

/*
 ==================================================================
 * ctx_aborted -- check abort flag after barrier
 *
 * FRONT: upstream barrier passed -- all upstream stores committed (AS)
 * LEAD:  atomic_load(acquire) -- sees all stores before the barrier (Pivot)
 * REAR:  bool -- true if session is in Gate-X state (IS)
 *   0: false -- proceed normally
 *   1: true  -- return GR_X without touching RAMStore
 * Contract: {{0 [ BB84Ctx* (AS/.\IS) bool ] 1}}
 ==================================================================
 */
bool ctx_aborted(BB84Ctx *ctx)
{
    return atomic_load_explicit(&ctx->abort_flag,
                                memory_order_acquire) != 0u;
}

/*
 ==================================================================
 * rng_u64 -- getrandom wrapper, single uint64_t
 *
 * FRONT: out -- pointer to receive random value (AS)
 * LEAD:  getrandom(2) syscall -- kernel CSPRNG (Pivot)
 * REAR:  *out -- 8 cryptographic random bytes (IS)
 *   X: getrandom returned short read or error
 *   1: *out filled with cryptographic random data
 * Contract: {{0 [ uint64_t* (AS/.\IS) *out filled ] 1}}
 ==================================================================
 */
GateResult rng_u64(uint64_t *out)
{
    ssize_t r = getrandom(out, sizeof *out, 0);
    if (r != (ssize_t)sizeof *out)
        return GR_X("getrandom failed");
    return GR_1(0);
}

/*
 ==================================================================
 * rng_bytes -- getrandom wrapper, arbitrary length
 *
 * FRONT: (buf, n) -- destination buffer and byte count (AS)
 * LEAD:  getrandom(buf, n, 0) -- kernel fills buf (Pivot)
 * REAR:  buf[0..n) -- n bytes from kernel entropy pool (IS)
 *   X: getrandom returned short read or error
 *   1: buf contains n cryptographic random bytes
 * Contract: {{0 [ (void*,size_t) (AS/.\IS) buf filled ] 1}}
 ==================================================================
 */
GateResult rng_bytes(void *buf, size_t n)
{
    ssize_t r = getrandom(buf, n, 0);
    if (r < 0 || (size_t)r != n)
        return GR_X("getrandom failed");
    return GR_1(0);
}

/*
 ==================================================================
 * coin_flip -- true with probability n/RATIO_DENOM, no IO
 *
 * FRONT: (rng_val, n) -- externally obtained random value (AS)
 * LEAD:  rng_val % RATIO_DENOM < n -- integer comparison (Pivot)
 * REAR:  bool -- deterministic given inputs (IS)
 *   Z: never
 *   1: true with probability n/RATIO_DENOM
 *
 * Bias: UINT64_MAX / 144000 = ~2.56e14 complete cycles.
 * Residual bias < 2^-40. Negligible.
 * Contract: {{0 [ (uint64_t,uint64_t) (AS/.\IS) bool ] 1}}
 ==================================================================
 */
bool coin_flip(uint64_t rng_val, uint64_t n)
{
    return (rng_val % RATIO_DENOM) < n;
}

/*
 ==================================================================
 * fisher_yates -- uniform random permutation of [0, n) in-place
 *
 * FRONT: arr[0..n) -- initial index sequence (AS)
 * LEAD:  getrandom per swap position -- unbiased selection (Pivot)
 * REAR:  arr[0..n) -- uniformly random permutation (IS)
 *   X: rng_u64 failure -- arr partially shuffled; caller checks
 *   1: arr is a uniform random permutation; every ordering
 *      equally probable (1/n!) given uniform rng_u64 output
 *
 * Correctness: Fisher-Yates is a bijection on permutation space.
 * At step i: arr[i] swapped with arr[j], j uniform in [0,i].
 * Inductively: all i! orderings of arr[0..i] equally likely.
 * Contract: {{0 [ (size_t*,size_t) (AS/.\IS) arr permuted ] 1}}
 ==================================================================
 */
GateResult fisher_yates(size_t *arr, size_t n)
{
    for (size_t i = n - 1u; i > 0u; i--) {
        uint64_t rv;
        GateResult r = rng_u64(&rv);
        if (!GR_VALID(r)) return r;

        size_t j   = (size_t)(rv % (uint64_t)(i + 1u));
        size_t tmp = arr[i];
        arr[i]     = arr[j];
        arr[j]     = tmp;
    }
    return GR_1(0);
}
