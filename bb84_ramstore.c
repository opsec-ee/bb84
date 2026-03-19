/*
 ==================================================================
 * @file    bb84_ramstore.c
 * @version 2.1
 * @brief   RAMStore mmap allocation and mprotect slab sealing
 *
 * Slab sizes:
 *   alice_raw      : BB84_N_PHOTONS * sizeof(QCell)       = 16KB
 *   sifted_key     : BB84_N_PHOTONS * sizeof(GateState)   =  2KB
 *   reconciled_key : ceil(BB84_N_PHOTONS/8) bytes         = 256B
 *                    (overprovisioned to BB84_N_PHOTONS bytes)
 *   final_key      : BB84_N_PHOTONS bytes                 =  2KB
 *
 * All start PROT_READ|PROT_WRITE. Each seal:
 *   mprotect(slab, page_round(size), PROT_READ)
 * Post-seal write from any thread: SIGSEGV. Intentional.
 *
 * page_round correctness proof:
 *   mprotect operates on page boundaries. Any slab that does not
 *   span an exact page count would leave a partial page writable
 *   if mprotect'd to its exact size. page_round ensures we cover
 *   the full last page, so the entire slab becomes read-only.
 ==================================================================
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "bb84_ramstore.h"

/*
 ==================================================================
 * INTERNAL
 ==================================================================
 */

/*
 * page_round -- round nbytes up to nearest OS page boundary
 *
 * FRONT: nbytes -- requested allocation size (AS)
 * LEAD:  (nbytes + pg-1) & ~(pg-1) -- page-alignment mask (Pivot)
 * REAR:  size_t -- smallest page-multiple >= nbytes (IS)
 *   Z: never
 *   1: always; result >= nbytes, aligned to sysconf(_SC_PAGESIZE)
 * Contract: {{0 [ size_t (AS/.\IS) size_t ] 1}}
 */
static size_t page_round(size_t nbytes)
{
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    return (nbytes + pg - 1u) & ~(pg - 1u);
}

/*
 * slab_alloc -- mmap anonymous page-aligned zero-filled slab
 *
 * FRONT: nbytes -- requested allocation size (AS)
 * LEAD:  mmap(MAP_ANONYMOUS) -- kernel grants aligned region (Pivot)
 * REAR:  pointer to zeroed PROT_READ|PROT_WRITE region (IS)
 *   X: mmap returned MAP_FAILED
 *   1: pointer valid, slab zeroed by kernel
 *
 * Contract: {{0 [ size_t (AS/.\IS) void* ] 1}}
 */
static void *slab_alloc(size_t nbytes)
{
    size_t sz = page_round(nbytes);
    void  *p  = mmap(nullptr, sz,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    return (p == MAP_FAILED) ? nullptr : p;
}

/*
 * slab_seal -- mprotect slab to PROT_READ
 *
 * FRONT: (p, nbytes) -- writable slab to seal (AS)
 * LEAD:  mprotect syscall -- kernel enforces read-only (Pivot)
 * REAR:  slab at p is now PROT_READ; any write = SIGSEGV (IS)
 *   X: mprotect failed (permissions not changed)
 *   1: slab sealed
 *
 * Contract: {{0 [ (void*,size_t) (AS/.\IS) sealed ] 1}}
 */
static GateResult slab_seal(void *p, size_t nbytes)
{
    if (mprotect(p, page_round(nbytes), PROT_READ) != 0)
        return GR_X("mprotect PROT_READ failed");
    return GR_1(0);
}

/*
 ==================================================================
 * PUBLIC API
 ==================================================================
 */

/*
 * ramstore_alloc -- allocate all four slabs
 *
 * FRONT: void -- no prior state (AS)
 * LEAD:  four slab_alloc calls (Pivot)
 * REAR:  RAMStore* with all pointers non-null, PROT_READ|PROT_WRITE (IS)
 *   X: any mmap failure
 *   1: all slabs ready
 *
 * Contract: {{0 [ void (AS/++\PLUS) RAMStore* ] 1}}
 */
[[nodiscard]] GateResult ramstore_alloc(RAMStore *store)
{
    memset(store, 0, sizeof *store);

    store->alice_raw = slab_alloc(BB84_N_PHOTONS * sizeof(QCell));
    if (!store->alice_raw)
        return GR_X("alice_raw mmap failed");

    store->sifted_key = slab_alloc(BB84_N_PHOTONS * sizeof(GateState));
    if (!store->sifted_key)
        return GR_X("sifted_key mmap failed");

    store->reconciled_key = slab_alloc(
        words_for_bits(BB84_N_PHOTONS) * sizeof(uint64_t));
    if (!store->reconciled_key)
        return GR_X("reconciled_key mmap failed");

    store->final_key = slab_alloc(BB84_N_PHOTONS);
    if (!store->final_key)
        return GR_X("final_key mmap failed");

    /* reconciled_words set when sifted_len is known (after LEAD) */
    return GR_1(0);
}

/*
 * ramstore_seal_front -- alice_raw -> PROT_READ after FRONT
 *
 * FRONT: alice_raw writable -- FRONT's committed output (AS)
 * LEAD:  mprotect(PROT_READ) (Pivot)
 * REAR:  alice_raw PROT_READ -- any write = SIGSEGV (IS)
 *   X: mprotect failed
 *   1: sealed
 *
 * Contract: {{0 [ RAMStore* (AS/.\IS) alice_raw sealed ] 1}}
 */
[[nodiscard]] GateResult ramstore_seal_front(RAMStore *store)
{
    return slab_seal(store->alice_raw,
                     BB84_N_PHOTONS * sizeof(QCell));
}

/*
 * ramstore_seal_lead -- sifted_key -> PROT_READ after LEAD
 *
 * FRONT: sifted_key writable -- LEAD's committed output (AS)
 * LEAD:  mprotect(PROT_READ) (Pivot)
 * REAR:  sifted_key PROT_READ (IS)
 *
 * Contract: {{0 [ RAMStore* (AS/.\IS) sifted_key sealed ] 1}}
 */
[[nodiscard]] GateResult ramstore_seal_lead(RAMStore *store)
{
    return slab_seal(store->sifted_key,
                     BB84_N_PHOTONS * sizeof(GateState));
}

/*
 * ramstore_seal_reconcile -- reconciled_key -> PROT_READ after RECONCILE
 *
 * FRONT: reconciled_key writable -- RECONCILE's corrected output (AS)
 * LEAD:  mprotect(PROT_READ) (Pivot)
 * REAR:  reconciled_key PROT_READ (IS)
 *   X: mprotect failed or reconciled_words == 0
 *   1: sealed
 *
 * Contract: {{0 [ RAMStore* (AS/.\IS) reconciled_key sealed ] 1}}
 */
[[nodiscard]] GateResult ramstore_seal_reconcile(RAMStore *store)
{
    if (store->reconciled_words == 0u)
        return GR_X("seal_reconcile: reconciled_words is zero");
    return slab_seal(store->reconciled_key,
                     store->reconciled_words * sizeof(uint64_t));
}

/*
 * ramstore_seal_rear -- final_key -> PROT_READ after REAR
 *
 * Contract: {{0 [ RAMStore* (AS/.\IS) final_key sealed ] 1}}
 *   X: final_len == 0 or mprotect failed
 *   1: sealed
 */
[[nodiscard]] GateResult ramstore_seal_rear(RAMStore *store)
{
    if (store->final_len == 0u)
        return GR_X("seal_rear: final_len is zero");
    return slab_seal(store->final_key, store->final_len);
}

/*
 * ramstore_free -- munmap all four slabs
 *
 * Lossy contract: all key material destroyed.
 * Contract: {{0 [ RAMStore* (AS/--\WAS) void ] 1}}
 */
void ramstore_free(RAMStore *store)
{
    if (store->alice_raw)
        munmap(store->alice_raw,
               page_round(BB84_N_PHOTONS * sizeof(QCell)));
    if (store->sifted_key)
        munmap(store->sifted_key,
               page_round(BB84_N_PHOTONS * sizeof(GateState)));
    if (store->reconciled_key)
        munmap(store->reconciled_key,
               page_round(words_for_bits(BB84_N_PHOTONS) * sizeof(uint64_t)));
    if (store->final_key)
        munmap(store->final_key,
               page_round(BB84_N_PHOTONS));
    memset(store, 0, sizeof *store);
}
