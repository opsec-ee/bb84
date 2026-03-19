/*
 ==================================================================
 * @file    bb84_reconcile.c
 * @version 2.1
 * @brief   RECONCILE sidecar -- Cascade-lite 4-pass error correction
 *
 * Reference: Brassard & Salvail, "Secret-Key Reconciliation by
 *   Public Discussion", EUROCRYPT 1993, LNCS 765, pp. 410-423.
 *
 * =================================================================
 * CHANGES v2.0 -> v2.1
 * =================================================================
 *
 * OPT-1: O(1) block lookup in cascade_re_check via inverted perm.
 *
 *   v2.0: cascade_re_check searched perm[p][0..n) linearly to find
 *   which permuted position holds corrected_pos. O(n) per call.
 *   With O(n*e) corrections and O(passes) re-checks per correction,
 *   the re-check loop was O(n^2 * e * passes) overall.
 *
 *   v2.1: inv_perm[pass][comp_pos] = i such that perm[pass][i] = comp_pos.
 *   Built at permutation time in O(n) per pass.
 *   Block lookup: block_idx = inv_perm[p][corrected_pos] / k. O(1).
 *   Total re-check cost: O(n * e * passes). Quadratic term gone.
 *
 *   Correctness: perm and inv_perm are inverse permutations on [0,n).
 *   Proof: perm[p] is a bijection on [0,n) by construction (Fisher-Yates
 *   produces every permutation with equal probability, all bijections).
 *   inv_perm[p][perm[p][i]] = i by definition.
 *   Therefore inv_perm[p][comp_pos] gives the unique i where
 *   perm[p][i] == comp_pos. O(1) by direct array addressing.
 *
 * OPT-2: reconciled_key packed uint64_t (8x memory reduction).
 *
 *   v2.0: reconciled_key stored as uint8_t[] with one byte per bit
 *   (0x00 or 0x01). n_rec bytes for n_rec bits. 8x over-allocation.
 *
 *   v2.1: reconciled_key is uint64_t[], words_for_bits(n_rec) words.
 *   n_rec bits packed 64-per-word, LSB-first. bit_set/bit_get access.
 *   For n_rec = 766 bits: v2.0 used 766 bytes, v2.1 uses 96 bytes.
 *   Fits in 2 cache lines vs 12.
 *
 * =================================================================
 * PROTOCOL POSITION (unchanged from v2.0)
 * =================================================================
 *
 * RECONCILE waits at barrier_rq for REAR to complete QBER estimation.
 * Reads store->sample_sift_idx[] and skips those positions.
 * Operates only on non-sample sifted bits.
 *
 * Barrier participation: lr, rq, rc (must reach all three).
 *
 * FRONT: (alice_raw, sifted_key) PROT_READ; sample_sift_idx[] (AS)
 * LEAD:  parity XOR per block -- error detection (Pivot)
 * REAR:  reconciled_key packed PROT_READ, parity_bits_leaked set (IS)
 *   Z: never
 *   X: upstream abort, alloc failure, RNG failure, seal failure
 *   1: all detectable errors corrected, reconciled_key sealed
 *
 * Contract: {{0 [ BB84Ctx* (AS/.\IS) GateResult* ] 1}}
 ==================================================================
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "bb84_reconcile.h"
#include "bb84_ramstore.h"

static const uint32_t cascade_k[CASCADE_PASSES] = {
    CASCADE_K0,
    CASCADE_K0 * 2u,
    CASCADE_K0 * 4u,
    CASCADE_K0 * 8u,
};

/*
 ==================================================================
 * BUILD_SAMPLE_MASK -- O(n) boolean lookup for sample positions
 *
 * FRONT: store->sample_sift_idx[0..BB84_SAMPLE_N) -- sifted positions
 *        chosen by REAR's Fisher-Yates draw (AS)
 * LEAD:  mask[sample_sift_idx[s]] = true for s in [0, BB84_SAMPLE_N) (Pivot)
 * REAR:  bool* mask -- true at each sampled sifted position (IS)
 *   X: calloc failure -- returns nullptr
 *   1: mask[i] == true iff sifted position i is in the QBER sample;
 *      collect_bits uses this to exclude those positions
 * Contract: {{0 [ RAMStore* (AS/++\PLUS) bool* ] 1}}
 ==================================================================
 */
static bool *build_sample_mask(const RAMStore *store)
{
    bool *mask = calloc(store->sifted_len, sizeof *mask);
    if (!mask) return nullptr;
    for (size_t s = 0u; s < BB84_SAMPLE_N; s++)
        mask[store->sample_sift_idx[s]] = true;
    return mask;
}

/*
 ==================================================================
 * COLLECT_BITS -- pack non-sample sifted bits into uint64_t array
 *
 * FRONT: (sifted_key, in_sample) -- sifted gate states + exclusion
 *        mask; in_sample[i] true => position i is public/discarded (AS)
 * LEAD:  GATE_1 -> bit_set(out_bits, count);
 *        GATE_0 -> bit stays 0;
 *        in_sample[sift_pos] -> skip entirely (Pivot)
 * REAR:  (out_bits[], sift_idx[]) -- packed bit array and position
 *        map for the n_rec non-sample sifted bits (IS)
 *   Z: no non-sample GATE_0/GATE_1 bits exist (count returns 0)
 *   1: out_bits[i] = bit value; sift_idx[i] = its sifted position;
 *      Cascade uses this as its working key copy
 *
 * OPT-2: out_bits is packed uint64_t, not one-byte-per-bit.
 * Contract: {{0 [ RAMStore* (AS/++\PLUS) (uint64_t[],size_t[]) ] 1}}
 ==================================================================
 */
static size_t collect_bits(const RAMStore *store,
                           const bool     *in_sample,
                           uint64_t       *out_bits,
                           size_t         *sift_idx)
{
    size_t count    = 0u;
    size_t sift_pos = 0u;

    for (size_t i = 0u; i < BB84_N_PHOTONS; i++) {
        GateState gs = store->sifted_key[i];
        if (gs != GATE_0 && gs != GATE_1) continue;

        if (!in_sample[sift_pos]) {
            sift_idx[count] = sift_pos;
            if (gs == GATE_1) bit_set(out_bits, count);
            count++;
        }
        sift_pos++;
    }
    return count;
}

/*
 ==================================================================
 * CASCADE CONTEXT
 *
 * inv_perm[pass][comp_pos] = i  such that  perm[pass][i] = comp_pos
 * Built alongside perm[] in O(n) per pass.
 * Used by cascade_re_check for O(1) block lookup.
 ==================================================================
 */
typedef struct {
    const RAMStore *store;
    const size_t   *phot_for_sift;  /* sift_pos -> photon index */
    uint64_t       *rec_bits;       /* packed, corrected in-place */
    size_t         *sift_idx;       /* comp_pos -> sift_pos */
    size_t          n;
    uint32_t        leaked;
    size_t         *corrected;
    size_t          corrected_len;
    size_t          corrected_cap;
    size_t         *perm    [CASCADE_PASSES];
    size_t         *inv_perm[CASCADE_PASSES];  /* OPT-1 */
} CascadeCtx;

/*
 ==================================================================
 * ALICE_PARITY -- XOR of Alice's original bits over a block
 *
 * Traversal: perm[pass][lo..hi) -> comp_pos -> sift_pos
 *            -> phot_for_sift[sift_pos] -> alice_raw[phot].alice_bit
 *
 * FRONT: perm[pass][lo..hi) -- permuted compressed positions (AS)
 * LEAD:  XOR of alice_raw[phot_for_sift[sift_idx[comp]]].alice_bit
 *        for each comp in the block (Pivot)
 * REAR:  uint8_t -- parity of Alice's original bits at those positions (IS)
 *   Z: lo >= hi (empty block; parity = 0 by XOR identity)
 *   1: parity bit; one half of the Cascade parity exchange
 * Contract: {{0 [ (CascadeCtx*,pass,lo,hi) (AS/.\IS) uint8_t ] 1}}
 ==================================================================
 */
static uint8_t alice_parity(const CascadeCtx *ccx,
                            uint32_t pass, size_t lo, size_t hi)
{
    uint8_t p = 0u;
    for (size_t j = lo; j < hi; j++) {
        size_t comp_pos = ccx->perm[pass][j];
        size_t sift_pos = ccx->sift_idx[comp_pos];
        size_t phot     = ccx->phot_for_sift[sift_pos];
        p ^= ccx->store->alice_raw[phot].alice_bit;
    }
    return p;
}

/*
 ==================================================================
 * BOB_PARITY -- XOR of Bob's reconciled bits over a block
 *
 * FRONT: perm[pass][lo..hi) -- permuted compressed positions (AS)
 * LEAD:  XOR of rec_bits[perm[pass][j]] for j in [lo, hi) (Pivot)
 * REAR:  uint8_t -- parity of Bob's reconciled bits at those positions (IS)
 *   Z: lo >= hi (empty block; parity = 0)
 *   1: parity bit; counterpart to alice_parity in the Cascade exchange;
 *      mismatch with alice_parity implies odd error count in block
 * Contract: {{0 [ (CascadeCtx*,pass,lo,hi) (AS/.\IS) uint8_t ] 1}}
 ==================================================================
 */
static uint8_t bob_parity(const CascadeCtx *ccx,
                          uint32_t pass, size_t lo, size_t hi)
{
    uint8_t p = 0u;
    for (size_t j = lo; j < hi; j++)
        p ^= bit_get(ccx->rec_bits, ccx->perm[pass][j]);
    return p;
}

/*
 ==================================================================
 * CORRECTED_APPEND -- record a corrected position for cascade re-check
 *
 * FRONT: ccx->corrected[0..corrected_len) -- current correction list (AS)
 * LEAD:  realloc if at capacity; corrected[corrected_len++] = pos (Pivot)
 * REAR:  pos is the last entry in ccx->corrected (IS)
 *   Z: realloc failure -- pos not recorded; cascade re-check misses
 *      it for prior passes (recoverable; Cascade continues)
 *   1: pos appended; cascade_re_check will examine its containing
 *      block in all prior passes
 * Contract: {{0 [ (CascadeCtx*,pos) (AS/.\IS) pos appended ] 1}}
 ==================================================================
 */
static void corrected_append(CascadeCtx *ccx, size_t pos)
{
    if (ccx->corrected_len >= ccx->corrected_cap) {
        size_t  nc = ccx->corrected_cap ? ccx->corrected_cap * 2u : 64u;
        size_t *p  = realloc(ccx->corrected, nc * sizeof *p);
        if (!p) return;
        ccx->corrected     = p;
        ccx->corrected_cap = nc;
    }
    ccx->corrected[ccx->corrected_len++] = pos;
}

/*
 ==================================================================
 * BISECT -- binary search error correction on a permuted block
 *
 * FRONT: (ccx, pass, lo, hi) -- permuted block [lo,hi) with a
 *        confirmed parity mismatch; exactly one error present (AS)
 * LEAD:  left-half parity exchange determines which sub-block holds
 *        the single error; recurse into mismatching half (Pivot)
 * REAR:  rec_bits[error_pos] flipped; corrected_append(error_pos) (IS)
 *   Z: never (called only on confirmed-mismatch blocks, lo < hi)
 *   1: base case hi-lo==1: perm[pass][lo] is the error position,
 *      bit flipped, corrected_append called
 *   recursive: hi-lo>1: one parity bit leaked, recurse one level
 *
 * Correctness proof (inductive):
 *   Base (hi-lo==1): single position IS the error. Flip it.
 *   Step (hi-lo>1): exactly one error in [lo,hi).
 *     Left parity mismatch -> error in left half. Recurse left.
 *     Left parity match    -> error in right half. Recurse right.
 *   Terminates in ceil(log2(hi-lo)) steps. Leaks ceil(log2(k)) bits.
 * Contract: {{0 [ (CascadeCtx*,pass,lo,hi) (AS/.\IS) one error corrected ] 1}}
 ==================================================================
 */
static void bisect(CascadeCtx *ccx, uint32_t pass, size_t lo, size_t hi)
{
    if (hi - lo == 1u) {
        size_t comp_pos = ccx->perm[pass][lo];
        bit_flip(ccx->rec_bits, comp_pos);
        corrected_append(ccx, comp_pos);
        return;
    }
    size_t  mid = lo + (hi - lo) / 2u;
    uint8_t ap  = alice_parity(ccx, pass, lo, mid);
    uint8_t bp  = bob_parity  (ccx, pass, lo, mid);
    ccx->leaked++;
    if (ap != bp) bisect(ccx, pass, lo,  mid);
    else          bisect(ccx, pass, mid, hi);
}

/*
 ==================================================================
 * CASCADE_RE_CHECK -- O(1) block lookup via inv_perm (OPT-1)
 *
 * FRONT: (ccx, corrected_pos, cur_pass) -- position just corrected
 *        by bisect; correcting it changed parity of its containing
 *        block in all prior passes (AS)
 * LEAD:  inv_perm[p][corrected_pos] / k -> block_idx in O(1);
 *        parity re-tested per prior pass block (Pivot)
 * REAR:  BISECT called on any prior-pass block with new mismatch;
 *        newly revealed errors corrected, leaked count updated (IS)
 *   Z: cur_pass == 0 (no prior passes to re-check)
 *   1: all prior-pass blocks containing corrected_pos re-examined;
 *      cascade propagation complete for this correction
 *
 * OPT-1 proof:
 *   perm[p] is a bijection; inv_perm[p] is its inverse.
 *   inv_perm[p][perm[p][i]] = i for all i in [0,n).
 *   block_idx = inv_perm[p][corrected_pos] / k. O(1) array access.
 * Contract: {{0 [ (CascadeCtx*,corrected_pos,cur_pass) (AS/.\IS) errors corrected ] 1}}
 ==================================================================
 */
static void cascade_re_check(CascadeCtx *ccx,
                             size_t corrected_pos, uint32_t cur_pass)
{
    for (uint32_t p = 0u; p < cur_pass; p++) {
        size_t k          = (size_t)cascade_k[p];

        /* OPT-1: O(1) lookup via inverted permutation */
        size_t perm_pos   = ccx->inv_perm[p][corrected_pos];
        size_t block_idx  = perm_pos / k;

        size_t lo = block_idx * k;
        size_t hi = lo + k;
        if (hi > ccx->n) hi = ccx->n;
        if (lo >= hi)    continue;

        uint8_t ap = alice_parity(ccx, p, lo, hi);
        uint8_t bp = bob_parity  (ccx, p, lo, hi);
        ccx->leaked++;

        if (ap != bp) bisect(ccx, p, lo, hi);
    }
}

/*
 ==================================================================
 * bb84_reconcile -- RECONCILE thread entry
 * Barriers: lr, rq, rc (must reach all three regardless of error)
 ==================================================================
 */
void *bb84_reconcile(void *arg)
{
    BB84Ctx  *ctx   = arg;
    RAMStore *store = ctx->store;

    GateResult *ret = malloc(sizeof *ret);
    if (!ret) {
        ctx_abort(ctx);
        pthread_barrier_wait(&ctx->barrier_lr);
        pthread_barrier_wait(&ctx->barrier_rq);
        pthread_barrier_wait(&ctx->barrier_rc);
        return nullptr;
    }
    *ret = GR_Z("reconcile not yet run");

    pthread_barrier_wait(&ctx->barrier_lr);

    if (ctx_aborted(ctx)) {
        *ret = GR_X("upstream Gate-X (LEAD)");
        pthread_barrier_wait(&ctx->barrier_rq);
        pthread_barrier_wait(&ctx->barrier_rc);
        return ret;
    }

    pthread_barrier_wait(&ctx->barrier_rq);

    if (ctx_aborted(ctx)) {
        *ret = GR_X("upstream Gate-X (REAR QBER)");
        pthread_barrier_wait(&ctx->barrier_rc);
        return ret;
    }

    {
        size_t n_total = store->sifted_len;

        bool   *in_sample     = build_sample_mask(store);
        size_t *phot_for_sift = malloc(n_total * sizeof *phot_for_sift);

        if (!in_sample || !phot_for_sift) {
            *ret = GR_X("reconcile: mask/phot alloc failed");
            free(in_sample); free(phot_for_sift);
            ctx_abort(ctx);
            goto barrier_rc;
        }

        {
            size_t k = 0u;
            for (size_t i = 0u; i < BB84_N_PHOTONS; i++) {
                if (store->sifted_key[i] == GATE_0 ||
                    store->sifted_key[i] == GATE_1)
                    phot_for_sift[k++] = i;
            }
        }

        size_t   n_rec    = n_total - BB84_SAMPLE_N;
        size_t   n_words  = words_for_bits(n_rec);

        uint64_t *rec_bits = calloc(n_words,  sizeof *rec_bits);
        size_t   *sift_idx = calloc(n_rec,    sizeof *sift_idx);

        if (!rec_bits || !sift_idx) {
            *ret = GR_X("reconcile: collect alloc failed");
            free(in_sample); free(phot_for_sift);
            free(rec_bits);  free(sift_idx);
            ctx_abort(ctx);
            goto barrier_rc;
        }

        size_t actual = collect_bits(store, in_sample, rec_bits, sift_idx);
        free(in_sample);

        if (actual != n_rec) {
            *ret = GR_X("reconcile: n_rec mismatch");
            free(phot_for_sift); free(rec_bits); free(sift_idx);
            ctx_abort(ctx);
            goto barrier_rc;
        }

        /*
         ==============================================================
         * Initialize CascadeCtx with inv_perm[] (OPT-1)
         ==============================================================
         */
        CascadeCtx ccx = {
            .store         = store,
            .phot_for_sift = phot_for_sift,
            .rec_bits      = rec_bits,
            .sift_idx      = sift_idx,
            .n             = n_rec,
            .leaked        = 0u,
            .corrected     = nullptr,
            .corrected_len = 0u,
            .corrected_cap = 0u,
        };
        memset(ccx.perm,     0, sizeof ccx.perm);
        memset(ccx.inv_perm, 0, sizeof ccx.inv_perm);

        /*
         * Build perm[p] and inv_perm[p] together.
         *
         * inv_perm[p][perm[p][i]] = i  for all i in [0, n_rec).
         *
         * FRONT: identity array [0..n_rec) (AS)
         * LEAD:  Fisher-Yates shuffle + inverse construction (Pivot)
         * REAR:  perm[p] random bijection; inv_perm[p] its inverse (IS)
         *
         * Contract: {{0 [ (p, n_rec) (AS/.\IS) (perm[p], inv_perm[p]) ] 1}}
         */
        bool perm_ok = true;

        for (uint32_t p = 0u; p < CASCADE_PASSES; p++) {
            ccx.perm[p]     = malloc(n_rec * sizeof *ccx.perm[p]);
            ccx.inv_perm[p] = malloc(n_rec * sizeof *ccx.inv_perm[p]);

            if (!ccx.perm[p] || !ccx.inv_perm[p]) {
                perm_ok = false; break;
            }

            for (size_t i = 0u; i < n_rec; i++)
                ccx.perm[p][i] = i;

            if (p > 0u) {
                GateResult fr = fisher_yates(ccx.perm[p], n_rec);
                if (!GR_VALID(fr)) { perm_ok = false; break; }
            }

            /* Build inverse: inv_perm[p][perm[p][i]] = i */
            for (size_t i = 0u; i < n_rec; i++)
                ccx.inv_perm[p][ccx.perm[p][i]] = i;
        }

        if (!perm_ok) {
            *ret = GR_X("reconcile: perm alloc/rng failed");
            goto cleanup;
        }

        /*
         ==============================================================
         * MAIN CASCADE LOOP -- 4 passes
         ==============================================================
         */
        for (uint32_t p = 0u; p < CASCADE_PASSES; p++) {
            size_t k        = (size_t)cascade_k[p];
            size_t n_blocks = (n_rec + k - 1u) / k;
            size_t prev_cor = ccx.corrected_len;

            for (size_t b = 0u; b < n_blocks; b++) {
                size_t lo = b * k;
                size_t hi = lo + k;
                if (hi > n_rec) hi = n_rec;
                if (lo >= hi)   break;

                uint8_t ap = alice_parity(&ccx, p, lo, hi);
                uint8_t bp = bob_parity  (&ccx, p, lo, hi);
                ccx.leaked++;

                if (ap != bp) bisect(&ccx, p, lo, hi);
            }

            for (size_t c = prev_cor; c < ccx.corrected_len; c++)
                cascade_re_check(&ccx, ccx.corrected[c], p);
        }

        /*
         ==============================================================
         * Write packed rec_bits directly to reconciled_key (OPT-2)
         *
         * reconciled_key is uint64_t[], n_words words.
         * Direct memcpy -- no byte-by-byte unpacking needed.
         ==============================================================
         */
        memcpy(store->reconciled_key, rec_bits,
               n_words * sizeof *rec_bits);

        store->reconciled_len    = n_rec;
        store->reconciled_words  = n_words;
        store->parity_bits_leaked = ccx.leaked;

        GateResult sr = ramstore_seal_reconcile(store);
        if (!GR_VALID(sr)) {
            *ret = sr;
            ctx_abort(ctx);
        } else {
            *ret = GR_1((uint64_t)ccx.leaked);
        }

cleanup:
        for (uint32_t p = 0u; p < CASCADE_PASSES; p++) {
            free(ccx.perm[p]);
            free(ccx.inv_perm[p]);
        }
        free(ccx.corrected);
        memset(rec_bits, 0, n_words * sizeof *rec_bits);
        free(rec_bits);
        free(sift_idx);
        free(phot_for_sift);
    }

barrier_rc:
    pthread_barrier_wait(&ctx->barrier_rc);
    return ret;
}
