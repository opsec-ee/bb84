/*
 ==================================================================
 * @file    bb84_rear.c
 * @version 2.1
 * @brief   REAR sidecar -- QBER estimation (Phase 4) + PA (Phase 5)
 *          + key confirmation verification
 *
 * REAR runs in two phases separated by barrier_rq:
 *
 * =================================================================
 * PHASE 1 (after barrier_lr, before barrier_rq): QBER estimation
 * =================================================================
 *
 * QBER must be measured on the RAW sifted key, before error
 * correction. Measuring after Cascade would always show ~0% error
 * because Cascade already corrected the errors. This would make the
 * QBER threshold check dead code -- a critical security failure.
 *
 * Correct BB84 order:
 *   1. Sift (LEAD)
 *   2. Estimate QBER on random sample of raw sifted bits  <-- REAR phase 1
 *   3. Abort if QBER > threshold
 *   4. Error correction (RECONCILE) on remaining bits
 *   5. Privacy amplification                              <-- REAR phase 2
 *
 * Pipeline (phase 1):
 *   a. Build sifted bit index list [0, sifted_len)
 *   b. Fisher-Yates shuffle over index list
 *   c. Take first BB84_SAMPLE_N as sample
 *      (random subset without replacement -- no prefix bias)
 *   d. For each sample position s:
 *        alice_bit = alice_raw[photon_at_s].alice_bit    (original)
 *        bob_bit   = sifted_key at photon_at_s           (raw, uncorrected)
 *        error    += (alice_bit != bob_bit)
 *   e. Write store->sample_sift_idx[] (RECONCILE skips these)
 *   f. Write store->qber_e_num
 *   g. Abort if !qber_accept(qber)
 *   h. Reach barrier_rq -- RECONCILE unblocks and runs Cascade
 *
 * =================================================================
 * PHASE 2 (after barrier_rc): Privacy amplification + confirmation
 * =================================================================
 *
 * reconciled_key contains (sifted_len - BB84_SAMPLE_N) bytes,
 * one per non-sample sifted bit, error-corrected by Cascade.
 * Sample positions are permanently discarded.
 *
 * PA length formula (ratio arithmetic proof in bb84_types.h):
 *   final_bits = floor(n_pa*(RATIO_DENOM - 2*h_val)/RATIO_DENOM)
 *                - parity_bits_leaked - SECURITY_PARAM
 *
 * Overflow bound:
 *   n_pa <= BB84_N_PHOTONS = 2048
 *   max(n_pa * RATIO_DENOM) = 2048 * 144000 = 294,912,000 < 2^64
 *
 * FRONT: sifted_key PROT_READ -- raw bits for QBER (AS)
 * LEAD:  QBER cross-multiply; Toeplitz GF(2) multiply for PA (Pivot)
 * REAR:  qber_e_num + sample_sift_idx[]; then final_key sealed (IS)
 *   Z: never
 *   X: upstream abort, QBER exceeded, PA<=0, alloc/seal failure
 *   1: final_key sealed, confirm_hash set, session_gate=GR_1
 *
 * Contract: {{0 [ BB84Ctx* (AS/.\IS) GateResult* ] 1}}
 ==================================================================
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "bb84_sidecar.h"
#include "bb84_ramstore.h"

/*
 ==================================================================
 * CONFIRM_HASH -- 64-bit rotate-XOR for key confirmation
 *
 * FRONT: (key, len) -- byte array (AS)
 * LEAD:  rotate-XOR accumulation (Pivot)
 * REAR:  uint64_t hash (IS)
 *   1: always (pure function)
 *
 * Leaks 64 bits -- covered by SECURITY_PARAM = 64.
 * Contract: {{0 [ (uint8_t*,size_t) (AS/.\IS) uint64_t ] 1}}
 ==================================================================
 */
static uint64_t confirm_hash_fn(const uint8_t *key, size_t len)
{
    uint64_t h = 0xA5A5A5A5A5A5A5A5ULL;
    for (size_t i = 0u; i < len; i++) {
        h ^= (uint64_t)key[i] << ((i % 8u) * 8u);
        h  = (h << 7u) | (h >> 57u);
    }
    return h;
}

/*
 ==================================================================
 * ALICE_CONFIRM_HASH -- compute Alice's reference hash for
 * key confirmation verification.
 *
 * After PA, Alice and Bob exchange hashes over the authenticated
 * channel. If they differ, reconciliation failed silently --
 * keys do not match. Session must abort.
 *
 * Alice's PA input: her original non-sample sifted bits,
 * identical to what Cascade should have corrected Bob's copy to.
 * We apply the SAME Toeplitz matrix (same r_seed from rng),
 * BUT: the Toeplitz seed is already consumed and final_key is
 * committed. We cannot re-run PA.
 *
 * Practical verification in simulation:
 *   Alice packs her non-sample alice_raw bits into a uint64_t
 *   array using the same sample exclusion mask as RECONCILE.
 *   She then directly compares that packed array against
 *   reconciled_key (Bob's corrected bits) word-by-word.
 *
 *   If they differ: Cascade left uncorrected errors. The PA
 *   output (final_key) was computed on a wrong input -- the
 *   keys Alice and Bob would derive from the same Toeplitz seed
 *   would differ. Session abort.
 *
 *   If they match: Cascade succeeded. confirm_hash computed from
 *   final_key is consistent. Key confirmed.
 *
 * This check is performed before sealing final_key.
 *
 * FRONT: (alice_raw, sample_sift_idx, reconciled_key) PROT_READ (AS)
 * LEAD:  packed alice bits XOR reconciled_key words (Pivot)
 * REAR:  bool -- true if all words match (IS)
 *   Z: n_rec == 0 (no bits to check)
 *   X: any word differs (reconciliation failure)
 *   1: all words match (Cascade fully corrected Bob's key)
 *
 * Contract: {{0 [ RAMStore* (AS/.\IS) bool ] 1}}
 ==================================================================
 */
[[nodiscard]]
static bool alice_confirm(const RAMStore *store)
{
    size_t n_rec = store->reconciled_len;
    if (n_rec == 0u) return false;

    /* Build same sample mask RECONCILE used */
    bool *in_sample = calloc(store->sifted_len, sizeof *in_sample);
    if (!in_sample) return false;

    for (size_t s = 0u; s < BB84_SAMPLE_N; s++)
        in_sample[store->sample_sift_idx[s]] = true;

    /* Pack alice's non-sample bits into a local bit array */
    size_t    n_words   = words_for_bits(n_rec);
    uint64_t *alice_bits = calloc(n_words, sizeof *alice_bits);

    if (!alice_bits) { free(in_sample); return false; }

    size_t comp     = 0u;
    size_t sift_pos = 0u;

    for (size_t i = 0u; i < BB84_N_PHOTONS; i++) {
        GateState gs = store->sifted_key[i];
        if (gs != GATE_0 && gs != GATE_1) continue;

        if (!in_sample[sift_pos]) {
            if (store->alice_raw[i].alice_bit)
                bit_set(alice_bits, comp);
            comp++;
        }
        sift_pos++;
    }

    free(in_sample);

    /* Compare alice_bits word-by-word against reconciled_key */
    bool match = true;
    for (size_t w = 0u; w < n_words; w++) {
        if (alice_bits[w] != store->reconciled_key[w]) {
            match = false;
            break;
        }
    }

    memset(alice_bits, 0, n_words * sizeof *alice_bits);
    free(alice_bits);
    return match;
}

/*
 ==================================================================
 * TOEPLITZ_HASH -- m x n GF(2) Toeplitz matrix multiply
 *
 * OPT-2: input is packed uint64_t[], accessed via bit_get.
 *        Matches reconciled_key packed layout from RECONCILE.
 *
 * FRONT: (input_bits, n, m) -- packed non-sample reconciled bits (AS)
 * LEAD:  T[j,i]=r[j+i]; output[j]=XOR_i{r[j+i] & input[i]} (Pivot)
 * REAR:  output[] -- m privacy-amplified bits (IS)
 *   X: rng_bytes or alloc failure
 *   1: m bits; Eve's info exponentially small if QBER < threshold
 *
 * Contract: {{0 [ (input,n,m) (AS/--\WAS) output[] ] 1}}
 ==================================================================
 */
[[nodiscard]]
static GateResult toeplitz_hash(const uint64_t *input_bits, size_t n,
                                uint64_t       *output,     size_t m)
{
    size_t    r_bits  = n + m - 1u;
    size_t    r_words = words_for_bits(r_bits);
    uint64_t *r_seed  = calloc(r_words, sizeof *r_seed);
    if (!r_seed) return GR_X("toeplitz: seed alloc failed");

    GateResult rr = rng_bytes(r_seed, r_words * sizeof *r_seed);
    if (!GR_VALID(rr)) { free(r_seed); return rr; }

    for (size_t j = 0u; j < m; j++) {
        uint64_t acc = 0u;
        for (size_t i = 0u; i < n; i++)
            acc ^= (uint64_t)bit_get(r_seed, j + i) &
                   (uint64_t)bit_get(input_bits, i);
        if (acc & 1u) bit_set(output, j);
    }

    memset(r_seed, 0u, r_words * sizeof *r_seed);
    free(r_seed);
    return GR_1(0);
}

/*
 ==================================================================
 * bb84_rear -- thread entry point
 * Barriers: lr, rq, rc (must reach all three regardless of error)
 ==================================================================
 */
void *bb84_rear(void *arg)
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
    *ret = GR_Z("rear not yet run");

    /* Wait for LEAD -- sifted_key PROT_READ after this */
    pthread_barrier_wait(&ctx->barrier_lr);

    if (ctx_aborted(ctx)) {
        *ret = GR_X("upstream Gate-X (LEAD)");
        pthread_barrier_wait(&ctx->barrier_rq);
        pthread_barrier_wait(&ctx->barrier_rc);
        return ret;
    }

    /* ==============================================================
     * PHASE 1 -- QBER on raw sifted_key
     * ==============================================================
     */
    {
        size_t  n         = store->sifted_len;
        size_t *phot_idx  = malloc(n * sizeof *phot_idx);
        size_t *order_idx = malloc(n * sizeof *order_idx);

        if (!phot_idx || !order_idx) {
            *ret = GR_X("rear p1: idx alloc failed");
            free(phot_idx); free(order_idx);
            ctx_abort(ctx);
            pthread_barrier_wait(&ctx->barrier_rq);
            pthread_barrier_wait(&ctx->barrier_rc);
            return ret;
        }

        /* phot_idx[i] = photon index for sifted bit i */
        {
            size_t k = 0u;
            for (size_t i = 0u; i < BB84_N_PHOTONS; i++) {
                if (store->sifted_key[i] == GATE_0 ||
                    store->sifted_key[i] == GATE_1) {
                    phot_idx[k]  = i;
                    order_idx[k] = k;
                    k++;
                }
            }
        }

        GateResult fr = fisher_yates(order_idx, n);
        if (!GR_VALID(fr)) {
            *ret = GR_X("rear p1: fisher-yates failed");
            free(phot_idx); free(order_idx);
            ctx_abort(ctx);
            pthread_barrier_wait(&ctx->barrier_rq);
            pthread_barrier_wait(&ctx->barrier_rc);
            return ret;
        }

        /*
         * QBER: compare raw sifted_key (received_bit) against
         * alice_raw[photon].alice_bit (original pre-noise bit).
         * sifted_key is indexed by photon position.
         *
         * This is measured BEFORE Cascade -- errors are real
         * channel + eavesdropper errors, not yet corrected.
         */
        RatioQBER qber = { .errors = 0u, .sample = BB84_SAMPLE_N };

        for (size_t s = 0u; s < BB84_SAMPLE_N; s++) {
            size_t    sift_pos  = order_idx[s];
            size_t    phot      = phot_idx[sift_pos];
            uint8_t   alice_bit = store->alice_raw[phot].alice_bit;
            GateState gs        = store->sifted_key[phot];
            uint8_t   bob_raw   = (gs == GATE_1) ? 1u : 0u;

            if (alice_bit != bob_raw) qber.errors++;

            store->sample_sift_idx[s] = sift_pos;
        }

        store->qber_e_num = qber_to_enum(qber);

        free(phot_idx);
        free(order_idx);

        if (!qber_accept(qber)) {
            store->session_gate = GR_X(
                "QBER exceeded 11% threshold -- session abort");
            *ret = store->session_gate;
            ctx_abort(ctx);
            pthread_barrier_wait(&ctx->barrier_rq);
            pthread_barrier_wait(&ctx->barrier_rc);
            return ret;
        }

        *ret = GR_1(qber.errors);
    }

    /* Signal RECONCILE: QBER done, sample positions written */
    pthread_barrier_wait(&ctx->barrier_rq);

    /* Wait for Cascade to complete */
    pthread_barrier_wait(&ctx->barrier_rc);

    if (ctx_aborted(ctx)) {
        *ret = GR_X("upstream Gate-X (RECONCILE)");
        return ret;
    }

    /* ==============================================================
     * PHASE 2 -- PA on reconciled_key
     * reconciled_key : PROT_READ (sealed by RECONCILE)
     * ==============================================================
     */
    {
        uint64_t h_val   = he_lookup(store->qber_e_num);
        uint64_t two_h   = 2u * h_val;
        size_t   n_pa    = store->reconciled_len;

        if (two_h >= RATIO_DENOM || n_pa == 0u) {
            store->session_gate = GR_X(
                "h(e) >= 0.5: no secure bits extractable");
            *ret = store->session_gate;
            return ret;
        }

        uint64_t numerator  = (uint64_t)n_pa * (RATIO_DENOM - two_h);
        uint64_t final_raw  = numerator / RATIO_DENOM;
        uint64_t leaked     = (uint64_t)store->parity_bits_leaked;

        if (final_raw <= leaked + SECURITY_PARAM) {
            store->session_gate = GR_X(
                "PA length <= 0 after leakage and security margin");
            *ret = store->session_gate;
            return ret;
        }

        size_t   final_bits = (size_t)(final_raw - leaked - SECURITY_PARAM);
        uint64_t *pa_out    = calloc(words_for_bits(final_bits),
                                     sizeof *pa_out);
        if (!pa_out) {
            *ret = GR_X("rear p2: pa_out alloc failed");
            return ret;
        }

        GateResult hr = toeplitz_hash(store->reconciled_key,
                                      n_pa, pa_out, final_bits);
        if (!GR_VALID(hr)) { free(pa_out); *ret = hr; return ret; }

        size_t final_bytes = (final_bits + 7u) / 8u;
        store->final_len   = final_bytes;

        for (size_t i = 0u; i < final_bytes; i++) {
            uint8_t byte = 0u;
            for (int b = 0; b < 8; b++) {
                size_t bi = i * 8u + (size_t)b;
                if (bi < final_bits && bit_get(pa_out, bi))
                    byte |= (uint8_t)(1u << b);
            }
            store->final_key[i] = byte;
        }

        memset(pa_out, 0u, words_for_bits(final_bits) * sizeof *pa_out);
        free(pa_out);

        /*
         * Key confirmation -- verify Alice and Bob's reconciled
         * bits match before committing final_key.
         *
         * alice_confirm() packs Alice's non-sample bits and compares
         * word-by-word against reconciled_key (Bob's Cascade output).
         * Mismatch means Cascade left uncorrected errors -- the PA
         * outputs would differ even with the same Toeplitz seed.
         * Abort rather than emit a split key.
         *
         * This is the simulation equivalent of the authenticated
         * channel hash exchange. Leakage already charged to
         * SECURITY_PARAM = 64 bits.
         */
        if (!alice_confirm(store)) {
            store->session_gate = GR_X(
                "key confirmation failed -- reconciliation error");
            *ret = store->session_gate;
            return ret;
        }

        store->confirm_hash = confirm_hash_fn(store->final_key,
                                              final_bytes);

        GateResult sr = ramstore_seal_rear(store);
        if (!GR_VALID(sr)) { *ret = sr; return ret; }

        store->session_gate = GR_1((uint64_t)final_bytes);
        *ret = store->session_gate;
    }

    return ret;
}
