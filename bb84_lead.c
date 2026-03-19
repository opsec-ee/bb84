/*
 ==================================================================
 * @file    bb84_lead.c
 * @version 2.1
 * @brief   LEAD sidecar -- classical basis reconciliation
 *
 * Waits for FRONT (barrier_fl). Checks abort_flag before reading
 * alice_raw. Produces sifted_key[] (I2 precursor).
 *
 * Pipeline:
 *   1. pthread_barrier_wait(barrier_fl)
 *   2. ctx_aborted() check -- return GR_X if set
 *   3. For each photon i:
 *        I4 = (alice_basis == bob_basis)
 *        if I4: sifted_key[i] = received_bit ? GATE_1 : GATE_0
 *        else:  sifted_key[i] = GATE_X
 *   4. ramstore_seal_lead -> sifted_key PROT_READ
 *   5. Reach barrier_lr -- RECONCILE unblocks
 *
 * Classical channel note:
 *   In real BB84 Alice and Bob exchange basis choices over an
 *   authenticated public channel. Here both alice_basis and
 *   bob_basis are in alice_raw (set by FRONT). LEAD reads both
 *   directly. The simulation collapses the authenticated channel
 *   into a direct read; correctness is preserved.
 *
 * FRONT: alice_raw sealed -- FRONT's committed output (AS)
 * LEAD:  (alice_basis == bob_basis) per photon -- basis test (Pivot)
 * REAR:  sifted_key[] sealed -- GATE_0/1 for matches, GATE_X for mismatches (IS)
 *   Z: never
 *   X: upstream abort, or seal failure
 *   1: sifted_key sealed, store->sifted_len set
 *
 * Contract: {{0 [ BB84Ctx* (AS/.\IS) GateResult* ] 1}}
 ==================================================================
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include "bb84_sidecar.h"
#include "bb84_ramstore.h"

void *bb84_lead(void *arg)
{
    BB84Ctx  *ctx   = arg;
    RAMStore *store = ctx->store;

    GateResult *ret = malloc(sizeof *ret);
    if (!ret) {
        ctx_abort(ctx);
        pthread_barrier_wait(&ctx->barrier_fl);
        pthread_barrier_wait(&ctx->barrier_lr);
        return nullptr;
    }    *ret = GR_Z("lead not yet run");

    /*
     * Wait for FRONT -- full memory fence via POSIX barrier.
     * alice_raw is PROT_READ and fully written after this point.
     */
    pthread_barrier_wait(&ctx->barrier_fl);

    if (ctx_aborted(ctx)) {
        *ret = GR_X("upstream Gate-X (FRONT)");
        goto barrier_lr;
    }

    /*
     ==================================================================
     * Basis reconciliation (I4 computation)
     *
     * alice_raw : PROT_READ (sealed by FRONT)
     * sifted_key: PROT_READ|PROT_WRITE (not yet sealed)
     ==================================================================
     */
    {
        size_t sifted_len = 0u;

        for (size_t i = 0u; i < BB84_N_PHOTONS; i++) {
            const QCell *cell = &store->alice_raw[i];

            if (cell->alice_basis == cell->bob_basis) {
                store->sifted_key[i] =
                    cell->received_bit ? GATE_1 : GATE_0;
                sifted_len++;
            } else {
                store->sifted_key[i] = GATE_X;
            }
        }

        store->sifted_len     = sifted_len;
        store->reconciled_words = words_for_bits(sifted_len);

        if (sifted_len < BB84_SAMPLE_N + SECURITY_PARAM) {
            *ret = GR_X("insufficient sifted bits for sample + security");
            ctx_abort(ctx);
            goto seal_lead;
        }

seal_lead:;
        GateResult sr = ramstore_seal_lead(store);
        if (!GR_VALID(sr)) {
            *ret = sr;
            ctx_abort(ctx);
            goto barrier_lr;
        }

        if (!ctx_aborted(ctx))
            *ret = GR_1((uint64_t)sifted_len);
    }

barrier_lr:
    pthread_barrier_wait(&ctx->barrier_lr);
    return ret;
}
