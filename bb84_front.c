/*
 ==================================================================
 * @file    bb84_front.c
 * @version 2.1
 * @brief   FRONT sidecar -- quantum channel
 *
 * Produces invariant I1: alice_raw[] with basis pairs and bits.
 *
 * Pipeline:
 *   1. Bulk getrandom -- three arrays + noise array, all at once
 *      to minimize syscall overhead
 *   2. Per-photon:
 *        alice_basis   = rng_bases_a[i] & 1
 *        bob_basis     = rng_bases_b[i] & 1
 *        alice_bit     = rng_bits[i] & 1
 *        received_bit  = alice_bit XOR coin_flip(rng_noise[i], NOISE_RATE_N)
 *        measurement   = GATE_Z (set by LEAD, not FRONT)
 *   3. ramstore_seal_front -> alice_raw PROT_READ
 *   4. Reach barrier_fl -- LEAD unblocks
 *
 * XOR invertibility:
 *   received = alice XOR noise
 *   alice    = received XOR noise  (XOR is its own inverse)
 *   Reconciliation corrects residual noise without requiring
 *   explicit noise knowledge.
 *
 * Abort protocol:
 *   Any failure sets ctx_abort() before barrier_fl.
 *   LEAD checks ctx_aborted() after barrier_fl before reading.
 *
 * FRONT: getrandom for alice_bases[], bob_bases[], bits[], noise[] (AS)
 * LEAD:  coin_flip(rng,NOISE_RATE_N) per photon -- noise injection (Pivot)
 * REAR:  alice_raw[i] -- committed QCell array, PROT_READ (IS)
 *   Z: never (thread always launches)
 *   X: getrandom failure or seal failure
 *   1: alice_raw sealed, BB84_N_PHOTONS QCells written
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

void *bb84_front(void *arg)
{
    BB84Ctx  *ctx   = arg;
    RAMStore *store = ctx->store;

    GateResult *ret = malloc(sizeof *ret);
    if (!ret) {
        ctx_abort(ctx);
        pthread_barrier_wait(&ctx->barrier_fl);
        return nullptr;
    }
    *ret = GR_Z("front not yet run");

    /*
     ==================================================================
     * Bulk RNG -- four getrandom calls, one per array.
     * Stack-allocated; zeroed before return (key material hygiene).
     * coin_flip is pure -- no IO in the photon loop.
     ==================================================================
     */
    uint8_t rng_bases_a[BB84_N_PHOTONS];
    uint8_t rng_bases_b[BB84_N_PHOTONS];
    uint8_t rng_bits   [BB84_N_PHOTONS];
    uint64_t rng_noise [BB84_N_PHOTONS];

    GateResult r;

    r = rng_bytes(rng_bases_a, BB84_N_PHOTONS);
    if (!GR_VALID(r)) { *ret = r; goto abort; }

    r = rng_bytes(rng_bases_b, BB84_N_PHOTONS);
    if (!GR_VALID(r)) { *ret = r; goto abort; }

    r = rng_bytes(rng_bits, BB84_N_PHOTONS);
    if (!GR_VALID(r)) { *ret = r; goto abort; }

    r = rng_bytes(rng_noise, BB84_N_PHOTONS * sizeof(uint64_t));
    if (!GR_VALID(r)) { *ret = r; goto abort; }

    /*
     ==================================================================
     * Photon loop -- pure after RNG, no IO, no branching on secrets
     ==================================================================
     */
    for (size_t i = 0u; i < BB84_N_PHOTONS; i++) {
        uint8_t alice_bit = rng_bits[i] & 1u;
        uint8_t noise     = coin_flip(rng_noise[i], NOISE_RATE_N) ? 1u : 0u;

        store->alice_raw[i] = (QCell){
            .alice_basis  = (Basis)(rng_bases_a[i] & 1u),
            .bob_basis    = (Basis)(rng_bases_b[i] & 1u),
            .alice_bit    = alice_bit,
            .received_bit = (uint8_t)(alice_bit ^ noise),
            .measurement  = GATE_Z,
            ._pad         = {0, 0, 0},
        };
    }

    r = ramstore_seal_front(store);
    if (!GR_VALID(r)) { *ret = r; goto abort; }

    *ret = GR_1(BB84_N_PHOTONS);
    goto cleanup;

abort:
    ctx_abort(ctx);

cleanup:
    memset(rng_bases_a, 0, sizeof rng_bases_a);
    memset(rng_bases_b, 0, sizeof rng_bases_b);
    memset(rng_bits,    0, sizeof rng_bits);
    memset(rng_noise,   0, sizeof rng_noise);
    pthread_barrier_wait(&ctx->barrier_fl);
    return ret;
}
