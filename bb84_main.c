/*
 ==================================================================
 * @file    bb84_main.c
 * @version 2.1
 * @brief   BB84 QKD simulation entry point and 8-run bench
 *
 * Four sidecar threads, three barriers:
 *
 *   FRONT --[fl]--> LEAD --[lr]--> RECONCILE --[rc]--> REAR
 *
 * Timing via ee_ratio_t (no IEEE 754).
 * 8-run bench computes min/max/mean/spread entirely in ratio
 * arithmetic -- no floats, no printf %f.
 *
 * Build (release):
 *   gcc -std=c23 -O3 -march=native -flto -Wall -Wextra -DNDEBUG \
 *       -funroll-loops -lpthread                                  \
 *       bb84_main.c bb84_ramstore.c bb84_front.c bb84_lead.c     \
 *       bb84_reconcile.c bb84_rear.c -o bb84
 *
 * Build (debug):
 *   gcc -std=c23 -O0 -g -Wall -Wextra -lpthread                  \
 *       bb84_main.c bb84_ramstore.c bb84_front.c bb84_lead.c     \
 *       bb84_reconcile.c bb84_rear.c -o bb84_dbg
 *
 * Build (asan):
 *   gcc -std=c23 -O1 -g -fsanitize=address,undefined             \
 *       -fno-omit-frame-pointer -lpthread                        \
 *       bb84_main.c bb84_ramstore.c bb84_front.c bb84_lead.c     \
 *       bb84_reconcile.c bb84_rear.c -o bb84_asan
 ==================================================================
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>
#include "bb84_types.h"
#include "bb84_ramstore.h"
#include "bb84_sidecar.h"
#include "bb84_selftest.h"

constexpr int BENCH_RUNS = 8;

/*
 ==================================================================
 * PRINT HELPERS -- all ratio arithmetic, no floats
 ==================================================================
 */

static const char *gate_str(GateState s)
{
    switch (s) {
    case GATE_Z: return "Z (undefined)";
    case GATE_X: return "X (Gate-X)";
    case GATE_0: return "0 (bit-0)";
    case GATE_1: return "1 (ok)";
    }
    return "?";
}

static void print_gate(const char *label, GateResult g)
{
    printf("  %-28s  [%s]  value=%-8" PRIu64 "  %s\n",
           label, gate_str(g.state), g.value,
           g.reason ? g.reason : "");
}

static void print_ratio(const char *label, uint64_t n, uint64_t d)
{
    uint64_t pct_int  = (n * 100u) / d;
    uint64_t pct_frac = ((n * 10000u) / d) % 100u;
    printf("  %-28s  %" PRIu64 "/%" PRIu64
           "  (%2" PRIu64 ".%02" PRIu64 "%%)\n",
           label, n, d, pct_int, pct_frac);
}

static void print_elapsed(const char *label, ee_ratio_t r)
{
    printf("  %-28s  %" PRIu64 ".%04" PRIu64 " s\n",
           label,
           ee_ratio_secs(r),
           ee_ratio_frac10k(r));
}

/*
 ==================================================================
 * RUN_SESSION -- single BB84 session
 *
 * FRONT: void (AS)
 * LEAD:  four sidecar threads + three barriers (Pivot)
 * REAR:  session_gate + final_len in store (IS)
 *   X: any allocation, barrier init, or pthread failure
 *   1: session complete, results in store
 *
 * Contract: {{0 [ (store*,elapsed*) (AS/.\IS) GateResult ] 1}}
 ==================================================================
 */
[[nodiscard]]
static GateResult run_session(RAMStore *store, ee_ratio_t *elapsed)
{
    BB84Ctx ctx = {0};
    atomic_store(&ctx.abort_flag, 0u);
    ctx.store = store;

    GateResult alloc = ramstore_alloc(store);
    if (!GR_VALID(alloc)) return alloc;

    pthread_barrier_init(&ctx.barrier_fl, nullptr, 2); /* FRONT + LEAD          */
    pthread_barrier_init(&ctx.barrier_lr, nullptr, 3); /* LEAD + REAR + RECONCILE */
    pthread_barrier_init(&ctx.barrier_rq, nullptr, 2); /* REAR + RECONCILE      */
    pthread_barrier_init(&ctx.barrier_rc, nullptr, 2); /* RECONCILE + REAR      */

    clock_t t0 = clock();

    pthread_t front_tid, lead_tid, rec_tid, rear_tid;
    pthread_create(&front_tid, nullptr, bb84_front,     &ctx);
    pthread_create(&lead_tid,  nullptr, bb84_lead,      &ctx);
    pthread_create(&rec_tid,   nullptr, bb84_reconcile, &ctx);
    pthread_create(&rear_tid,  nullptr, bb84_rear,      &ctx);

    GateResult *fr = nullptr, *lr = nullptr,
               *rr = nullptr, *rear_r = nullptr;
    pthread_join(front_tid, (void **)&fr);
    pthread_join(lead_tid,  (void **)&lr);
    pthread_join(rec_tid,   (void **)&rr);
    pthread_join(rear_tid,  (void **)&rear_r);

    clock_t t1 = clock();
    *elapsed = ee_ratio_elapsed(t0, t1);

    if (fr)     free(fr);
    if (lr)     free(lr);
    if (rr)     free(rr);
    if (rear_r) free(rear_r);

    pthread_barrier_destroy(&ctx.barrier_fl);
    pthread_barrier_destroy(&ctx.barrier_lr);
    pthread_barrier_destroy(&ctx.barrier_rq);
    pthread_barrier_destroy(&ctx.barrier_rc);

    return store->session_gate;
}

/*
 ==================================================================
 * PRINT_SESSION -- detailed report for a single session
 ==================================================================
 */
static void print_session(const RAMStore *store,
                          ee_ratio_t      elapsed,
                          int             run_num)
{
    printf("\n--- Run %d ---\n", run_num);

    printf("Protocol:\n");
    print_ratio("noise rate",    NOISE_RATE_N,   RATIO_DENOM);
    print_ratio("QBER threshold",QBER_THRESH_N,  RATIO_DENOM);

    printf("\nSession:\n");
    print_gate("session_gate", store->session_gate);
    printf("  %-28s  %zu bits (~%" PRIu64 "%% of %zu)\n",
           "sifted_len",
           store->sifted_len,
           (uint64_t)(store->sifted_len * 100u) / BB84_N_PHOTONS,
           BB84_N_PHOTONS);
    printf("  %-28s  %" PRIu32 " bits\n",
           "cascade_parity_leaked",
           store->parity_bits_leaked);
    printf("  %-28s  %zu bytes (%zu bits)\n",
           "final_len",
           store->final_len,
           store->final_len * 8u);
    printf("  %-28s  %016" PRIx64 "  %s\n",
           "confirm_hash",
           store->confirm_hash,
           store->session_gate.state == GATE_1 ? "[verified]" : "");

    if (store->session_gate.state == GATE_1 && store->final_len > 0u) {
        printf("\nFinal key (first 32 bytes):\n  ");
        size_t show = store->final_len < 32u ? store->final_len : 32u;
        for (size_t i = 0u; i < show; i++)
            printf("%02x", store->final_key[i]);
        if (store->final_len > 32u)
            printf(" ...(+%zu bytes)", store->final_len - 32u);
        printf("\n");
    }

    printf("\nPerformance (ee_ratio_t -- no IEEE 754):\n");
    print_elapsed("elapsed", elapsed);
    printf("  %-28s  %" PRIu64 " photons/s\n",
           "throughput",
           ee_ratio_throughput((uint64_t)BB84_N_PHOTONS, elapsed));
}

/*
 ==================================================================
 * BENCH -- 8-run timing in ratio arithmetic
 *
 * min/max/mean all computed as uint64_t numerators over
 * CLOCKS_PER_SEC. Spread = (max-min)*100/mean as integer %.
 * No floats.
 ==================================================================
 */
static void bench(void)
{
    printf("\n==========================================\n");
    printf("8-run benchmark\n");
    printf("==========================================\n");

    uint64_t times[BENCH_RUNS];
    uint64_t sum  = 0u;
    uint64_t mn   = UINT64_MAX;
    uint64_t mx   = 0u;
    int      ok   = 0;

    for (int r = 0; r < BENCH_RUNS; r++) {
        RAMStore   store   = {0};
        ee_ratio_t elapsed = {0};

        GateResult gr = run_session(&store, &elapsed);
        ramstore_free(&store);

        times[r] = elapsed.num;
        sum      += elapsed.num;

        if (elapsed.num < mn) mn = elapsed.num;
        if (elapsed.num > mx) mx = elapsed.num;

        if (gr.state == GATE_1) ok++;

        printf("  run %d: %" PRIu64 ".%04" PRIu64 " s  [%s]\n",
               r + 1,
               elapsed.num / elapsed.den,
               ((elapsed.num % elapsed.den) * 10000u) / elapsed.den,
               gate_str(gr.state));
    }

    uint64_t mean      = sum / (uint64_t)BENCH_RUNS;
    uint64_t den       = times[0] ? times[0] : 1u;  /* use CLOCKS_PER_SEC */
    (void)den;

    /* Use CLOCKS_PER_SEC as denominator for all ratio prints */
    uint64_t cps = (uint64_t)CLOCKS_PER_SEC;

    printf("\nResults (ee_ratio_t -- no IEEE 754):\n");
    printf("  Min:    %" PRIu64 ".%04" PRIu64 " s\n",
           mn / cps, ((mn % cps) * 10000u) / cps);
    printf("  Max:    %" PRIu64 ".%04" PRIu64 " s\n",
           mx / cps, ((mx % cps) * 10000u) / cps);
    printf("  Mean:   %" PRIu64 ".%04" PRIu64 " s\n",
           mean / cps, ((mean % cps) * 10000u) / cps);

    if (mean > 0u) {
        uint64_t spread_int  = (mx - mn) * 100u / mean;
        uint64_t spread_frac = ((mx - mn) * 10000u / mean) % 100u;
        printf("  Spread: +/-%" PRIu64 ".%02" PRIu64 "%%\n",
               spread_int, spread_frac);
    }

    printf("  OK:     %d/%d sessions\n\n", ok, BENCH_RUNS);
}

/*
 ==================================================================
 * MAIN
 ==================================================================
 */
int main(void)
{
    printf("BB84 QKD Simulation v2.1\n");
    printf("C23 / Cascade-lite + h(e) PA + RAMStore + 4-sidecar\n");
    printf("==========================================\n");

    /*
     * Self-test before any external interaction (ppo-2).
     * Checks known mathematical truths on the ratio system
     * and bit-packing. Halts on any failure.
     */
    {
        GateResult st = bb84_self_test();
        if (!GR_VALID(st)) {
            fprintf(stderr,
                "startup self-test FAILED: %s\n",
                st.reason ? st.reason : "unknown");
            return 1;
        }
        printf("  self-test                   PASS (%llu checks)\n",
               (unsigned long long)st.value);
    }
    printf("  photons          = %zu\n",   BB84_N_PHOTONS);
    printf("  sample_n         = %zu\n",   BB84_SAMPLE_N);
    printf("  cascade_passes   = %u\n",    CASCADE_PASSES);
    printf("  cascade_k0       = %u\n",    CASCADE_K0);
    printf("  security_param   = %u bits\n", SECURITY_PARAM);
    print_ratio("noise rate",     NOISE_RATE_N,   RATIO_DENOM);
    print_ratio("QBER threshold", QBER_THRESH_N,  RATIO_DENOM);
    printf("==========================================\n");

    /* Single detailed session */
    RAMStore   store   = {0};
    ee_ratio_t elapsed = {0};

    GateResult gr        = run_session(&store, &elapsed);
    (void)gr;
    print_session(&store, elapsed, 1);

    GateState final_gate = store.session_gate.state;
    ramstore_free(&store);

    /* 8-run bench */
    bench();

    return (final_gate == GATE_1) ? 0 : 1;
}
