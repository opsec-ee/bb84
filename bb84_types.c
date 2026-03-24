/*
 ==================================================================
 * @file    bb84_types.c
 * @version 2.2
 * @author  H. Overman (ee)
 * @license MIT -- Copyright (c) 2026 H. Overman (ee)
 * @brief   ee_ratio_t helpers, h(e) table and lookup,
 *          RatioQBER functions
 *
 * All function definitions that belong in a .c file, not a header.
 * bb84_types.h contains only typedefs, structs, constants,
 * static_asserts, macros, and extern prototypes.
 ==================================================================
 */
#include "bb84_types.h"

/*
 ==================================================================
 * HE_TABLE -- binary entropy precomputed over [0%, 11%]
 *
 * Correctness verification (Python):
 *   import math
 *   def h(e): return 0 if e==0 else -e*math.log2(e)-(1-e)*math.log2(1-e)
 *   for pct in range(12): print(pct, round(h(pct/100)*144000))
 *
 *   0  ->      0      (exact)
 *   1  ->  11634     (h=0.08079)  CONFIRMED: round(-0.01*log2(0.01)-0.99*log2(0.99)*144000)=11634
 *   2  ->  20367     (h=0.14144)
 *   3  ->  27992     (h=0.19439)  CONFIRMED: round(-0.03*log2(0.03)-0.97*log2(0.97)*144000)=27992
 *   4  ->  34890     (h=0.24229)
 *   5  ->  41241     (h=0.28640)
 *   6  ->  47152     (h=0.32744)
 *   7  ->  52693     (h=0.36592)
 *   8  ->  57914     (h=0.40218)
 *   9  ->  62852     (h=0.43647)  CONFIRMED: round(-0.09*log2(0.09)-0.91*log2(0.91)*144000)=62852
 *  10  ->  67535     (h=0.46899)
 *  11  ->  71988     (h=0.49991 -- he_lookup returns RATIO_DENOM at threshold)
 ==================================================================
 */
const he_entry_t HE_TABLE[HE_TABLE_LEN] = {
    {     0u,     0u },   /*  0%  h=0.00000  exact                              */
    {  1440u,  11634u },  /*  1%  h=0.08079  round(h(1/100)*144000)=11634       */
    {  2880u,  20367u },  /*  2%  h=0.14144  round(h(2/100)*144000)=20367       */
    {  4320u,  27992u },  /*  3%  h=0.19439  round(h(3/100)*144000)=27992       */
    {  5760u,  34890u },  /*  4%  h=0.24229  round(h(4/100)*144000)=34890       */
    {  7200u,  41241u },  /*  5%  h=0.28640  round(h(5/100)*144000)=41241       */
    {  8640u,  47152u },  /*  6%  h=0.32744  round(h(6/100)*144000)=47152       */
    { 10080u,  52693u },  /*  7%  h=0.36592  round(h(7/100)*144000)=52693       */
    { 11520u,  57914u },  /*  8%  h=0.40218  round(h(8/100)*144000)=57914       */
    { 12960u,  62852u },  /*  9%  h=0.43647  round(h(9/100)*144000)=62852       */
    { 14400u,  67535u },  /* 10%  h=0.46899  round(h(10/100)*144000)=67535      */
    { 15840u,  71988u },  /* 11%  h=0.49991  round(h(11/100)*144000)=71988      */
    /*                                                                           */
    /* NOTE: 11% entry h_num=71988 (not 72000). The exact h(0.11)=71987.898.    */
    /* he_lookup returns RATIO_DENOM=144000 for e >= QBER_THRESH_N, never       */
    /* the table value at index 11. The 11% row is a bracket endpoint only.     */
    /* The threshold gate fires at he_lookup() before the table is reached.     */
};

/*
 ==================================================================
 * ee_ratio_t helpers
 ==================================================================
 */

/*
 * ee_ratio_elapsed
 * FRONT: (t0, t1) -- CLOCK_MONOTONIC timespec pair (AS)
 * LEAD:  (t1.sec-t0.sec)*1e9 + (t1.nsec-t0.nsec) -- ns delta (Pivot)
 *        Exact integer. No IEEE 754.
 * REAR:  ee_ratio_t{num=ns_delta, den=1,000,000,000} (IS)
 *   Z: impossible by construction
 *   1: exact wall time rational, monotonically non-decreasing
 * Contract: {{0 [ (timespec,timespec) (AS/--\WAS) ee_ratio_t ] 1}}
 *            Lossy: only ns delta preserved; t0, t1 not recoverable.
 */
ee_ratio_t ee_ratio_elapsed(struct timespec t0, struct timespec t1)
{
    uint64_t ns = (uint64_t)(t1.tv_sec  - t0.tv_sec)  * 1000000000ull
                + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    return (ee_ratio_t){ .num = ns, .den = 1000000000ull };
}

/*
 * ee_ratio_secs
 * FRONT: ee_ratio_t{num,den} (AS)
 * LEAD:  num / den -- integer floor division (Pivot)
 * REAR:  uint64_t whole seconds (IS)
 *   Z: den == 0 -- returns 0
 *   1: floor(num/den)
 * Contract: {{0 [ ee_ratio_t (AS/--\WAS) uint64_t ] 1}}
 */
uint64_t ee_ratio_secs(ee_ratio_t r)
{
    return r.den ? r.num / r.den : 0u;
}

/*
 * ee_ratio_frac10k
 * FRONT: ee_ratio_t{num,den} (AS)
 * LEAD:  (num % den) * 10000 / den -- fractional part scaled (Pivot)
 * REAR:  uint64_t fractional seconds in units of 0.0001 s (IS)
 *   Z: den == 0 -- returns 0
 *   1: 4-digit fractional part of num/den
 * Contract: {{0 [ ee_ratio_t (AS/--\WAS) uint64_t ] 1}}
 */
uint64_t ee_ratio_frac10k(ee_ratio_t r)
{
    if (!r.den) return 0u;
    return ((r.num % r.den) * 10000u) / r.den;
}

/*
 * ee_ratio_throughput
 * FRONT: (count, elapsed) -- item count + ee_ratio_t time (AS)
 * LEAD:  count * elapsed.den / elapsed.num -- items per second (Pivot)
 * REAR:  uint64_t items/second, integer arithmetic (IS)
 *   Z: elapsed.num == 0 -- returns 0 (no time elapsed)
 *   1: exact integer items/second
 * Contract: {{0 [ (uint64_t,ee_ratio_t) (AS/--\WAS) uint64_t ] 1}}
 */
uint64_t ee_ratio_throughput(uint64_t count, ee_ratio_t elapsed)
{
    if (!elapsed.num) return 0u;
    return (count * elapsed.den) / elapsed.num;
}

/*
 ==================================================================
 * he_lookup -- integer linear interpolation of h(e)
 *
 * FRONT: e_num -- QBER as numerator over RATIO_DENOM (AS)
 * LEAD:  bracket search + cross-multiply interpolation (Pivot)
 * REAR:  h_num -- h(e)*RATIO_DENOM, integer arithmetic (IS)
 *   Z: e_num == 0 -> 0
 *   X: e_num >= QBER_THRESH_N -> RATIO_DENOM (capacity boundary)
 *   1: interpolated h(e)*RATIO_DENOM in [0, 72000]
 *
 * Proof: linear interpolation defers division to last step only.
 * No rounding error accumulates.
 * Contract: {{0 [ uint64_t (AS/--\WAS) uint64_t ] 1}}
 *            Lossy: piecewise linear projection; not invertible.
 ==================================================================
 */
uint64_t he_lookup(uint64_t e_num)
{
    if (e_num == 0u)             return 0u;
    if (e_num >= QBER_THRESH_N)  return RATIO_DENOM;

    size_t lo = 0u;
    size_t hi = HE_TABLE_LEN - 1u;

    for (size_t i = 0u; i < HE_TABLE_LEN - 1u; i++) {
        if (e_num >= HE_TABLE[i].e_num &&
            e_num <  HE_TABLE[i + 1u].e_num) {
            lo = i;
            hi = i + 1u;
            break;
        }
    }

    uint64_t e_lo   = HE_TABLE[lo].e_num;
    uint64_t e_hi   = HE_TABLE[hi].e_num;
    uint64_t h_lo   = HE_TABLE[lo].h_num;
    uint64_t h_hi   = HE_TABLE[hi].h_num;
    uint64_t e_span = e_hi - e_lo;

    if (e_span == 0u) return h_lo;

    uint64_t h_span = (h_hi > h_lo) ? h_hi - h_lo : h_lo - h_hi;
    uint64_t frac   = h_span * (e_num - e_lo) / e_span;

    return (h_hi >= h_lo) ? h_lo + frac : h_lo - frac;
}

/*
 ==================================================================
 * qber_accept
 *
 * FRONT: RatioQBER{errors,sample} -- measured channel error pair (AS)
 * LEAD:  errors*RATIO_DENOM <= QBER_THRESH_N*sample (Pivot)
 *        Cross-multiply: no division, no float.
 * REAR:  bool -- session proceed/abort decision (IS)
 *   Z: sample == 0 -> false (conservative)
 *   0: QBER above threshold -- abort indicated
 *   1: QBER at or below threshold -- channel acceptable
 * Contract: {{0 [ RatioQBER (AS/--\WAS) bool ] 1}}
 ==================================================================
 */
bool qber_accept(RatioQBER q)
{
    if (q.sample == 0u) return false;
    return q.errors * RATIO_DENOM <= QBER_THRESH_N * q.sample;
}

/*
 ==================================================================
 * qber_to_enum
 *
 * FRONT: RatioQBER{errors,sample} -- measured error pair (AS)
 * LEAD:  (errors * RATIO_DENOM) / sample -- ratio normalisation (Pivot)
 * REAR:  uint64_t e_num -- QBER as numerator over RATIO_DENOM (IS)
 *   Z: sample == 0 -> 0
 *   1: e_num in [0, RATIO_DENOM]; monotone in errors/sample
 * Contract: {{0 [ RatioQBER (AS/--\WAS) uint64_t ] 1}}
 ==================================================================
 */
uint64_t qber_to_enum(RatioQBER q)
{
    if (q.sample == 0u) return 0u;
    return (q.errors * RATIO_DENOM) / q.sample;
}
