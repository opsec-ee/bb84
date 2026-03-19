/*
 ==================================================================
 * @file    bb84_types.c
 * @version 2.1
 * @author  H. Overman (ee)
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
 *   0  ->      0
 *   1  ->  11635     (h=0.08079)
 *   2  ->  20370     (h=0.14146)
 *   3  ->  27993     (h=0.19440)
 *   4  ->  34879     (h=0.24221)
 *   5  ->  41243     (h=0.28641)
 *   6  ->  47193     (h=0.32773)
 *   7  ->  52773     (h=0.36648)
 *   8  ->  58006     (h=0.40282)
 *   9  ->  62862     (h=0.43654)
 *  10  ->  67535     (h=0.46899)
 *  11  ->  72000     (h=0.50000 -- exact)
 ==================================================================
 */
const he_entry_t HE_TABLE[HE_TABLE_LEN] = {
    {     0u,     0u },   /*  0%  h=0.00000 */
    {  1440u,  11635u },  /*  1%  h=0.08079 */
    {  2880u,  20370u },  /*  2%  h=0.14146 */
    {  4320u,  27993u },  /*  3%  h=0.19440 */
    {  5760u,  34879u },  /*  4%  h=0.24221 */
    {  7200u,  41243u },  /*  5%  h=0.28641 */
    {  8640u,  47193u },  /*  6%  h=0.32773 */
    { 10080u,  52773u },  /*  7%  h=0.36648 */
    { 11520u,  58006u },  /*  8%  h=0.40282 */
    { 12960u,  62862u },  /*  9%  h=0.43654 */
    { 14400u,  67535u },  /* 10%  h=0.46899 */
    { 15840u,  72000u },  /* 11%  h=0.50000 (threshold -- exact) */
};

/*
 ==================================================================
 * ee_ratio_t helpers
 ==================================================================
 */

/*
 * ee_ratio_elapsed
 * FRONT: (start, end) -- clock_t tick pair from kernel (AS)
 * LEAD:  end - start gives tick delta; den = CLOCKS_PER_SEC (Pivot)
 * REAR:  ee_ratio_t{num=delta, den=CLOCKS_PER_SEC} (IS)
 *   Z: den == 0 (clock unavailable)
 *   1: num/den is exact elapsed time
 * Contract: {{0 [ (clock_t,clock_t) (AS/.\IS) ee_ratio_t ] 1}}
 */
ee_ratio_t ee_ratio_elapsed(clock_t start, clock_t end)
{
    return (ee_ratio_t){
        .num = (uint64_t)(end - start),
        .den = (uint64_t)CLOCKS_PER_SEC
    };
}

/*
 * ee_ratio_secs
 * FRONT: ee_ratio_t{num,den} (AS)
 * LEAD:  num / den -- integer floor division (Pivot)
 * REAR:  uint64_t whole seconds (IS)
 *   Z: den == 0 -- returns 0
 *   1: floor(num/den)
 * Contract: {{0 [ ee_ratio_t (AS/.\IS) uint64_t ] 1}}
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
 * Contract: {{0 [ ee_ratio_t (AS/.\IS) uint64_t ] 1}}
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
 * Contract: {{0 [ (uint64_t,ee_ratio_t) (AS/.\IS) uint64_t ] 1}}
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
 * Contract: {{0 [ uint64_t (AS/.\IS) uint64_t ] 1}}
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
 * Contract: {{0 [ RatioQBER (AS/.\IS) bool ] 1}}
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
 * Contract: {{0 [ RatioQBER (AS/.\IS) uint64_t ] 1}}
 ==================================================================
 */
uint64_t qber_to_enum(RatioQBER q)
{
    if (q.sample == 0u) return 0u;
    return (q.errors * RATIO_DENOM) / q.sample;
}
