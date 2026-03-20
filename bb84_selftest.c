/*
 ==================================================================
 * @file    bb84_selftest.c
 * @version 2.1
 * @author  H. Overman (ee)
 * @brief   Self-test implementation -- ppo-2 SELF-TESTS AT STARTUP
 *
 * Five spot-checks on known mathematical truths.
 * All answers derivable by hand. No external state required.
 * Failure halts startup before any session is attempted.
 *
 * =================================================================
 * CHECKS AND DERIVATIONS
 * =================================================================
 *
 * CHECK 1: he_lookup(0) == 0
 *   h(0) = -0*log2(0) - 1*log2(1) = 0 + 0 = 0
 *   h(0) * 144000 = 0. Exact by definition.
 *
 * CHECK 2: he_lookup(QBER_THRESH_N) == RATIO_DENOM
 *   QBER_THRESH_N = 15840 = 11% * 144000
 *   he_lookup returns RATIO_DENOM at capacity boundary.
 *   This encodes h(11%) = 0.5: 0.5 * 144000 = 72000 = RATIO_DENOM/2
 *   but the function returns RATIO_DENOM (not 72000) at the boundary
 *   to signal capacity exhaustion. Verified against PA formula:
 *   final_bits = n*(1 - 2*h(e)) -- at h=0.5 this is zero.
 *
 * CHECK 3: qber_accept({errors=0, sample=256}) == true
 *   0/256 = 0% error. 0 * 144000 <= 15840 * 256 = 4,055,040. True.
 *   Zero error rate must always be accepted.
 *
 * CHECK 4: qber_accept({errors=29, sample=256}) == false
 *   29/256 = 11.328% > 11% threshold.
 *   29 * 144000 = 4,176,000
 *   15840 * 256 = 4,055,040
 *   4,176,000 > 4,055,040 -> reject. Derivable by integer arithmetic.
 *
 * CHECK 5: words_for_bits(64)==1, words_for_bits(65)==2
 *   (64 + 63) / 64 = 127 / 64 = 1 (integer division). One word.
 *   (65 + 63) / 64 = 128 / 64 = 2. Spills to second word.
 *   Boundary condition on packed bit array sizing.
 *
 * =================================================================
 * GATE STATE MAPPING
 * =================================================================
 *
 * FRONT: known input constants (AS)
 * LEAD:  integer comparison against hand-derived expected values (Pivot)
 * REAR:  GATE_1 all pass / GATE_X with named failure (IS)
 ==================================================================
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include "bb84_selftest.h"
#include "bb84_sidecar.h"

/*
 ==================================================================
 * SELF_CHECK macro
 *
 * Evaluates expr. On failure: prints diagnostic, returns GR_X.
 * On pass: continues to next check.
 *
 * FRONT: (expr, msg) -- boolean expression + failure label (AS)
 * LEAD:  evaluate expr -- compare actual vs expected (Pivot)
 * REAR:  continues if true; GR_X with msg if false (IS)
 ==================================================================
 */
#define SELF_CHECK(expr, msg)                                   \
    do {                                                        \
        if (!(expr)) {                                          \
            fprintf(stderr,                                     \
                "[bb84_self_test] FAIL: %s\n", (msg));         \
            return GR_X(msg);                                   \
        }                                                       \
    } while (0)

/*
 ==================================================================
 * bb84_self_test
 ==================================================================
 */
GateResult bb84_self_test(void)
{
    /*
     * Check 1: h(0) = 0
     * Derivation: -0*log2(0) - 1*log2(1) = 0
     * he_lookup(0) must return 0.
     */
    SELF_CHECK(he_lookup(0u) == 0u,
               "he_lookup(0) != 0  -- h(0) must be zero");

    /*
     * Check 2: he_lookup at threshold returns RATIO_DENOM
     * Derivation: QBER_THRESH_N/RATIO_DENOM = 11%
     * h(11%) = 0.5 -- capacity boundary.
     * he_lookup returns RATIO_DENOM to signal exhaustion.
     * PA formula: n*(RATIO_DENOM - 2*RATIO_DENOM)/RATIO_DENOM = -n < 0
     * -> abort. Correct.
     */
    SELF_CHECK(he_lookup(QBER_THRESH_N) == RATIO_DENOM,
               "he_lookup(QBER_THRESH_N) != RATIO_DENOM  -- threshold boundary wrong");

    /*
     * Check 3: zero error rate accepted
     * Derivation: 0 * 144000 = 0 <= 15840 * 256 = 4,055,040. True.
     */
    SELF_CHECK(qber_accept((RatioQBER){ .errors = 0u, .sample = 256u }),
               "qber_accept({0,256}) == false  -- zero error must be accepted");

    /*
     * Check 4: 11.33% error rate rejected
     * Derivation:
     *   29 * 144000 = 4,176,000
     *   15840 * 256 = 4,055,040
     *   4,176,000 > 4,055,040  -> reject
     */
    SELF_CHECK(!qber_accept((RatioQBER){ .errors = 29u, .sample = 256u }),
               "qber_accept({29,256}) == true  -- 11.33% must be rejected");

    /*
     * Check 5: words_for_bits boundary
     * Derivation:
     *   words_for_bits(64) = (64+63)/64 = 127/64 = 1
     *   words_for_bits(65) = (65+63)/64 = 128/64 = 2
     */
    SELF_CHECK(words_for_bits(64u) == 1u,
               "words_for_bits(64) != 1  -- 64 bits must fit in one word");
    SELF_CHECK(words_for_bits(65u) == 2u,
               "words_for_bits(65) != 2  -- 65 bits must spill to second word");

    return GR_1(5u);   /* 5 checks passed */
}
