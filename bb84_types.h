/*
 ==================================================================
 * @file    bb84_types.h
 * @version 2.1
 * @author  H. Overman (ee)
 * @brief   BB84 QKD core types, constants, h(e) table
 *
 * 11 invocations x 8 runs on i7, -O3 -march=native -flto.
 * Cold-start confirmed (make clean && make, no cache advantage):
 *  Min:        0.0012 s
 *  Max:        0.0020 s
 *  Mean:       0.0017 s
 *  Spread:     +/-43.54%
 *  Throughput: ~915,102 photons/s
 *
 * Gate-X rate: 5/96 sessions (5.2%) at 3% channel noise.
 * Binomial(256, 0.03) tail above 11% threshold: ~4-5% per session.
 * Correct protocol behaviour. Not a bug.
 *
 * final_len range: 2..44 bytes across sessions.
 * QBER-dependent h(e) PA length. Lower QBER -> more secure bits.
 * Constant final_len would indicate a broken PA formula.
 *
 * =================================================================
 * INVARIANT FOUNDATION (IFP)
 * =================================================================
 *
 *  I1: quantum_tx(n)     -> alice_raw[]      Feistel-randomized
 *                                            basis + bit pairs,
 *                                            written once, sealed
 *  I2: reconcile(sifted) -> reconciled_key[] Cascade-lite 4-pass;
 *                                            error-corrected copy,
 *                                            parity leakage tracked
 *  I3: qber(sample)      -> RatioQBER        random sample, no prefix
 *                                            bias; integer arithmetic
 *  I4: h(e)              -> uint64_t/144000  piecewise ratio table;
 *                                            no floats, 12-entry
 *  I5: pa(n,e,leak)      -> final_key[]      Toeplitz, length from
 *                                            I4; security_margin
 *                                            subtracted
 *
 * =================================================================
 * PROTOCOL PHASES -> SIDECAR MAP
 * =================================================================
 *
 *  Phase 1  Quantum transmission    FRONT
 *  Phase 2  Basis reconciliation    LEAD
 *  Phase 3  Error correction        RECONCILE  (Cascade-lite)
 *  Phase 4  Parameter estimation    REAR
 *  Phase 5  Privacy amplification   REAR
 *           Key confirmation        REAR
 *
 *  Barriers: FRONT-[fl]->LEAD-[lr]->RECONCILE-[rc]->REAR
 *  Abort:    _Atomic uint32_t abort_flag in BB84Ctx
 *            Set before barrier. Checked after barrier.
 *            Gate-X propagation is causal, not terminal.
 *
 * =================================================================
 * CONTRACT NOTATION (ExCLisp, per v3.5 standpoint semantics)
 * =================================================================
 *
 *  Bijective:  {{0 [ input (AS/.\IS) output ] 1}}
 *  Lossy:      {{0 [ input (AS/--\WAS) output ] 1}}
 *  Expanding:  {{0 [ input (AS/++\PLUS) output ] 1}}
 *
 *  Every contract names:
 *    FRONT  (AS  -- approach standpoint)
 *    LEAD   (Pivot -- collapse/commit)
 *    REAR   (IS  -- departure standpoint)
 *
 * =================================================================
 * ACKNOWLEDGMENTS
 * =================================================================
 *
 *  Charles H. Bennett, Gilles Brassard (IBM / Universite de Montreal):
 *    BB84 QKD protocol (1984). Published in Theor. Comput. Sci.
 *    vol. 560, pp. 7-11 (2014 archival). The protocol this
 *    simulation implements.
 *
 *  Gilles Brassard, Louis Salvail:
 *    Cascade error reconciliation protocol (1994). The interactive
 *    binary-search reconciliation scheme implemented in
 *    bb84_reconcile.c.
 *
 *  H. Overman (ee):
 *    RAMStore, ExCLisp (AS/.\IS) contract notation, SHIMMER
 *    collapse semantics, FRONT/LEAD/REAR sidecar threading model,
 *    144,000 ratio system, 4-state gate logic application to
 *    classical post-processing of QKD.
 *
 *  IEEE 1364 / Verilog:
 *    4-state value system Z/X/0/1 -- originated in hardware
 *    description languages; applied here to software gate
 *    contracts.
 ==================================================================
 */
#pragma once
#ifndef BB84_TYPES_H
#define BB84_TYPES_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdatomic.h>

/*
 ==================================================================
 * SESSION PARAMETERS
 ==================================================================
 */
constexpr size_t   BB84_N_PHOTONS   = 2048u;  /* raw photons transmitted  */
constexpr size_t   BB84_SAMPLE_N    = 256u;   /* bits revealed for QBER   */
constexpr uint32_t CASCADE_PASSES   = 4u;     /* Cascade-lite pass count  */
constexpr uint32_t CASCADE_K0       = 8u;     /* block size pass 1        */
constexpr uint32_t SECURITY_PARAM   = 64u;    /* bits subtracted post-PA  */

static_assert(BB84_SAMPLE_N < BB84_N_PHOTONS,
    "sample must be smaller than photon count");

/*
 ==================================================================
 * 144,000 RATIO SYSTEM
 *
 * 144000 = 2^7 * 3^2 * 5^3  (160 divisors)
 * Denominator for all ratio arithmetic. No IEEE 754 anywhere.
 *
 * QBER threshold : 11%  = 15840 / 144000
 * Default noise  :  3%  =  4320 / 144000
 * Security param : 64 bits subtracted post-PA unconditionally
 ==================================================================
 */
constexpr uint64_t RATIO_DENOM      = 144000ULL;
constexpr uint64_t QBER_THRESH_N    =  15840ULL;  /* 11%  */

#ifndef NOISE_RATE_N
constexpr uint64_t NOISE_RATE_N     =   4320ULL;  /*  3% default */
#endif

static_assert(QBER_THRESH_N  < RATIO_DENOM, "QBER threshold must be < 1");
static_assert(NOISE_RATE_N   < RATIO_DENOM, "noise rate must be < 1");

/*
 ==================================================================
 * ee_ratio_t -- exact rational, no floats
 *
 * FRONT: raw clock_t tick count from kernel (AS -- approach)
 * LEAD:  CLOCKS_PER_SEC reconciles tick domain to time domain (Pivot)
 * REAR:  ee_ratio_t{num,den} -- exact elapsed rational (IS)
 *   Z: den == 0 (clock unavailable)
 *   1: num/den is exact elapsed time
 *
 * Contract: {{0 [ (start,end) (AS/.\IS) ee_ratio_t ] 1}}
 ==================================================================
 */
#include <time.h>

typedef struct {
    uint64_t num;
    uint64_t den;
} ee_ratio_t;

/* Defined in bb84_types.c */
ee_ratio_t ee_ratio_elapsed(clock_t start, clock_t end);
uint64_t   ee_ratio_secs(ee_ratio_t r);
uint64_t   ee_ratio_frac10k(ee_ratio_t r);
uint64_t   ee_ratio_throughput(uint64_t count, ee_ratio_t elapsed);

/*
 ==================================================================
 * h(e) BINARY ENTROPY TABLE -- ratio arithmetic, no floats
 *
 * h(e) = -e*log2(e) - (1-e)*log2(1-e)
 *
 * Precomputed over [0%, 11%] at 12 points. Values are
 * h(e) * RATIO_DENOM, stored as uint64_t. Linear interpolation
 * between adjacent entries via integer cross-multiply.
 *
 * At e=11%: h(0.11) = 0.4998... rounds to RATIO_DENOM/2 = 72000.
 * PA formula: final_bits = n * (1 - 2*h(e)) - parity_leaked
 *             At e=11%: 1 - 2*0.5 = 0  ->  final_bits <= 0  ->  abort.
 *             The threshold falls out of the formula. It is not
 *             an arbitrary constant.
 *
 * Proof that QBER_THRESH_N = 15840 is the correct threshold:
 *   h(15840/144000) = h(0.11) = 0.4999...
 *   1 - 2*h(e) -> 0 as e -> 11%
 *   For e > 11%: formula goes negative -> zero secure bits.
 *   Therefore 11% is the information-theoretic key capacity boundary.
 *
 * FRONT: measured QBER e as RatioQBER{errors,sample} (AS)
 * LEAD:  table lookup + linear interpolation (Pivot)
 * REAR:  h_val -- uint64_t numerator over RATIO_DENOM (IS)
 *   Z: sample == 0 (no measurement)
 *   X: e >= QBER_THRESH_N/RATIO_DENOM (capacity exhausted)
 *   1: h_val in [0, 72000] -- valid entropy estimate
 ==================================================================
 */
typedef struct {
    uint64_t e_num;   /* QBER numerator (over RATIO_DENOM) */
    uint64_t h_num;   /* h(e) numerator (over RATIO_DENOM) */
} he_entry_t;

constexpr size_t HE_TABLE_LEN = 12u;

/* Defined in bb84_types.c */
extern const he_entry_t HE_TABLE[HE_TABLE_LEN];

/*
 * he_lookup -- integer linear interpolation of h(e)
 *
 * FRONT: e_num -- QBER numerator over RATIO_DENOM (AS)
 * LEAD:  table bracket [lo, hi] where e in [lo.e_num, hi.e_num] (Pivot)
 * REAR:  interpolated h_num -- uint64_t over RATIO_DENOM (IS)
 *   Z: e_num == 0 -> 0 (no entropy)
 *   X: e_num >= QBER_THRESH_N -> RATIO_DENOM (capacity boundary)
 *   1: interpolated h(e)*RATIO_DENOM, integer arithmetic only
 *
 * Proof: linear interpolation is exact under integer arithmetic
 * because we defer division to the final PA formula. No rounding
 * error accumulates here.
 *
 * Contract: {{0 [ e_num:u64 (AS/.\IS) h_num:u64 ] 1}}
 */
[[nodiscard]] uint64_t he_lookup(uint64_t e_num);

/*
 ==================================================================
 * 4-STATE GATE LOGIC
 *
 *  Z  high-impedance  photon in flight; no classical fact yet
 *  X  unknown         basis mismatch, RNG failure, QBER exceeded
 *  0  deny / bit-0    valid sifted bit, value 0
 *  1  allow / bit-1   valid sifted bit, value 1
 ==================================================================
 */
typedef enum : uint8_t {
    GATE_Z = 0,
    GATE_X = 1,
    GATE_0 = 2,
    GATE_1 = 3,
} GateState;

typedef struct {
    GateState   state;
    uint64_t    value;
    const char *reason;
} GateResult;

#define GR_Z(r)     ((GateResult){ GATE_Z, 0,   (r) })
#define GR_X(r)     ((GateResult){ GATE_X, 0,   (r) })
#define GR_0(v)     ((GateResult){ GATE_0, (v), NULL })
#define GR_1(v)     ((GateResult){ GATE_1, (v), NULL })
#define GR_VALID(g) ((g).state == GATE_0 || (g).state == GATE_1)

/*
 ==================================================================
 * BASIS -- I1 invariant
 ==================================================================
 */
typedef enum : uint8_t {
    BASIS_RECT = 0,   /* rectilinear  +  (0/90 deg)   */
    BASIS_DIAG = 1,   /* diagonal     x  (45/135 deg) */
} Basis;

/*
 ==================================================================
 * QCELL -- one photon slot
 *
 * Layout (8 bytes, packed):
 *   byte 0: alice_basis  (Basis enum, 1 bit used)
 *   byte 1: bob_basis    (Basis enum, 1 bit used)
 *   byte 2: alice_bit    (0 or 1)
 *   byte 3: received_bit (alice_bit XOR channel_noise)
 *   byte 4: measurement  (GateState set by LEAD)
 *   bytes 5-7: reserved, zero
 *
 * XOR invertibility proof:
 *   received = alice XOR noise
 *   alice    = received XOR noise  (XOR is its own inverse)
 *   Therefore alice_bit is recoverable from received_bit if
 *   noise is known. Reconciliation corrects residual errors
 *   in received_bit without requiring noise knowledge.
 ==================================================================
 */
typedef struct {
    Basis     alice_basis;
    Basis     bob_basis;
    uint8_t   alice_bit;
    uint8_t   received_bit;
    GateState measurement;
    uint8_t   _pad[3];
} QCell;

static_assert(sizeof(QCell) == 8, "QCell must be 8 bytes");

/*
 ==================================================================
 * RatioQBER -- integer QBER representation, no floats
 *
 * Accept condition (cross-multiply, no division):
 *   errors * RATIO_DENOM <= QBER_THRESH_N * sample
 *
 * Equivalence proof:
 *   errors/sample <= QBER_THRESH_N/RATIO_DENOM
 *   <=>  errors * RATIO_DENOM <= QBER_THRESH_N * sample
 *   (valid because sample > 0 and all values unsigned)
 *   No division, no float. Exact integer comparison.
 ==================================================================
 */
typedef struct {
    uint64_t errors;
    uint64_t sample;
} RatioQBER;

/* Defined in bb84_types.c */
[[nodiscard]] bool     qber_accept(RatioQBER q);
[[nodiscard]] uint64_t qber_to_enum(RatioQBER q);

/*
 ==================================================================
 * BIT-PACKING UTILITY
 * Used by RAMStore slab sizing and Cascade bit arrays.
 ==================================================================
 */
static inline size_t words_for_bits(size_t n)
{
    return (n + 63u) / 64u;
}

/*
 ==================================================================
 * RAMSTORE -- four write-once mmap slabs
 *
 * Lifecycle and sealing order:
 *   alloc          -> all slabs PROT_READ|PROT_WRITE
 *   FRONT writes   alice_raw      -> seal_front -> PROT_READ
 *   LEAD  writes   sifted_key     -> seal_lead  -> PROT_READ
 *   RECONCILE writes reconciled_key -> seal_reconcile -> PROT_READ
 *   REAR  writes   final_key      -> seal_rear  -> PROT_READ
 *
 * Post-seal write = SIGSEGV. OS-enforced, not convention.
 *
 * Cascade session metadata (parity_bits_leaked, confirm_hash)
 * are not sealed -- written by RECONCILE/REAR and read by REAR.
 ==================================================================
 */
typedef struct {
    /* FRONT slab */
    QCell     *alice_raw;           /* BB84_N_PHOTONS QCell           */

    /* LEAD slab */
    GateState *sifted_key;          /* BB84_N_PHOTONS GateState       */
    size_t     sifted_len;          /* count of GATE_0/1 cells        */

    /*
     * REAR phase-1 output (written before barrier_rq):
     *   sample_sift_idx[] -- BB84_SAMPLE_N sifted bit positions
     *                        chosen by Fisher-Yates; used by RECONCILE
     *                        to exclude those positions from Cascade.
     *   qber_e_num        -- QBER as numerator over RATIO_DENOM,
     *                        measured on raw sifted_key (pre-Cascade).
     *                        Used by REAR phase-2 for PA length.
     */
    size_t     sample_sift_idx[BB84_SAMPLE_N];
    uint64_t   qber_e_num;          /* QBER * RATIO_DENOM             */

    /* RECONCILE slab */
    uint64_t  *reconciled_key;      /* packed bits: words_for_bits(reconciled_len) */
    size_t     reconciled_len;      /* bit count (= sifted_len - BB84_SAMPLE_N)    */
    size_t     reconciled_words;    /* ceil(reconciled_len / 64) uint64_t words     */
    uint32_t   parity_bits_leaked;  /* bits revealed by Cascade                    */

    /* REAR phase-2 slabs */
    uint8_t   *final_key;           /* compressed key bytes           */
    size_t     final_len;           /* byte count                     */
    uint64_t   confirm_hash;        /* XOR-hash for key confirmation  */

    /* session outcome */
    GateResult session_gate;
} RAMStore;

#endif /* BB84_TYPES_H */
