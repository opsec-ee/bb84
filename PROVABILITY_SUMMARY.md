# PROVABILITY SUMMARY — BB84 QKD Simulation v2.2

```
Build:
  [x] Release: zero warnings, zero errors
  [x] ASan+UBSan: zero errors (detect_leaks=0, LSAN suppressed)
  [x] Noisy build: Gate-X fires correctly at 25% noise (0/8 sessions)

Tests:
  [x] Self-test: PASS (8 checks)
  [x] Check 1: he_lookup(0) == 0
  [x] Check 2: he_lookup(QBER_THRESH_N) == RATIO_DENOM
  [x] Check 3: qber_accept({0, 256}) == true
  [x] Check 4: qber_accept({29, 256}) == false
  [x] Check 5: words_for_bits(64) == 1
  [x] Check 6: words_for_bits(65) == 2
  [x] Check 7: HE_TABLE[3] spot-check (3%, 27992)
  [x] Check 8: qber_to_enum({3,100}) == 4320

Invariants:
  [x] static_assert: 6 compile-time checks pass
  [x] Security invariant stated in IFP block
  [x] Phase ordering: MEASURE before CORRECT (QBER on raw key)
  [x] RAMStore sealing: mprotect PROT_READ per phase in causal order
  [x] Gate-X rate ~5% at 3% noise (Binomial(256,0.03) tail)

Contracts:
  [x] 45 contracts across 14 files, all three standpoints named
  [x] (AS/.IS) zero instances (none claimed)
  [x] (AS/--WAS): 27  (AS/++PLUS): 6  (--): 5
  [x] 135 [[nodiscard]] annotations
  [x] LEAD names specific operation on every contract
  [x] Two-phase REAR has two explicit phase contracts (P1)
  [x] No recomputation of in-scope reconciled_words (P2)
  [x] cascade_k[] has formula + derivation + spot-checks (P3)

Numerical claims:
  [x] RATIO_DENOM = 144000 = 2^7 * 3^2 * 5^3  CONFIRMED
  [x] QBER_THRESH_N = 15840 = 11% * 144000     CONFIRMED
  [x] NOISE_RATE_N = 4320 = 3% * 144000        CONFIRMED
  [x] HE_TABLE[1] = 11634                       CONFIRMED (Python)
  [x] HE_TABLE[3] = 27992                       CONFIRMED (Python)
  [x] HE_TABLE[9] = 62852                       CONFIRMED (Python)
  [x] confirm_hash seed: per-session getrandom -- fixed seed removed
  [x] cascade_k[] = [8,16,32,64]                CONFIRMED (Python)
  [x] PA overflow bound 2048*144000 < 2^64      CONFIRMED

Standards:
  [x] ISO C23 clean (-std=c2x -Wpedantic)
  [x] No constexpr (replaced with #define)
  [x] No assert() (replaced with Gate-X or static_assert)
  [x] No IEEE 754 (all arithmetic via ee_ratio_t or integer)
  [x] No printf %f/%e/%g (ratio display only)
  [x] Stale reference sweep: zero ppo-2/3/4, zero constexpr

Performance:
  [x] CLOCK_MONOTONIC wall-time (not clock())
  [x] Spread documented as scheduler artifact, not algorithmic
  [x] Throughput: ~54k-120k photons/s (session-dependent)

Sign-off:
  [x] Author: H. Overman (ee)
  [ ] Reviewer: LeeMetaXTRON -- PENDING
```
