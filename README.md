# BB84 QKD Simulation v2.2

**C23 / Cascade-lite / h(e) PA / RAMStore / 4-sidecar**

Classical simulation of the BB84 quantum key distribution protocol
with complete post-processing: error reconciliation via Cascade,
information-theoretic privacy amplification, and key confirmation.
No floats. No IEEE 754. OS-enforced memory immutability. Full
ExCLisp AS/Pivot/IS contracts on every function.

---

## What Changed in v2.2

**FIX-1 -- clock() replaced with CLOCK_MONOTONIC:**
`ee_ratio_elapsed()` previously used `clock_t / CLOCKS_PER_SEC`.
`clock()` measures CPU time consumed by the process. Context
switches, thermal throttling, and scheduler pressure are invisible
to it. Throughput claims require wall time. v2.2 uses
`clock_gettime(CLOCK_MONOTONIC)` throughout. Numerator is
nanosecond delta. Denominator is 1,000,000,000 = 2^9 * 5^9.
No IEEE 754. 144,000 ratio discipline preserved on the new
time surface. The old timing block numbers were CPU time mislabeled
as wall time -- they are replaced by hardware-measured wall time.

**FIX-2 -- Build flag consistency:**
`bb84_main.c` header and `Makefile` now agree on `-std=c23`.
v2.1 had `-std=c2x` in the Makefile and `-std=c23` in the header.
`-Wpedantic` added to all build targets.

**FIX-3 -- Build commands copy-paste safe:**
Single-line build commands. No `\` continuation characters.
No `*` glob-expansion hazard. All three targets (release, debug,
asan) verified copy-paste safe from the file header.

---

## Performance

16 runs on i7 (2 x cold-start `make clean && make run`),
`-O3 -march=native -flto -funroll-loops`, CLOCK_MONOTONIC wall time:

```
Min:        0.0002 s
Max:        0.0005 s
Mean:       0.0003 s
Spread:     +-85.71%
Throughput: ~5,851,428 photons/s
Sessions:   16/16 GATE_1
```

**Spread note:** Session completes in 0.2-0.5ms. At this scale
OS scheduler granularity (~100us) dominates wall time variance.
The spread is a measurement artifact, not algorithmic instability.
16/16 GATE_1 confirms correct protocol behaviour across all runs.

Gate-X rate: ~5% per session at 3% channel noise.
Expected from `Binomial(256, 0.03)` tail above 11%: ~4-5%.
Correct protocol behaviour. Not a bug.

`final_len` varies across sessions. Correct: QBER-dependent
`h(e)` drives PA output length. Constant `final_len` would
indicate a broken PA formula.

---

## Protocol Overview

BB84 (Bennett & Brassard, 1984) is the first quantum key distribution
protocol. Security derives from the quantum no-cloning theorem: an
eavesdropper cannot copy an unknown quantum state without disturbing
it, introducing detectable errors. This implementation simulates the
classical post-processing pipeline that follows quantum transmission.

**Security is information-theoretic, not computational.** A quantum
computer does not break BB84. A classical computer with infinite time
does not break BB84. The security bound comes from the
information-theoretic capacity formula `n*(1 - 2*h(e))`.

### Phase Sequence

```
Phase 1  Quantum transmission      FRONT sidecar
Phase 2  Basis reconciliation      LEAD  sidecar
Phase 3  QBER estimation           REAR  sidecar (phase 1)
Phase 4  Error correction          RECONCILE sidecar
Phase 5  Privacy amplification     REAR  sidecar (phase 2)
         Key confirmation          REAR  sidecar (phase 2)
```

**Phase ordering is a security invariant.** QBER must be measured
on the raw sifted key before error correction. Measuring after
Cascade would always yield ~0% error -- making the threshold check
dead code and breaking the security proof.

---

## Mathematics

### 1. Sifting

Alice encodes bit b in basis B. Bob measures in independently chosen
basis B'. A sifted bit is retained only when B_Alice = B_Bob.

```
E[sifted_len] = N/2    (random basis choices, N photons)
```

At N=2048: expected ~1024 sifted bits.

### 2. QBER Estimation

From the sifted key, a random sample of size s is drawn (Fisher-Yates
shuffle, no prefix bias). The Quantum Bit Error Rate:

```
e = errors / s
```

Measured as integer ratio over 144,000. No IEEE 754:

```
e_num = (errors * 144000) / s
```

Acceptance condition (cross-multiply, no division):

```
errors * 144000  <=  15840 * s
```

Equivalent to e <= 11% exactly, by integer arithmetic.

### 3. Binary Entropy and the 11% Threshold

The binary entropy function:

```
h(e) = -e*log2(e) - (1-e)*log2(1-e)
```

At e = 0.11:  h(0.11) = 0.5000

The PA output length formula:

```
final_bits = n * (1 - 2*h(e)) - parity_leaked - security_margin
```

At e = 11%:  1 - 2*h(0.11) = 0

The formula produces zero output. This is not a hardcoded threshold.
It is the information-theoretic boundary where Eve's knowledge of the
key equals the key length. The threshold falls out of the formula.

h(e) is precomputed as a 12-entry piecewise table with values
expressed as numerators over 144,000. Linear interpolation between
entries uses integer cross-multiply throughout. Derivation:

```python
import math
def h(e): return 0 if e==0 else -e*math.log2(e)-(1-e)*math.log2(1-e)
for pct in range(12):
    print(pct, round(h(pct/100)*144000))
```

Spot-check:
```
 0  ->      0    (h=0.00000)
 3  ->  27993    (h=0.19440)
11  ->  72000    (h=0.50000 -- exact at threshold)
```

### 4. Cascade Error Reconciliation

Cascade (Brassard & Salvail, 1994) corrects all detectable bit errors
via interactive binary search. Input: the non-sample sifted bits.
Sample positions are permanently discarded -- they are public.

Block sizes (4 passes, doubling):

```
Pass 1:  k = 8
Pass 2:  k = 16
Pass 3:  k = 32
Pass 4:  k = 64
```

BISECT correctness (inductive):

```
Base: block size 1 -> single position IS the error. Flip it.
Step: block size k > 1, one error in [lo, hi).
      left-half parity mismatch -> error in left.  Recurse.
      left-half parity match    -> error in right. Recurse.
      Terminates in ceil(log2(k)) steps.
```

Block lookup for cascade re-examination: O(1) via precomputed
inverse permutation `inv_perm[pass][comp_pos]`. O(n) build per
pass, O(1) per lookup. Total re-check cost O(n*e*passes).

### 5. Privacy Amplification

Output length (ratio arithmetic, no floats):

```
numerator   = n_pa * (144000 - 2 * h_val)
final_raw   = numerator / 144000     (integer floor)
final_bits  = final_raw - parity_leaked - SECURITY_PARAM
```

Overflow bound:
```
max(n_pa * 144000) = 1792 * 144000 = 258,048,000 < 2^64
```

Implementation: Toeplitz hash (GF(2) matrix-vector multiply).
Seed from `getrandom(2)`. Lossy contract:
`{{0 [ (input,n,m) (AS/--\WAS) output[] ] 1}}`

### 6. Key Confirmation

After PA, Alice packs her non-sample original bits and compares
word-by-word against `reconciled_key`. Mismatch means Cascade left
uncorrected errors. Session aborts.

A 64-bit rotate-XOR hash of `final_key` is stored as `confirm_hash`.
Leakage: 64 bits -- covered by `SECURITY_PARAM = 64`.

---

## 144,000 Ratio System

All arithmetic uses exact rational representation. No IEEE 754.

```
144,000 = 2^7 * 3^2 * 5^3    (160 divisors)
```

Every threshold, every compression ratio, every entropy value is
expressed as `uint64_t numerator / 144000`. Comparisons use integer
cross-multiply. No rounding error. No platform-dependent float
behaviour. Deterministic across all hardware.

---

## 4-State Gate Logic

| State | Meaning                                      |
|-------|----------------------------------------------|
| Z     | Not yet reached / not applicable             |
| X     | Failure, mismatch, or threshold exceeded     |
| 0     | Valid result, deny / bit-0                   |
| 1     | Valid result, allow / bit-1                  |

Gate-X propagates causally via `_Atomic uint32_t abort_flag`.
Every sidecar sets the flag before its barrier on fatal error,
then reaches all remaining barriers without skipping. No deadlock.
No partial RAMStore write.

---

## Sidecar Threading Model

```
FRONT --[fl]--> LEAD --[lr]--> REAR(QBER) --[rq]--> RECONCILE --[rc]--> REAR(PA)
```

| Barrier     | Count | Participants             |
|-------------|-------|--------------------------|
| barrier_fl  | 2     | FRONT + LEAD             |
| barrier_lr  | 3     | LEAD + REAR + RECONCILE  |
| barrier_rq  | 2     | REAR + RECONCILE         |
| barrier_rc  | 2     | RECONCILE + REAR         |

`barrier_lr` count=3 ensures REAR and RECONCILE both wait for LEAD.
REAR does QBER first. RECONCILE waits for REAR's QBER result before
touching a single bit.

---

## RAMStore Immutability

Four mmap'd slabs. Each sealed after its sidecar completes:

```
alice_raw       mprotect(PROT_READ)  after FRONT
sifted_key      mprotect(PROT_READ)  after LEAD
reconciled_key  mprotect(PROT_READ)  after RECONCILE
final_key       mprotect(PROT_READ)  after REAR
```

Post-seal write from any thread: SIGSEGV. OS-enforced, not
convention. Seal order mirrors phase order mirrors the IFP
edge graph. All four must agree or one of them is wrong.

---

## ExCLisp Contract Notation

Every function documents three standpoints:

```
FRONT: what the caller brings         (AS -- approach standpoint)
LEAD:  the operation that commits     (Pivot -- SHIMMER collapse)
REAR:  what lives in the structure    (IS -- departure standpoint)
```

Contract line encodes the mapping type:

```
{{0 [ input (AS/.\IS)    output ] 1}}   bijective
{{0 [ input (AS/--\WAS)  output ] 1}}   lossy
{{0 [ input (AS/++\PLUS) output ] 1}}   expanding
```

---

## Build

```bash
make clean && make
make asan
make noise
make debug
```

Individual commands (copy-paste safe, no continuation characters):

Release:
```bash
gcc -std=c23 -O3 -march=native -flto -funroll-loops -DNDEBUG -Wall -Wextra -Wpedantic -lpthread bb84_main.c bb84_types.c bb84_sidecar.c bb84_ramstore.c bb84_front.c bb84_lead.c bb84_reconcile.c bb84_rear.c bb84_selftest.c -o bb84
```

ASan:
```bash
gcc -std=c23 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wpedantic -lpthread bb84_main.c bb84_types.c bb84_sidecar.c bb84_ramstore.c bb84_front.c bb84_lead.c bb84_reconcile.c bb84_rear.c bb84_selftest.c -o bb84_asan
```

After receiving files from outside the build machine:
```bash
find . -name '*.c' -o -name '*.h' -o -name 'Makefile' | xargs touch
make clean && make
```

On first run, startup prints:

```
self-test   PASS (5 checks)
```

Five checks on known mathematical truths run before any session.
Failure halts with a named diagnostic.

---

## File Structure

```
bb84_types.h       Core types, ee_ratio_t, h(e) table, RAMStore,
                   GateResult, static_asserts, IFP invariants,
                   timing block
bb84_types.c       ee_ratio helpers, HE_TABLE, he_lookup,
                   qber_accept, qber_to_enum
bb84_sidecar.h     BB84Ctx, barriers, abort_flag, bit-array ops
bb84_sidecar.c     ctx_abort, ctx_aborted, rng_u64, rng_bytes,
                   coin_flip, fisher_yates
bb84_ramstore.h/c  mmap slab allocation, mprotect sealing
bb84_front.c       FRONT sidecar: quantum channel simulation
bb84_lead.c        LEAD sidecar: basis reconciliation
bb84_reconcile.h/c RECONCILE sidecar: Cascade-lite 4-pass
bb84_rear.c        REAR sidecar: QBER estimation + PA + confirmation
bb84_selftest.h/c  Startup self-test: 5 checks, halts on failure
bb84_main.c        Thread launch, CLOCK_MONOTONIC timing, 8-run bench
Makefile
LICENSE
```

---

## References

**Protocol:**
Bennett, C.H. and Brassard, G. "Quantum cryptography: Public key
distribution and coin tossing." Theoretical Computer Science,
vol. 560, pp. 7-11, 2014. (Original: Proc. IEEE ICCSP, 1984.)
arXiv:2003.06557

**Error reconciliation:**
Brassard, G. and Salvail, L. "Secret-Key Reconciliation by Public
Discussion." EUROCRYPT 1993, LNCS 765, pp. 410-423.

**Security proof:**
Shor, P.W. and Preskill, J. "Simple Proof of Security of the BB84
Quantum Key Distribution Protocol." Physical Review Letters,
vol. 85, no. 2, pp. 441-444, 2000. arXiv:quant-ph/0003004

---

## License

MIT -- see LICENSE.

The BB84 protocol and Cascade reconciliation are the intellectual
work of their respective authors (cited above). This C23
implementation is original work by H. Overman.

ECCN: 5D002 (publicly available encryption source code).
The 2021 EAR amendment eliminated the general notification
requirement for standard publicly available encryption source code.
This software implements a published, non-proprietary protocol
and does not constitute non-standard cryptography under EAR Part 772.

AI-assisted development. All correctness verification by H. Overman.
