BB84 QKD simulation — C23, Cascade-lite, h(e) PA, 4-pass 4-sidecar, RAMStore

# BB84 QKD Simulation v2.1

**C23 / Cascade-lite / h(e) PA / RAMStore / 4-sidecar**

Classical simulation of the BB84 quantum key distribution protocol
with complete post-processing: error reconciliation via Cascade,
information-theoretic privacy amplification, and key confirmation.
No floats. OS-enforced memory immutability. Full ExCLisp AS/Pivot/IS
contracts on every function.

---

## Protocol Overview

BB84 (Bennett & Brassard, 1984) is the first quantum key distribution
protocol. Security derives from the quantum no-cloning theorem: an
eavesdropper cannot copy an unknown quantum state without disturbing
it, introducing detectable errors. This implementation simulates the
classical post-processing pipeline that follows quantum transmission.

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
on the raw sifted key *before* error correction. Measuring after
Cascade would always yield ~0% error — making the threshold check
dead code and breaking the security proof.

---

## Mathematics

### 1. Sifting

Alice encodes bit b ∈ {0,1} in basis β ∈ {+, ×}. Bob measures
in independently chosen basis β'. A sifted bit is retained only
when β_Alice = β_Bob.

```
E[sifted_len] = N/2    (random basis choices, N photons)
```

At N=2048: expected ~1024 sifted bits. Observed: 994–1063.

### 2. QBER Estimation

From the sifted key, a random sample of size s is drawn (Fisher-Yates
shuffle, no prefix bias). The Quantum Bit Error Rate:

```
e = errors / s
```

Measured as integer ratio over 144,000 — no IEEE 754:

```
e_num = (errors × 144000) / s
```

Acceptance condition (cross-multiply, no division):

```
errors × 144000  ≤  15840 × s
```

Equivalent to e ≤ 11% exactly, by integer arithmetic.

### 3. Binary Entropy and the 11% Threshold

The binary entropy function:

```
h(e) = -e·log₂(e) - (1-e)·log₂(1-e)
```

At e = 0.11:  h(0.11) ≈ 0.5000

The PA output length formula (see §5) is:

```
final_bits = n · (1 - 2·h(e)) - parity_leaked - security_margin
```

At e = 11%:  1 - 2·h(0.11) = 1 - 2·0.5 = 0

The formula produces zero output. This is not a hardcoded threshold —
it is the information-theoretic boundary where Eve's knowledge of the
key equals the key length. The threshold *falls out* of the formula.

h(e) is precomputed as a 12-entry piecewise table with values
expressed as numerators over 144,000. Linear interpolation between
entries uses integer cross-multiply throughout. Derivation:

```python
import math
def h(e): return 0 if e==0 else -e*math.log2(e)-(1-e)*math.log2(1-e)
for pct in range(12):
    print(pct, round(h(pct/100)*144000))
```

### 4. Cascade Error Reconciliation

Cascade (Brassard & Salvail, 1994) corrects all detectable bit errors
via interactive binary search. Input: the non-sample sifted bits
(sample positions are permanently discarded — they are public).

**Block sizes (4 passes, doubling):**

```
Pass 1:  k = 8     (optimal for e ≈ 11%: k ≈ 0.73/e)
Pass 2:  k = 16
Pass 3:  k = 32
Pass 4:  k = 64
```

**Per-pass algorithm:**

1. Apply random permutation (Fisher-Yates, independent per pass)
   — scatters errors across blocks between passes
2. Divide n positions into blocks of size k
3. For each block: exchange parity (1 bit leaked)
4. On mismatch: BISECT the block

**BISECT** (binary search, inductive correctness):

```
Base: block size 1 → single position IS the error. Flip it.
Step: block size k > 1, one error in [lo, hi).
      left-half parity mismatch → error in left.  Recurse.
      left-half parity match    → error in right. Recurse.
      Terminates in ⌈log₂(k)⌉ steps.
      Leaks ⌈log₂(k)⌉ bits per correction.
```

**Cascade effect:** correcting a bit flips the parity of its
containing block in all prior passes. Those blocks are
re-examined — this is why the protocol is called Cascade.
Block lookup for re-examination: O(1) via precomputed
inverse permutation `inv_perm[pass][comp_pos]`.

**Information leaked by Cascade:**

```
per block (parity exchange):    1 bit
per BISECT on block of size k:  ⌈log₂(k)⌉ bits
```

Total `parity_bits_leaked` is tracked exactly and subtracted
from the PA input length.

### 5. Privacy Amplification

Input: n_pa = sifted_len - BB84_SAMPLE_N reconciled bits.

Output length (ratio arithmetic, no floats):

```
numerator   = n_pa × (144000 - 2 × h_val)
final_raw   = numerator / 144000          (integer floor)
final_bits  = final_raw - parity_leaked - SECURITY_PARAM
```

where `h_val = h(e) × 144000` from the precomputed table,
`parity_leaked` = bits revealed by Cascade,
`SECURITY_PARAM` = 64 (covers key confirmation hash leakage).

**Overflow bound:**
```
max(n_pa × 144000) = 1792 × 144000 = 258,048,000 < 2⁶⁴
```

**Implementation:** Toeplitz hash (GF(2) matrix-vector multiply).

```
T is an m × n matrix where T[j,i] = r[j+i]
r[] is a random seed of length (n + m - 1) bits from getrandom(2)

output[j] = XOR_i { r[j+i] & input[i] }  for i ∈ [0, n)
```

Security: if Eve knows at most e fraction of input bits and
e < threshold, her information on the Toeplitz output is
exponentially small in the security parameter.

Lossy contract: `{{0 [ (input,n,m) (AS/--\WAS) output[] ] 1}}`
Information is intentionally and irreversibly destroyed.

### 6. Key Confirmation

After PA, Alice packs her non-sample original bits and compares
word-by-word against `reconciled_key` (Bob's Cascade output).
Mismatch means Cascade left uncorrected errors — keys would
diverge even under the same Toeplitz seed. Session aborts.

A 64-bit rotate-XOR hash of `final_key` is stored as
`confirm_hash`. Leakage: 64 bits — covered by `SECURITY_PARAM`.

---

## 144,000 Ratio System

All arithmetic uses exact rational representation. No IEEE 754.

```
144,000 = 2⁷ × 3² × 5³    (160 divisors)
```

160 divisors means 160 common fractions are exact with this
denominator. Every threshold, every compression ratio, every
entropy value is expressed as `uint64_t numerator / 144000`.

Comparisons use integer cross-multiply:

```c
/* QBER accept: e <= threshold  */
errors * RATIO_DENOM <= QBER_THRESH_N * sample

/* PA length: n * (1 - 2*h(e))  */
numerator = n_pa * (RATIO_DENOM - 2 * h_val)
final_raw = numerator / RATIO_DENOM
```

No rounding error. No platform-dependent float behaviour.
Deterministic across all hardware.

---

## 4-State Gate Logic

Every function returns or operates on one of four states:

| State | Name           | Meaning                              |
|-------|----------------|--------------------------------------|
| Z     | High-impedance | Not yet reached / not applicable     |
| X     | Unknown        | Failure, mismatch, or threshold exceeded |
| 0     | Deny / bit-0   | Valid result, false/low value        |
| 1     | Allow / bit-1  | Valid result, true/high value        |

Gate-X propagates causally via `_Atomic uint32_t abort_flag`:

```
Any sidecar on fatal condition:
  1. atomic_store(abort_flag, 1)   before its barrier
  2. Reaches ALL remaining barriers (no skipping — deadlock prevention)
  3. Returns GR_X from thread entry point

Every sidecar after each barrier:
  atomic_load(abort_flag, acquire) — stops without touching RAMStore
```

---

## Sidecar Threading Model

Four threads. Four barriers. Strict causal ordering.

```
FRONT --[fl]--> LEAD --[lr]--> REAR(QBER) --[rq]--> RECONCILE --[rc]--> REAR(PA)
```

| Barrier     | Count | Participants                    |
|-------------|-------|---------------------------------|
| barrier_fl  | 2     | FRONT + LEAD                    |
| barrier_lr  | 3     | LEAD + REAR + RECONCILE         |
| barrier_rq  | 2     | REAR + RECONCILE                |
| barrier_rc  | 2     | RECONCILE + REAR                |

`barrier_lr` count=3 ensures REAR and RECONCILE both wait for
LEAD before either proceeds. REAR does QBER first. RECONCILE
waits for REAR's QBER result before touching a single bit.

---

## RAMStore Immutability

Four mmap'd slabs. Each sealed after its sidecar completes:

```
alice_raw       mprotect(PROT_READ)  after FRONT
sifted_key      mprotect(PROT_READ)  after LEAD
reconciled_key  mprotect(PROT_READ)  after RECONCILE
final_key       mprotect(PROT_READ)  after REAR
```

Post-seal write from any thread: `SIGSEGV`. OS-enforced,
not convention. Seal order mirrors phase order mirrors
the IFP edge graph.

---

## ExCLisp Contract Notation

Every function documents three standpoints:

```
FRONT: what the caller brings         (AS — approach standpoint)
LEAD:  the operation that commits     (Pivot — SHIMMER collapse)
REAR:  what lives in the structure    (IS — departure standpoint)
```

Followed by gate states derived from the pivot:

```
Z: not applicable / not yet reached
X: pivot failed or precondition violated
0: valid result, deny/bit-0 semantic
1: valid result, allow/bit-1 semantic
```

Contract line encodes the mapping type:

```
{{0 [ input (AS/.\IS)    output ] 1}}   bijective  (round-trip preserves identity)
{{0 [ input (AS/--\WAS)  output ] 1}}   lossy      (information destroyed)
{{0 [ input (AS/++\PLUS) output ] 1}}   expanding  (one-to-many)
```

---

## Performance

Measured on i7, `-O3 -march=native -flto -funroll-loops`, cold start:

```
Min:        0.0017 s
Max:        0.0020 s
Mean:       0.0020 s
Spread:     +/-42.54%
Throughput: ~500K -- 915K photons/s
```

Gate-X rate: ~5% per session at 3% channel noise.
Expected from `Binomial(256, 0.03)` tail above 11%: ~4–5%.
Correct protocol behaviour. Not a bug.

`final_len` varies 2–44 bytes across sessions. Correct:
QBER-dependent `h(e)` drives PA output length.
Constant `final_len` would indicate a broken PA formula.

---

## Build

```bash
make              # release: -O3 -march=native -flto
make asan         # AddressSanitizer + UBSan
make noise        # 25% noise — exercises Gate-X abort path
make debug        # -O0 -g

# After receiving files from outside the build machine:
find . -name '*.c' -o -name '*.h' -o -name 'Makefile' | xargs touch
make clean && make
```

---

## File Structure

```
bb84_types.h       Core types, ee_ratio_t, h(e) table, RAMStore,
                   GateResult, static_asserts, IFP invariants
bb84_sidecar.h     BB84Ctx, barriers, abort_flag, RNG primitives,
                   bit-array ops, Fisher-Yates
bb84_ramstore.h/c  mmap slab allocation, mprotect sealing
bb84_front.c       FRONT sidecar: quantum channel simulation
bb84_lead.c        LEAD sidecar: basis reconciliation
bb84_reconcile.h/c RECONCILE sidecar: Cascade-lite 4-pass
bb84_rear.c        REAR sidecar: QBER estimation + PA + confirmation
bb84_main.c        Thread launch, ee_ratio_t timing, 8-run bench
Makefile
LICENSE
```

---

## References

**Protocol:**
Bennett, C.H. and Brassard, G. "Quantum cryptography: Public key
distribution and coin tossing." *Theoretical Computer Science*,
vol. 560, pp. 7–11, 2014. (Original: Proc. IEEE ICCSP, Bangalore, 1984.)
arXiv:2003.06557

**Error reconciliation:**
Brassard, G. and Salvail, L. "Secret-Key Reconciliation by Public
Discussion." *EUROCRYPT 1993*, LNCS 765, pp. 410–423.

**Security proof:**
Shor, P.W. and Preskill, J. "Simple Proof of Security of the BB84
Quantum Key Distribution Protocol." *Physical Review Letters*,
vol. 85, no. 2, pp. 441–444, 2000. arXiv:quant-ph/0003004

---

## License

MIT — see `LICENSE`.

The BB84 protocol and Cascade reconciliation are the intellectual
work of their respective authors (cited above). This C23
implementation is original work by H. Overman.

ECCN: 5D002 (publicly available encryption source code).
The 2021 EAR amendment eliminated the general notification
requirement for standard publicly available encryption source code.
This software implements a published, non-proprietary protocol
and does not constitute non-standard cryptography under EAR Part 772.
