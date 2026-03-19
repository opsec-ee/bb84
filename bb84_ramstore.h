/*
 ==================================================================
 * @file    bb84_ramstore.h
 * @version 2.1
 * @brief   RAMStore slab lifecycle: alloc, seal per sidecar, free
 *
 * Four slabs, independently mmap'd, page-aligned.
 * Each seal: mprotect(PROT_READ) -- post-seal write = SIGSEGV.
 *
 * Sealing order enforces causal chain:
 *   seal_front     -- LEAD cannot write alice_raw after this
 *   seal_lead      -- RECONCILE cannot write sifted_key after this
 *   seal_reconcile -- REAR cannot write reconciled_key after this
 *   seal_rear      -- nobody writes final_key after this
 ==================================================================
 */
#pragma once
#ifndef BB84_RAMSTORE_H
#define BB84_RAMSTORE_H

#include "bb84_types.h"

[[nodiscard]] GateResult ramstore_alloc(RAMStore *store);
[[nodiscard]] GateResult ramstore_seal_front(RAMStore *store);
[[nodiscard]] GateResult ramstore_seal_lead(RAMStore *store);
[[nodiscard]] GateResult ramstore_seal_reconcile(RAMStore *store);
[[nodiscard]] GateResult ramstore_seal_rear(RAMStore *store);
void                     ramstore_free(RAMStore *store);

#endif /* BB84_RAMSTORE_H */
