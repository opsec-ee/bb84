/*
 ==================================================================
 * @file    bb84_reconcile.h
 * @version 2.1
 * @brief   Cascade-lite error reconciliation declarations
 *
 * Public entry point: bb84_reconcile (thread entry)
 * Internal helpers declared here for unit testability.
 ==================================================================
 */
#pragma once
#ifndef BB84_RECONCILE_H
#define BB84_RECONCILE_H

#include "bb84_types.h"
#include "bb84_sidecar.h"

/*
 * bb84_reconcile -- RECONCILE sidecar thread entry
 *
 * Implements Cascade-lite 4-pass error correction.
 * Reads alice_raw (PROT_READ) and sifted_key (PROT_READ).
 * Writes reconciled_key (mutable copy, corrected in-place).
 * Tracks parity_bits_leaked.
 * Seals reconciled_key on completion.
 *
 * Contract: {{0 [ BB84Ctx* (AS/.\IS) GateResult* ] 1}}
 */
void *bb84_reconcile(void *ctx);

#endif /* BB84_RECONCILE_H */
