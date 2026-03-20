/*
 ==================================================================
 * @file    bb84_selftest.h
 * @version 2.1
 * @author  H. Overman (ee)
 * @brief   Self-test declarations -- run before any external
 *          interaction per ppo-2 SELF-TESTS AT STARTUP
 *
 * Tests are concrete: specific inputs, specific outputs.
 * Spot-checks on known mathematical truths derivable by hand.
 * Failure halts startup and reports which check failed.
 *
 * The tests are the surface check on the projection.
 * If they pass, the ratio system and bit-packing are correct.
 * If they fail, fix the projection before fixing anything else.
 ==================================================================
 */
#pragma once
#ifndef BB84_SELFTEST_H
#define BB84_SELFTEST_H

#include "bb84_types.h"

/*
 * bb84_self_test -- run all startup checks
 *
 * FRONT: void -- no prior state required (AS)
 * LEAD:  five spot-checks on known mathematical truths (Pivot)
 * REAR:  GateResult -- GATE_1 if all pass, GATE_X with diagnostic (IS)
 *   X: any check fails -- reason names the specific failure
 *   1: all checks pass -- projection is correct
 *
 * Contract: {{0 [ void (AS/.\IS) GateResult ] 1}}
 */
[[nodiscard]] GateResult bb84_self_test(void);

#endif /* BB84_SELFTEST_H */
