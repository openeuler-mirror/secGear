/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __BIT_OPERATION_H__
#define __BIT_OPERATION_H__

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG
    #define ASSERT(x) assert(x)
#else
    #define ASSERT(x) ((void)0)
#endif

/*
 * Returns the number of trailing 0-bits in x, starting at the least significant bit position.
 * If x is 0, the result is undefined.
 */
static inline uint32_t count_tailing_zeroes(uint64_t value)
{
    ASSERT(value != 0);
    return (uint32_t)__builtin_ctzll(value);
}

/*
 * Returns the number of 1-bits in value.
 */
static inline uint32_t count_ones(uint64_t value)
{
    ASSERT(value != 0);
    return (uint32_t)__builtin_popcountll(value);
}

/*
 * Returns the number of leading 0-bits in x, starting at the most significant bit position.
 * If x is 0, the result is undefined.
 */
static inline uint32_t count_leading_zeroes(uint64_t value)
{
    ASSERT(value != 0);
    return (uint32_t)__builtin_clzll(value);
}

/*
 * In the bitmap with the start address of addr, bit i is cleared if it is 1, and true is returned.
 * Otherwise, false is returned.
 */
static inline bool test_and_clear_bit(volatile uint64_t *addr, uint32_t i)
{
    uint64_t old_val;
    uint64_t new_val;

    while (true) {
        old_val = *addr;
        if ((old_val & (1UL << i)) == 0) {
            break;
        }

        new_val = old_val & (~(1UL << i));
        if (__atomic_compare_exchange(addr, &old_val, &new_val, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            return true;
        }
    }

    return false;
}

/*
 * Set bit i in the bitmap whose start address is addr.
 */
static inline void set_bit(volatile uint64_t *addr, uint32_t i)
{
    (void)__atomic_or_fetch(addr, 1ULL << i, __ATOMIC_ACQUIRE);
}

#ifdef __cplusplus
}
#endif

#endif
