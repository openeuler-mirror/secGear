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

#ifndef __SWITCHLESS_DEFS_H__
#define __SWITCHLESS_DEFS_H__

#include <stdint.h>
#include <stdbool.h>

#include "secgear_uswitchless.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SWITCHLESS_BITS_IN_QWORD 64

/*
 *                        sl_task_pool_t      free_bit_buf
 *                        |                   |
 *                        v                   v
 *                        +-------------------+-+-+--------+-+----------------+-+
 *                  +---- | task_buf          | | |        | |                | |
 *                  | +-- | pool_buf          |0|1|  ...   |1|       ...      |1|   normal memory
 *                  | |   +-------------------+-+-+--------+-+----------------+-+
 *                  | |
 *                  | |                       signal_bit_buf
 *                  | |                       |
 *                  | |                       v
 *                  | +-> +-------------------+-+-+--------+-+----------------+-+
 *                  |     |                   | | |        | |                | |
 *                  |     | cc_sl_config_t    |1|0|  ...   |0|       ...      |0|
 *                  +---> +--------+---------++-+-+---+----+-+--+--------+----+-+
 *                task[0] | status | func id | retval | params1 | prams2 | ...  |   shared memory
 *                        +--------+---------+--------+---------+--------+------+
 *                task[n] |                          ...                        |
 *                        +-----------------------------------------------------+
 */

typedef struct {
    char *pool_buf; // switchless task pool control area, includes configuration area, signal bit area, and task area
    char *task_buf; // part of pool_buf, stores invoking tasks
    uint64_t *free_bit_buf; // length is bit_buf_size, the task indicated by the bit subscript is idle
    uint64_t *signal_bit_buf; // length is bit_buf_size, the task indicated by the bit subscript is to be processed
    uint32_t bit_buf_size; // size of each bit buf in bytes, determined by sl_call_pool_size_qwords in cc_sl_config_t
    uint32_t per_task_size; // size of each task in bytes, for details, see task[0]
    volatile bool need_stop_tworkers; // indicates whether to stop the trusted proxy thread
    cc_sl_config_t pool_cfg;
} sl_task_pool_t;

typedef struct {
    volatile uint32_t status;
    uint16_t func_id;
    uint16_t retval_size;
    volatile uint64_t ret_val;
    uint64_t params[0];
} sl_task_t;

#define SL_CALCULATE_PER_TASK_SIZE(cfg) \
    (sizeof(sl_task_t) + (cfg)->num_max_params * sizeof(uint64_t))

typedef enum {
    SL_TASK_INIT = 0,
    SL_TASK_SUBMITTED,
    SL_TASK_ACCEPTED,
    SL_TASK_DONE_SUCCESS,
    SL_TASK_DONE_FAILED
} sl_task_status_t;

/*
 * Summary: get pool buf size by config
 * Parameters:
 *     pool_cfg: configuration information of the task pool
 * Return:
 *     pool size in bytes
 */
inline size_t sl_get_pool_buf_len_by_config(cc_sl_config_t *pool_cfg)
{
    size_t signal_bit_buf_size = pool_cfg->sl_call_pool_size_qwords * sizeof(uint64_t);
    size_t each_task_size = SL_CALCULATE_PER_TASK_SIZE(pool_cfg);
    size_t task_buf_size = each_task_size * pool_cfg->sl_call_pool_size_qwords * SWITCHLESS_BITS_IN_QWORD;
    return sizeof(cc_sl_config_t) + signal_bit_buf_size + task_buf_size;
}

/*
 * Summary: Switchless bridge function prototype on the security side
 * Parameters:
 *     task_buf: task_buf, refer to sl_task_t
 * Return: NA
 */
typedef void (*sl_ecall_func_t)(void *task_buf);

#ifdef __cplusplus
}
#endif

#endif
