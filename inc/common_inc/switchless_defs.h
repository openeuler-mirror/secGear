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

#ifdef __cplusplus
extern "C" {
#endif

#define SWITCHLESS_BITS_IN_QWORD 64

/**********************************************
***********************************************
*************                         *********
*******   switchless task pool layout   *******

sl_task_pool_config_t
sl_task_t
+---------------------------------------------








*/

typedef struct {
    uint32_t nu_uworkers;  // number of untrusted (for ocalls) worker threads
    uint32_t num_tworkers; // number of trusted (for ecalls) worker threads
    uint32_t call_pool_size_qwords; // number of switchless calls pool size (actual number is x64)
    uint32_t num_max_params; // max number of parameters
} sl_task_pool_config_t;

typedef struct {
    sl_task_pool_config_t pool_cfg;
    char *pool_buf;
    char *task_buf;
    uint64_t *free_bit_buf; // idle task flag
    uint64_t *signal_bit_buf; // to-be-processed task flag
    uint32_t bit_buf_sizel; // size of each task flag area
    uint32_t task_size; // size of each task
    volatile bool need_stop_tworkers;
} sl_task_pool_t;

typedef struct {
    volatile uint32_t status;
    uint32_t func_id;
    volatile uint64_t ret_val;
    uint64_t params[0];
} sl_task_t;

#define SL_CALCULATE_PER_TASK_SIZE(cfg) \
    (sizeof(sl_task_t) + cfg->num_max_params * sizeof(uint64_t))

typedef enum {
    SL_TASK_INIT = 0,
    SL_TASK_SUBMIDTTED,
    SL_TASK_ACCEPTER,
    SL_TASK_DONE_SUCCESS,
    SL_TASK_DONE_FAILED
} sl_task_status_t;

/*
 * Summary: get pool buf size by config
 * Parameters:
 *      pool_cfg: configuration information of the task pool
 * Return: 
 *      pool size in bytes
 */
inline size_t sl_get_pool_buf_len_by_config(sl_task_pool_config_t *pool_cfg)
{
    size_t signal_bit_buf_size = pool_cfg->call_pool_size_qwords *sizeof(uint64_t);
    size_t each_task_size = SL_CALCULATE_PER_TASK_SIZE(pool_cfg);
    size_t task_buf_size = each_task_size * pool_cfg->call_pool_size_qwords * SWITCHLESS_BITS_IN_QWORD;
    return sizeof(sl_task_pool_config_t) + signal_bit_buf_size + task_buf_size;
}

/*
 * Summary: Switchless bridge function prototype on the security side
 * Parameters:
 *      task_buf: task_buf, refer to sl_task_t
 * Return: NA
 */
typedef void (*sl_ecall_func_t)(void *task_buf);

#ifdef __cplusplus
}
#endif

#endif