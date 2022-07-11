/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "gp_uswitchless.h"

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "status.h"
#include "bit_operation.h"
#include "enclave_internal.h"
#include "gp_enclave.h"


#define USWITCHLESS_TASK_POOL(enclave) (((gp_context_t *)enclave->private_data)->sl_task_pool)

#define SWITCHLESS_MAX_UWORKERS 512
#define SWITCHLESS_MAX_TWORKERS 512
#define SWITCHLESS_MAX_PARAMETER_NUM 16
#define SWITCHLESS_MAX_POOL_SIZE_QWORDS 8
#define SWITCHLESS_DEFAULT_UWORKERS 8
#define SWITCHLESS_DEFAULT_TWORKERS 8
#define SWITCHLESS_DEFAULT_POOL_SIZE_QWORDS 1

bool uswitchless_is_valid_config(sl_task_pool_config_t *cfg)
{
    if ((cfg->num_uworkers > SWITCHLESS_MAX_UWORKERS) ||
        (cfg->num_tworkers > SWITCHLESS_MAX_TWORKERS) ||
        (cfg->num_max_params > SWITCHLESS_MAX_PARAMETER_NUM) ||
        (cfg->call_pool_size_qwords > SWITCHLESS_MAX_POOL_SIZE_QWORDS)) {
        return false;
    }

    return true;
}

void uswitchless_adjust_config(sl_task_pool_config_t *cfg)
{
    if (cfg->num_uworkers == 0) {
        cfg->num_uworkers = SWITCHLESS_DEFAULT_UWORKERS;
    }

    if (cfg->num_tworkers == 0) {
        cfg->num_tworkers = SWITCHLESS_DEFAULT_TWORKERS;
    }

    if (cfg->call_pool_size_qwords == 0) {
        cfg->call_pool_size_qwords = SWITCHLESS_DEFAULT_POOL_SIZE_QWORDS;
    }
}

sl_task_pool_t *uswitchless_create_task_pool(void *pool_buf, sl_task_pool_config_t *pool_cfg)
{
    size_t bit_buf_size = pool_cfg->call_pool_size_qwords * sizeof(uint64_t);
    sl_task_pool_t *pool = (sl_task_pool_t *)calloc(sizeof(sl_task_pool_t) + bit_buf_size, sizeof(char));
    if (pool == NULL) {
        return NULL;
    }

    pool->pool_cfg = *pool_cfg;
    pool->bit_buf_size = bit_buf_size;
    pool->task_size = SL_CALCULATE_PER_TASK_SIZE(pool_cfg);

    pool->pool_buf = (char *)pool_buf;
    pool->free_bit_buf = (uint64_t *)((char *)pool + sizeof(sl_task_pool_t));
    (void)memset(pool->free_bit_buf, 0xFF, bit_buf_size);
    pool->signal_bit_buf = (uint64_t *)(pool->pool_buf + sizeof(sl_task_pool_config_t));
    pool->task_buf = (char *)pool->signal_bit_buf + pool->bit_buf_size;

    return pool;
}

bool uswitchless_is_switchless_enabled(cc_enclave_t *enclave)
{
    if ((enclave != NULL) && (enclave->private_data != NULL) && (USWITCHLESS_TASK_POOL(enclave) != NULL)) {
        return true;
    }

    return false;
}

bool uswitchless_is_valid_param_num(cc_enclave_t *enclave, uint32_t argc)
{
    return argc <= USWITCHLESS_TASK_POOL(enclave)->pool_cfg.num_max_params;
}

int uswitchless_get_idle_task_index(cc_enclave_t *enclave)
{
    sl_task_pool_t *pool = USWITCHLESS_TASK_POOL(enclave);
    int call_pool_size_qwords = (int)pool->pool_cfg.call_pool_size_qwords;
    uint64_t *free_bit_buf = pool->free_bit_buf;
    int start_bit = 0;
    int end_bit = 0;
    uint64_t *element_ptr = NULL;
    uint64_t element_val = 0;

    for (int i = 0; i < call_pool_size_qwords; ++i) {
        element_ptr = free_bit_buf + i;
        element_val = *element_ptr;

        if (element_val == 0) {
            continue;
        }

        start_bit = count_tailing_zeroes(element_val);
        end_bit = SWITCHLESS_BITS_IN_QWORD - count_leading_zeroes(element_val);

        for (int j = start_bit; j < end_bit; ++j) {
            if (test_and_clear_bit(element_ptr, j) != 0) {
                return i * SWITCHLESS_BITS_IN_QWORD + j;
            }
        }
    }

    return -1;
}

void uswitchless_put_idle_task_by_index(cc_enclave_t *enclave, int task_index)
{
    int i = task_index / SWITCHLESS_BITS_IN_QWORD;
    int j = task_index % SWITCHLESS_BITS_IN_QWORD;
    sl_task_pool_t *pool = USWITCHLESS_TASK_POOL(enclave);

    set_bit(pool->free_bit_buf + i, j);
}

static inline sl_task_t *uswitchless_get_task_by_index(cc_enclave_t *enclave, int task_index)
{
    sl_task_pool_t *pool = USWITCHLESS_TASK_POOL(enclave);

    return (sl_task_t *)(pool->task_buf + task_index * pool->task_size);
}

void uswitchless_fill_task(cc_enclave_t *enclave, int task_index, uint32_t func_id, uint32_t argc, void *args)
{
    sl_task_t *task = uswitchless_get_task_by_index(enclave, task_index);

    task->func_id = func_id;
    __atomic_store_n(&task->status, SL_TASK_INIT, __ATOMIC_RELEASE);
    memcpy(&task->params[0], args, sizeof(uint64_t) * argc);
}

void uswitchless_submit_task(cc_enclave_t *enclave, int task_index)
{
    sl_task_t *task = uswitchless_get_task_by_index(enclave, task_index);
    __atomic_store_n(&task->status, SL_TASK_SUBMITTED, __ATOMIC_RELEASE);

    int i = task_index / SWITCHLESS_BITS_IN_QWORD;
    int j = task_index % SWITCHLESS_BITS_IN_QWORD;
    set_bit(USWITCHLESS_TASK_POOL(enclave)->signal_bit_buf + i, j);
}

#define CA_TIMEOUT_IN_SEC 60
#define CA_GETTIME_PER_CNT 100000000
cc_enclave_result_t uswitchless_get_task_result(cc_enclave_t *enclave, int task_index, void *retval, size_t retval_size)
{
    sl_task_t *task = uswitchless_get_task_by_index(enclave, task_index);
    uint32_t cur_status;
    int count = 0;
    struct timespec start;
    struct timespec end;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &start);

    while (true) {
        cur_status = __atomic_load_n(&task->status, __ATOMIC_ACQUIRE);

        if (cur_status == SL_TASK_DONE_SUCCESS) {
            if ((retval != NULL) && (retval_size != 0)) {
                (void)memcpy(retval, (void *)&task->ret_val, retval_size);
            }

            return CC_SUCCESS;
        } else if (cur_status == SL_TASK_DONE_FAILED) {
            return (cc_enclave_result_t)task->ret_val;
        }

        if (count > CA_GETTIME_PER_CNT) {
            clock_gettime(CLOCK_MONOTONIC_COARSE, &end);
            if (end.tv_sec - start.tv_sec > CA_TIMEOUT_IN_SEC) {
                break;
            }
            count = 0;
        }
        ++count;
    }

    return CC_ERROR_TIMEOUT;
}
