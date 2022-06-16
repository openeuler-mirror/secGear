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
#include "itrustee_tswitchless.h"

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include "secgear_defs.h"
#include "switchless_defs.h"
#include "bit_operation.h"
#include "tee_time_api.h"
#include "secgear_log.h"
#include "tee_log.h"

#ifndef TEESMP_THREAD_ATTR_CA_WILDCARD
#define TEESMP_THREAD_ATTR_CA_WILDCARD 0
#endif

#ifndef TEESMP_THREAD_ATTR_CA_INHERIT
#define TEESMP_THREAD_ATTR_CA_INHERIT (-1U)
#endif

#ifndef TEESMP_THREAD_ATTR_TASK_ID_INHERIT
#define TEESMP_THREAD_ATTR_TASK_ID_INHERIT (-1U)
#endif

#ifndef TEESMP_THREAD_ATTR_INVALID
#define TEESMP_THREAD_ATTR_INVALID (1U << 31)
#endif

#ifndef TEESMP_THREAD_ATTR_F_SHADOW
#define TEESMP_THREAD_ATTR_F_SHADOW (1U << 24)
#endif

#ifndef TEESMP_THREAD_ATTR_HAS_SHADOW
#define TEESMP_THREAD_ATTR_HAS_SHADOW 0x1
#endif

#ifndef TEESMP_THREAD_ATTR_NO_SHADOW
#define TEESMP_THREAD_ATTR_NO_SHADOW 0x0
#endif

#ifndef TEESMP_THREAD_ATTR_TASK_ID
#define TEESMP_THREAD_ATTR_TASK_ID TEESMP_THREAD_ATTR_TASK_ID_INHERIT
#endif

static sl_task_pool_t *tswitchless_init_pool(void *pool_buf)
{
    sl_task_pool_t *pool = (sl_task_pool_t *)calloc(sizeof(sl_task_pool_t), sizeof(char));
    if (pool == NULL) {
        SLogError("Malloc memory for tpool failed.");
        return NULL;
    }

    sl_task_pool_config_t *pool_cfg = (sl_task_pool_config_t *)pool_buf;

    pool->pool_cfg = *pool_cfg;
    pool->bit_buf_size = pool_cfg->call_pool_size_qwords * sizeof(uint64_t);
    pool->task_size = SL_CALCULATE_PER_TASK_SIZE(pool_cfg);

    pool->pool_buf = (char *)pool_buf;
    pool->signal_bit_buf = (uint64_t *)(pool->pool_buf + sizeof(sl_task_pool_config_t));
    pool->task_buf = (char *)pool->signal_bit_buf + pool->bit_buf_size;

    return pool;
}

static void tswitchless_fini_workers(sl_task_pool_t *pool, pthread_t *tids)
{
    int ret;
    uint32_t thread_num = pool->pool_cfg.num_tworkers;
    pool->need_stop_tworkers = true;

    for (uint32_t i = 0; i < thread_num; ++i) {
        if (tids[i] != NULL) {
            ret = pthread_join(tids[i], NULL);
            if (ret != 0) {
                SLogWarning("Failed to exit the tworker thread, ret=%d.", ret);
            }
        }
    }
}

static inline sl_task_t *tswitchless_get_task_by_index(sl_task_pool_t *pool, int task_index)
{
    return (sl_task_t *)(pool->task_buf + task_index * pool->task_size);
}

static int tswitchless_get_pending_task(sl_task_pool_t *pool)
{
    int call_pool_size_qwords = (int)pool->pool_cfg.call_pool_size_qwords;
    uint64_t *signal_bit_buf = pool->signal_bit_buf;
    int start_bit = 0;
    int end_bit = 0;
    uint64_t *element_ptr = NULL;
    uint64_t element_val = 0;

    for (int i = 0; i < call_pool_size_qwords; ++i) {
        element_ptr = signal_bit_buf + i;
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

extern const sl_ecall_func_t sl_ecall_func_table[];
extern const size_t sl_ecall_func_table_size;

static void tswitchless_proc_task(sl_task_t *task)
{
    uint32_t function_id = task->func_id;
    if (function_id >= sl_ecall_func_table_size) {
        task->ret_val = CC_ERROR_SWITCHLESS_INVALID_FUNCTION_ID;
        __atomic_store_n(&task->status, SL_TASK_DONE_FAILED, __ATOMIC_RELEASE);

        SLogError("Invalid switchless function index:%u.", function_id);
        return;
    }

    sl_ecall_func_t func = sl_ecall_func_table[function_id];
    if (func == NULL) {
        task->ret_val = CC_ERROR_SWITCHLESS_FUNCTION_NOT_EXIST;
        __atomic_store_n(&task->status, SL_TASK_DONE_FAILED, __ATOMIC_RELEASE);

        SLogError("The switchless function with index:%u does not exist.", function_id);
        return;
    }

    func(task);
    __atomic_store_n(&task->status, SL_TASK_DONE_SUCCESS, __ATOMIC_RELEASE);
}

static int thread_num = 0;

static void *tswitchless_thread_routine(void *data)
{
    int thread_index = __atomic_add_fetch(&thread_num, 1, __ATOMIC_ACQ_REL);
    SLogTrace("Enter tworkers: %d.", thread_index);

    int task_index;
    sl_task_t *task_buf = NULL;
    sl_task_pool_t *pool = (sl_task_pool_t *)data;
    int processed_count = 0;

    while (true) {
        if (pool->need_stop_tworkers) {
            break;
        }

        task_index = tswitchless_get_pending_task(pool);
        if (task_index == -1) {
            continue;
        }

        task_buf = tswitchless_get_task_by_index(pool, task_index);
        __atomic_store_n(&task_buf->status, SL_TASK_ACCEPTED, __ATOMIC_RELEASE);
        tswitchless_proc_task(task_buf);

        processed_count++;
    }

    SLogTrace("Exit tworkers: %d, processed: %d.", thread_index, processed_count);
    (void)__atomic_sub_fetch(&thread_num, 1, __ATOMIC_ACQ_REL);

    return NULL;
}

static pthread_t *tswitchless_init_workers(sl_task_pool_t *pool)
{
    int ret;
    sl_task_pool_config_t *pool_cfg = &pool->pool_cfg;

    pthread_t *tids = (pthread_t *)calloc(pool_cfg->num_tworkers * sizeof(pthread_t), sizeof(char));
    if (tids == NULL) {
        SLogError("Malloc memory for tworkers failed.");
        return NULL;
    }

    pthread_attr_t attr;
    THREAD_ATTR_INIT(&attr);
    ret = pthread_attr_settee(&attr,
                              TEESMP_THREAD_ATTR_CA_INHERIT,
                              TEESMP_THREAD_ATTR_TASK_ID_INHERIT,
                              TEESMP_THREAD_ATTR_HAS_SHADOW);
    if (ret != 0) {
        free(tids);
        THREAD_ATTR_DESTROY(&attr);

        SLogError("Set tee thread attr failed, ret: %d.", ret);
        return NULL;
    }

    for (uint32_t i = 0; i < pool_cfg->num_tworkers; ++i) {
        ret = pthread_create(tids + i, &attr, tswitchless_thread_routine, pool);
        if (ret != 0) {
            tswitchless_fini_workers(pool, tids);
            free(tids);
            THREAD_ATTR_DESTROY(&attr);

            SLogError("Create tee thread failed, index:%u, ret:%d.", i, ret);
            return NULL;
        }
    }

    THREAD_ATTR_DESTROY(&attr);

    return tids;
}

cc_enclave_result_t tswitchless_init(void *pool_buf, sl_task_pool_t **pool, pthread_t **tids)
{
    sl_task_pool_t *tmp_pool = tswitchless_init_pool(pool_buf);
    if (tmp_pool == NULL) {
        return CC_FAIL;
    }

    pthread_t *tmp_tids = tswitchless_init_workers(tmp_pool);
    if (tmp_tids == NULL) {
        free(tmp_pool);
        return CC_FAIL;
    }

    *pool = tmp_pool;
    *tids = tmp_tids;

    return CC_SUCCESS;
}

void tswitchless_fini(sl_task_pool_t *pool, pthread_t *tids)
{
    tswitchless_fini_workers(pool, tids);
    free(tids);
    free(pool);
}
