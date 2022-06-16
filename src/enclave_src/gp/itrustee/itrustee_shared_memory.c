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

#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include "gp.h"
#include "status.h"
#include "secgear_log.h"
#include "itrustee_tswitchless.h"
#include "shared_memory_defs.h"
#include "secgear_list.h"
#include "secgear_defs.h"

typedef struct {
    list_node_t node;
    size_t host_addr;
    size_t enclave_addr;
    size_t buf_len;
    pthread_mutex_t mtx_lock;
    pthread_cond_t unregister_cond;
    sl_task_pool_t *pool;
    pthread_t *tid_arr;
} shared_memory_block_t;

static pthread_rwlock_t g_shared_memory_list_lock = PTHREAD_RWLOCK_INITIALIZER;
static list_node_t g_shared_memory_list = {
    .next = &g_shared_memory_list,
    .prev = &g_shared_memory_list
};

static shared_memory_block_t *create_shared_memory_block(void *host_buf, size_t host_buf_len, void *registered_buf)
{
    shared_memory_block_t *shared_mem = calloc(sizeof(shared_memory_block_t), sizeof(char));
    if (shared_mem == NULL) {
        return NULL;
    }

    list_init(&shared_mem->node);
    MUTEX_INIT(&shared_mem->mtx_lock, NULL);
    COND_INIT(&shared_mem->unregister_cond, NULL);

    shared_mem->host_addr = (size_t)host_buf;
    shared_mem->enclave_addr = (size_t)((char *)registered_buf + sizeof(gp_shared_memory_t));
    shared_mem->buf_len = host_buf_len;

    return shared_mem;
}

static void destroy_shared_memory_block(shared_memory_block_t *shared_mem)
{
    if (shared_mem != NULL) {
        MUTEX_DESTROY(&shared_mem->mtx_lock);
        COND_DESTROY(&shared_mem->unregister_cond);
        free(shared_mem);
    }
}

static void add_shared_memory_block_to_list(shared_memory_block_t *shared_mem)
{
    RWLOCK_LOCK_WR(&g_shared_memory_list_lock);
    list_add_after(&shared_mem->node, &g_shared_memory_list);
    RWLOCK_UNLOCK(&g_shared_memory_list_lock);
}

static void remove_shared_memory_block_from_list(shared_memory_block_t *shared_mem)
{
    RWLOCK_LOCK_WR(&g_shared_memory_list_lock);
    list_remove(&shared_mem->node);
    RWLOCK_UNLOCK(&g_shared_memory_list_lock);
}

static cc_enclave_result_t itrustee_register_shared_memory(void *host_buf,
                                                           size_t host_buf_len,
                                                           void *registered_buf,
                                                           bool is_control_buf)
{
    cc_enclave_result_t ret = CC_FAIL;

    shared_memory_block_t *shared_mem = create_shared_memory_block(host_buf, host_buf_len, registered_buf);
    if (shared_mem == NULL) {
        return CC_ERROR_OUT_OF_MEMORY;
    }

    if (is_control_buf) {
        ret = tswitchless_init((void *)shared_mem->enclave_addr, &shared_mem->pool, &shared_mem->tid_arr);
        if (ret != CC_SUCCESS) {
            destroy_shared_memory_block(shared_mem);
            return CC_ERROR_TSWITCHLESS_INIT_FAILED;
        }
    }

    add_shared_memory_block_to_list(shared_mem);
    ((gp_shared_memory_t *)registered_buf)->is_registered = true;

    // Waiting for the deregistration signal
    MUTEX_LOCK(&shared_mem->mtx_lock);
    COND_WAIT(&shared_mem->unregister_cond, &shared_mem->mtx_lock);
    MUTEX_UNLOCK(&shared_mem->mtx_lock);

    ((gp_shared_memory_t *)registered_buf)->is_registered = false;
    remove_shared_memory_block_from_list(shared_mem);

    if (is_control_buf) {
        tswitchless_fini(shared_mem->pool, shared_mem->tid_arr);
    }

    destroy_shared_memory_block(shared_mem);

    return CC_SUCCESS;
}

cc_enclave_result_t ecall_register_shared_memory(uint8_t *in_buf,
                                                 size_t in_buf_size,
                                                 uint8_t *out_buf,
                                                 size_t out_buf_size,
                                                 uint8_t *registered_buf,
                                                 size_t *output_bytes_written)
{
    /* Check if the input and output buffers can be visited */
    if ((!in_buf || !cc_is_within_enclave(in_buf, in_buf_size)) ||
        (!out_buf || !cc_is_within_enclave(out_buf, out_buf_size))) {
        return CC_ERROR_ADDRESS_UNACCESSABLE;
    }

    /* Parse input parameters from in_buf */
    size_t in_buf_offset = size_to_aligned_size(sizeof(gp_register_shared_memory_size_t));
    gp_register_shared_memory_size_t *args_size = (gp_register_shared_memory_size_t *)in_buf;

    uint8_t *host_buf_p = NULL;
    uint8_t *host_buf_len_p = NULL;
    uint8_t *is_control_buf_p = NULL;
    SET_PARAM_IN_1(host_buf_p, size_t, host_buf, args_size->shared_buf_size);
    SET_PARAM_IN_1(host_buf_len_p, size_t, host_buf_len, args_size->shared_buf_len_size);
    SET_PARAM_IN_1(is_control_buf_p, bool, is_control_buf, args_size->is_control_buf_size);

    /* Fill return val, out and in-out parameters */
    size_t out_buf_offset = 0;

    uint8_t *retval_p = NULL;
    SET_PARAM_OUT(retval_p, int, retval, args_size->retval_size);

    *retval = itrustee_register_shared_memory((void *)host_buf, host_buf_len, registered_buf, is_control_buf);
    *output_bytes_written = out_buf_offset;

    return CC_SUCCESS;
}

size_t addr_host_to_enclave(size_t host_addr)
{
    list_node_t *cur = NULL;
    shared_memory_block_t *mem_block = NULL;
    size_t ptr = 0;

    RWLOCK_LOCK_RD(&g_shared_memory_list_lock);

    list_for_each(cur, &g_shared_memory_list) {
        mem_block = list_entry(cur, shared_memory_block_t, node);

        if ((host_addr >= mem_block->host_addr) && (host_addr < (mem_block->host_addr + mem_block->buf_len))) {
            ptr = mem_block->enclave_addr + (host_addr - mem_block->host_addr);
            break;
        }
    }

    RWLOCK_UNLOCK(&g_shared_memory_list_lock);

    return ptr;
}

static cc_enclave_result_t itrustee_unregister_shared_memory(size_t host_addr)
{
    cc_enclave_result_t ret = CC_ERROR_ITEM_NOT_FOUND;
    list_node_t *cur = NULL;
    shared_memory_block_t *mem_block = NULL;

    RWLOCK_LOCK_RD(&g_shared_memory_list_lock);

    list_for_each(cur, &g_shared_memory_list) {
        mem_block = list_entry(cur, shared_memory_block_t, node);

        if (host_addr == mem_block->host_addr) {
            MUTEX_LOCK(&mem_block->mtx_lock);
            COND_SIGNAL(&mem_block->unregister_cond);
            MUTEX_UNLOCK(&mem_block->mtx_lock);
            ret = CC_SUCCESS;
            break;
        }
    }

    RWLOCK_UNLOCK(&g_shared_memory_list_lock);

    return ret;
}

cc_enclave_result_t ecall_unregister_shared_memory(uint8_t *in_buf,
                                                   size_t in_buf_size,
                                                   uint8_t *out_buf,
                                                   size_t out_buf_size,
                                                   uint8_t *shared_buf,
                                                   size_t *output_bytes_written)
{
    IGNORE(shared_buf);

    /* Check if the input and output buffers can be visited */
    if ((!in_buf || !cc_is_within_enclave(in_buf, in_buf_size)) ||
        (!out_buf || !cc_is_within_enclave(out_buf, out_buf_size))) {
        return CC_ERROR_ADDRESS_UNACCESSABLE;
    }

    /* Fill in and in-out parameters */
    size_t in_buf_offset = size_to_aligned_size(sizeof(gp_unregister_shared_memory_size_t));
    gp_unregister_shared_memory_size_t *args_size = (gp_unregister_shared_memory_size_t *)in_buf;

    uint8_t *host_addr_p;
    SET_PARAM_IN_1(host_addr_p, size_t, host_addr, args_size->shared_buf_size);

    /* Fill return val, out and in-out parameters */
    size_t out_buf_offset = 0;

    uint8_t *retval_p;
    SET_PARAM_OUT(retval_p, int, retval, args_size->retval_size);

    *retval = itrustee_unregister_shared_memory(host_addr);
    *output_bytes_written = out_buf_offset;

    return CC_SUCCESS;
}
