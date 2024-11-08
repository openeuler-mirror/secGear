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

#include "gp_shared_memory.h"

#include <stdlib.h>
#include <pthread.h>
#include <tee_client_type.h>
#include "secgear_defs.h"
#include "gp_shared_memory_defs.h"
#include "enclave_internal.h"
#include "gp_enclave.h"
#include "gp_uswitchless.h"
#include "secgear_list.h"
#include "enclave_log.h"
#include "status.h"

#define TEEC_SHARED_MEMORY_ENTRY(ptr) \
    ((TEEC_SharedMemory *)((char *)(ptr) - sizeof(gp_shared_memory_t)))

static pthread_rwlock_t g_shared_mem_list_lock = PTHREAD_RWLOCK_INITIALIZER;
static list_node_t g_shared_mem_list = {
    .next = &g_shared_mem_list,
    .prev = &g_shared_mem_list
};

static void gp_remove_shared_mem_from_list(gp_shared_memory_t *shared_mem)
{
    CC_RWLOCK_LOCK_WR(&g_shared_mem_list_lock);
    list_remove(&shared_mem->node);
    CC_RWLOCK_UNLOCK(&g_shared_mem_list_lock);
}

static void gp_add_shared_mem_to_list(gp_shared_memory_t *shared_mem)
{
    CC_RWLOCK_LOCK_WR(&g_shared_mem_list_lock);
    list_add_after(&shared_mem->node, &g_shared_mem_list);
    CC_RWLOCK_UNLOCK(&g_shared_mem_list_lock);
}

void *gp_malloc_shared_memory(cc_enclave_t *context, size_t size, bool is_control_buf, int try_cnt)
{
    gp_context_t *gp_context = (gp_context_t *)context->private_data;
    gp_shared_memory_t gp_shared_mem = {
        .is_control_buf = is_control_buf,
        .is_registered = false,
        .enclave = (void *) context,
        .register_tid = 0,
        .reg_session = NULL
    };
    gp_shared_mem.reg_session = malloc(sizeof(TEEC_Session));
    if (gp_shared_mem.reg_session == NULL) {
        return NULL;
    }
    TEEC_SharedMemory *teec_shared_mem = (TEEC_SharedMemory *)(&gp_shared_mem.shared_mem);
    teec_shared_mem->size = size + sizeof(gp_shared_memory_t);
    teec_shared_mem->flags = try_cnt == 0 ? TEEC_MEM_REGISTER_INOUT : TEEC_MEM_SHARED_INOUT;

    TEEC_Result result = TEEC_AllocateSharedMemory(&gp_context->ctx, teec_shared_mem);
    if (result == TEEC_ERROR_BAD_PARAMETERS) {
        print_warning("not support register type, try shared type again.\n");
        teec_shared_mem->flags = TEEC_MEM_SHARED_INOUT;
        result = TEEC_AllocateSharedMemory(&gp_context->ctx, teec_shared_mem);
    }

    if (result != TEEC_SUCCESS) {
        free(gp_shared_mem.reg_session);
        return NULL;
    }

    // save meta data
    (void)memcpy(teec_shared_mem->buffer, &gp_shared_mem, sizeof(gp_shared_mem));

    gp_add_shared_mem_to_list((gp_shared_memory_t *)teec_shared_mem->buffer);
    return (char *)teec_shared_mem->buffer + sizeof(gp_shared_mem);
}

static bool gp_is_shared_mem_start_addr(const void *ptr)
{
    size_t addr = (size_t)ptr;
    bool isExist = false;
    list_node_t *cur = NULL;
    gp_shared_memory_t *mem = NULL;

    CC_RWLOCK_LOCK_RD(&g_shared_mem_list_lock);
    list_for_each(cur, &g_shared_mem_list) {
        mem = list_entry(cur, gp_shared_memory_t, node);
        if (addr == (size_t)((char *)mem + sizeof(gp_shared_memory_t))) {
            isExist = true;
            break;
        }
    }
    CC_RWLOCK_UNLOCK(&g_shared_mem_list_lock);

    return isExist;
}

cc_enclave_result_t gp_free_shared_memory(cc_enclave_t *enclave, void *ptr)
{
    CC_IGNORE(enclave);

    if (!gp_is_shared_mem_start_addr(ptr)) {
        print_error_term("GP free shared memory failed: invalid shared memory start address.\n");
        return CC_ERROR_SHARED_MEMORY_NOT_REGISTERED;
    }

    if (GP_SHARED_MEMORY_ENTRY(ptr)->enclave != enclave) {
        return CC_ERROR_INVALID_HANDLE;
    }

    gp_remove_shared_mem_from_list(GP_SHARED_MEMORY_ENTRY(ptr));
    if (GP_SHARED_MEMORY_ENTRY(ptr)->reg_session != NULL) {
        free(GP_SHARED_MEMORY_ENTRY(ptr)->reg_session);
        GP_SHARED_MEMORY_ENTRY(ptr)->reg_session = NULL;
    }

    TEEC_SharedMemory sharedMem = *TEEC_SHARED_MEMORY_ENTRY(ptr);
    TEEC_ReleaseSharedMemory(&sharedMem);

    return CC_SUCCESS;
}

#ifndef TEE_SECE_AGENT_ID
#define TEE_SECE_AGENT_ID 0x53656345
#endif

#define PARAM_OFFSET_MOVE(cur_param_offset, offset_var_name, cur_param_size) \
    size_t offset_var_name = cur_param_offset; \
    cur_param_offset += (cur_param_size)

cc_enclave_result_t gp_register_shared_memory(cc_enclave_t *enclave, void *ptr)
{
    uint32_t ms = TEE_SECE_AGENT_ID;

    if (!gp_is_shared_mem_start_addr(ptr)) {
        return CC_ERROR_SHARED_MEMORY_START_ADDR_INVALID;
    }

    gp_shared_memory_t *gp_shared_mem = GP_SHARED_MEMORY_ENTRY(ptr);
    if (!gp_shared_mem->is_control_buf && !uswitchless_is_switchless_enabled(enclave)) {
        return CC_ERROR_SWITCHLESS_DISABLED;
    }

    if (GP_SHARED_MEMORY_ENTRY(ptr)->enclave != enclave) {
        return CC_ERROR_INVALID_HANDLE;
    }

    if (__atomic_load_n(&gp_shared_mem->is_registered, __ATOMIC_ACQUIRE)) {
        return CC_ERROR_SHARED_MEMORY_REPEAT_REGISTER;
    }

    gp_register_shared_memory_size_t args_size = {
        .retval_size = size_to_aligned_size(sizeof(int)),
        .shared_buf_size = size_to_aligned_size(sizeof(void *)),
        .shared_buf_len_size = size_to_aligned_size(sizeof(size_t)),
        .is_control_buf_size = size_to_aligned_size(sizeof(bool))
    };

    /* Calculate the input parameter offset. */
    size_t in_param_buf_size = size_to_aligned_size(sizeof(args_size));
    PARAM_OFFSET_MOVE(in_param_buf_size, ptr_offset, args_size.shared_buf_size);
    PARAM_OFFSET_MOVE(in_param_buf_size, ptr_len_offset, args_size.shared_buf_len_size);
    PARAM_OFFSET_MOVE(in_param_buf_size, is_control_buf_offset, args_size.is_control_buf_size);

    /* Calculate the output parameter offset. */
    size_t out_param_buf_size = 0;
    PARAM_OFFSET_MOVE(out_param_buf_size, retval_offset, args_size.retval_size);
 
    /* Allocate in_buf and out_buf */
    char *param_buf = (char *)calloc(in_param_buf_size + out_param_buf_size, sizeof(char));
    if (param_buf == NULL) {
        return CC_ERROR_OUT_OF_MEMORY;
    }

    char *in_param_buf = param_buf;
    char *out_param_buf = param_buf + in_param_buf_size;

    /* Copy in_params to in_buf */
    memcpy(in_param_buf, &args_size, size_to_aligned_size(sizeof(args_size)));
    memcpy(in_param_buf + ptr_offset, &ptr, sizeof(void*));
    size_t shared_mem_size = ((TEEC_SharedMemory *)(&gp_shared_mem->shared_mem))->size - sizeof(gp_shared_memory_t);
    memcpy(in_param_buf + ptr_len_offset, &shared_mem_size, sizeof(size_t));
    memcpy(in_param_buf + is_control_buf_offset, &gp_shared_mem->is_control_buf, sizeof(bool));

    /* Call the cc_enclave function */
    cc_enclave_result_t ret = enclave->list_ops_node->ops_desc->ops->cc_ecall_enclave(enclave,
        fid_register_shared_memory, in_param_buf, in_param_buf_size, out_param_buf, out_param_buf_size, &ms, NULL);
    if (ret != CC_SUCCESS) {
        free(param_buf);
        return ret;
    }

    /* Copy out_buf to out_params */
    int retval = 0;
    (void)memcpy(&retval, out_param_buf + retval_offset, sizeof(int));
    if (retval != (int)CC_SUCCESS) {
        free(param_buf);
        return CC_FAIL;
    }

    free(param_buf);
    return CC_SUCCESS;
}

cc_enclave_result_t unregister_shared_memory(cc_enclave_t *enclave, gp_shared_memory_t* gp_shared_mem)
{
    uint32_t ms = TEE_SECE_AGENT_ID;

    if (!__atomic_load_n(&gp_shared_mem->is_registered, __ATOMIC_ACQUIRE)) {
        return CC_ERROR_SHARED_MEMORY_NOT_REGISTERED;
    }

    /* Fill argments size */
    gp_unregister_shared_memory_size_t args_size = {
        .retval_size = size_to_aligned_size(sizeof(int)),
        .shared_buf_size = size_to_aligned_size(sizeof(void *))
    };
 
    /* Calculate the input parameter offset. */
    size_t in_param_buf_size = size_to_aligned_size(sizeof(args_size));
    PARAM_OFFSET_MOVE(in_param_buf_size, ptr_offset, args_size.shared_buf_size);

    /* Calculate the output parameter offset. */
    size_t out_param_buf_size = 0;
    PARAM_OFFSET_MOVE(out_param_buf_size, retval_offset, args_size.retval_size);

    /* Allocate in_buf and out_buf */
    char *param_buf = (char *)calloc(in_param_buf_size + out_param_buf_size, sizeof(char));
    if (param_buf == NULL) {
        return CC_ERROR_OUT_OF_MEMORY;
    }

    char *in_param_buf = param_buf;
    char *out_param_buf = param_buf + in_param_buf_size;

    /* Copy in_params to in_buf */
    void *ptr = (char *)gp_shared_mem + sizeof(gp_shared_memory_t);
    memcpy(in_param_buf, &args_size, size_to_aligned_size(sizeof(args_size)));
    memcpy(in_param_buf + ptr_offset, &ptr, sizeof(void*));

    cc_enclave_result_t ret = enclave->list_ops_node->ops_desc->ops->cc_ecall_enclave(enclave,
        fid_unregister_shared_memory, in_param_buf, in_param_buf_size, out_param_buf, out_param_buf_size, &ms, NULL);
    if (ret != CC_SUCCESS) {
        free(param_buf);
        return ret;
    }

    /* Copy out_buf to out_params */
    int retval = 0;
    (void)memcpy(&retval, out_param_buf + retval_offset, sizeof(int));
    if (retval != (int)CC_SUCCESS) {
        free(param_buf);
        return CC_FAIL;
    }

    if (gp_shared_mem->register_tid) {
        (void)pthread_join(gp_shared_mem->register_tid, NULL);
        gp_shared_mem->register_tid = 0;
    }

    free(param_buf);
    return CC_SUCCESS;
}
cc_enclave_result_t gp_unregister_shared_memory(cc_enclave_t *enclave, void* ptr)
{

    if (!gp_is_shared_mem_start_addr(ptr)) {
        return CC_ERROR_SHARED_MEMORY_START_ADDR_INVALID;
    }

    if (GP_SHARED_MEMORY_ENTRY(ptr)->enclave != enclave) {
        return CC_ERROR_INVALID_HANDLE;
    }

    gp_shared_memory_t *gp_shared_mem = GP_SHARED_MEMORY_ENTRY(ptr);
    return unregister_shared_memory(enclave, gp_shared_mem);
}

cc_enclave_result_t gp_release_all_shared_memory(cc_enclave_t *enclave)
{
    list_node_t *cur = NULL;
    list_node_t *tmp = NULL;
    gp_shared_memory_t *mem = NULL;
    cc_enclave_result_t step_ret;
    cc_enclave_result_t ret = CC_SUCCESS;

    CC_RWLOCK_LOCK_RD(&g_shared_mem_list_lock);
    list_for_each_safe(cur, tmp, &g_shared_mem_list) {
        mem = list_entry(cur, gp_shared_memory_t, node);
        if (mem->is_control_buf) {
            continue;
        }
        step_ret = unregister_shared_memory(enclave, mem);
        if (step_ret != CC_SUCCESS) {
            ret = step_ret;
            continue;
        }
        list_remove(&mem->node);
        TEEC_SharedMemory sharedMem = *(TEEC_SharedMemory *)mem;
        TEEC_ReleaseSharedMemory(&sharedMem);
    }
    CC_RWLOCK_UNLOCK(&g_shared_mem_list_lock);

    return ret; 
}
