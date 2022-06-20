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

#include "secgear_shared_memory.h"

#include "status.h"
#include "enclave_internal.h"
#include "shared_memory_defs.h"
#include "secgear_defs.h"

#define FUNC_CREATE_SHARED_MEM(enclave) \
    enclave->list_ops_node->ops_desc->ops->cc_malloc_shared_memory
#define FUNC_FREE_SHARED_MEM(enclave) \
    enclave->list_ops_node->ops_desc->ops->cc_free_shared_memory
#define FUNC_REGISTER_SHARED_MEM(enclave) \
    enclave->list_ops_node->ops_desc->ops->cc_register_shared_memory
#define FUNC_UNREGISTER_SHARED_MEM(enclave) \
    enclave->list_ops_node->ops_desc->ops->cc_unregister_shared_memory

void *cc_malloc_shared_memory(cc_enclave_t *enclave, size_t size)
{
    if (enclave == NULL || size == 0 || !enclave->used_flag) {
        return NULL;
    }

    RWLOCK_LOCK_RD(&enclave->rwlock);

    if (enclave->list_ops_node == NULL || FUNC_CREATE_SHARED_MEM(enclave) == NULL) {
        RWLOCK_UNLOCK(&enclave->rwlock);
        return NULL;
    }

    void *ptr = FUNC_CREATE_SHARED_MEM(enclave)(enclave, size, false);

    RWLOCK_UNLOCK(&enclave->rwlock);

    return ptr;
}

cc_enclave_result_t cc_free_shared_memory(cc_enclave_t *enclave, void *ptr)
{
    if (enclave == NULL || ptr == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

// #if defined(ENCLAVE) && ENCLAVE == GP
    if (GP_SHARED_MEMORY_ENTRY(ptr)->enclave != enclave) {
        return CC_ERROR_INVALID_HANDLE;
    }
// #endif

    RWLOCK_LOCK_RD(&enclave->rwlock);

    if (enclave->list_ops_node == NULL || FUNC_FREE_SHARED_MEM(enclave) == NULL) {
        RWLOCK_UNLOCK(&enclave->rwlock);
        return CC_ERROR_NOT_IMPLEMENTED;
    }

    FUNC_FREE_SHARED_MEM(enclave)(enclave, ptr);

    RWLOCK_UNLOCK(&enclave->rwlock);

    return CC_SUCCESS;
}

cc_enclave_result_t cc_register_shared_memory(cc_enclave_t *enclave, void *ptr)
{
    if (enclave == NULL || ptr == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

// #if defined(ENCLAVE) && ENCLAVE == GP
    if (GP_SHARED_MEMORY_ENTRY(ptr)->enclave != enclave) {
        return CC_ERROR_INVALID_HANDLE;
    }
// #endif

    RWLOCK_LOCK_RD(&enclave->rwlock);

    if (enclave->list_ops_node == NULL || FUNC_REGISTER_SHARED_MEM(enclave) == NULL) {
        RWLOCK_UNLOCK(&enclave->rwlock);
        return CC_ERROR_NOT_IMPLEMENTED;
    }

    cc_enclave_result_t ret = FUNC_REGISTER_SHARED_MEM(enclave)(enclave, ptr);

    RWLOCK_UNLOCK(&enclave->rwlock);

    return ret;
}

cc_enclave_result_t cc_unregister_shared_memory(cc_enclave_t *enclave, void *ptr)
{
    if (enclave == NULL || ptr == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

// #if defined(ENCLAVE) && ENCLAVE == GP
    if (GP_SHARED_MEMORY_ENTRY(ptr)->enclave != enclave) {
        return CC_ERROR_INVALID_HANDLE;
    }
// #endif

    RWLOCK_LOCK_RD(&enclave->rwlock);

    if (enclave->list_ops_node == NULL || FUNC_UNREGISTER_SHARED_MEM(enclave) == NULL) {
        RWLOCK_UNLOCK(&enclave->rwlock);
        return CC_ERROR_NOT_IMPLEMENTED;
    }

    cc_enclave_result_t ret = FUNC_UNREGISTER_SHARED_MEM(enclave)(enclave, ptr);

    RWLOCK_UNLOCK(&enclave->rwlock);

    return ret;
}
