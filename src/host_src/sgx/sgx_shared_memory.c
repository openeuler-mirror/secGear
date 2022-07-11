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

#include "sgx_shared_memory.h"

#include <stdlib.h>
#include "secgear_defs.h"

void *sgx_malloc_shared_memory(cc_enclave_t *enclave, size_t size, bool is_control_buf)
{
    CC_IGNORE(enclave);
    CC_IGNORE(is_control_buf);

    return malloc(size);
}

void sgx_free_shared_memory(cc_enclave_t *enclave, void *ptr)
{
    CC_IGNORE(enclave);

    free(ptr);
}

cc_enclave_result_t sgx_register_shared_memory(cc_enclave_t *enclave, void *ptr)
{
    CC_IGNORE(enclave);
    CC_IGNORE(ptr);

    return CC_SUCCESS;
}

cc_enclave_result_t sgx_unregister_shared_memory(cc_enclave_t *enclave, void *ptr)
{
    CC_IGNORE(enclave);
    CC_IGNORE(ptr);

    return CC_SUCCESS;
}
