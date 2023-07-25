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

#include "bottom_memory_check.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"

/* 
 * param buffer [IN] point to buffer address
 * param size   [IN] buffer size to be checked
 *
 * retval ture target buffer is within enclave
 * retval false target buffer is outside of enclave 
 */
bool itrustee_memory_in_enclave(const void *buffer, uint32_t size)
{
    if (!TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, buffer, size)) {
        return true;
    } else if (!TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_ANY_OWNER, buffer, size)) {
        return true;
    }
    return false;
}

/*
 * param buffer [IN] point to buffer address
 * param size   [IN] buffer size to be checked
 *
 * retval false target buffer is within enclave
 * retval true target buffer is outside of enclave
 */
bool itrustee_memory_out_enclave(const void *buffer, uint32_t size)
{
    if (!TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, buffer, size) &&
        !TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_ANY_OWNER, buffer, size)) {
        return false;
    }
    return true;
}

