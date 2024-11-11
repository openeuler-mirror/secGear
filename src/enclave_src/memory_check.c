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

#include "bottom_memory_check.h"


/*
 * param addr [IN] point to buffer address
 * param size   [IN] buffer size to be checked
 *
 * retval true target buffer is within enclave
 * retval false target buffer is outside of enclave
 */

bool cc_enclave_memory_in_enclave(const void *addr, size_t size)
{
    if (addr == NULL && size == 0)
        return true;
    if (addr == NULL || size == 0)
        return false;
    return MEMORY_CHECK_IN_FN(addr, size);
}


/*
 * param addr [IN] point to buffer address
 * param size   [IN] buffer size to be checked
 *
 * retval false target buffer is within enclave
 * retval true target buffer is outside of enclave
 */
bool cc_enclave_memory_out_enclave(const void *addr, size_t size)
{
    if (addr == NULL && size == 0)
        return true;
    if (addr == NULL || size == 0)
        return false;
    return MEMORY_CHECK_OUT_FN(addr, size);
}
