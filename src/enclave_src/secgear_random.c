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

#include "secgear_random.h"
#include "random_internal.h"

cc_enclave_result_t cc_enclave_generate_random(void *buffer, size_t size)
{
    cc_enclave_result_t res;
    if (buffer == NULL || size == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    res = _cc_generate_random(buffer, size);
    switch (res) {
        case 0:
            res = CC_SUCCESS;
            break;
        case 1:
            res = CC_FAIL;
            break;
        default:
            res = CC_ERROR_UNEXPECTED;
            break;
    }
    return res;
}
