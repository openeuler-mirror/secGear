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
#include "error_conversion.h"

cc_enclave_result_t conversion_res_status(uint32_t enclave_res)
{
    switch (enclave_res) {
        case SGX_SUCCESS:
            return CC_SUCCESS;
        case SGX_ERROR_INVALID_PARAMETER:
            return CC_ERROR_BAD_PARAMETERS;
        case SGX_ERROR_OUT_OF_MEMORY:
            return CC_ERROR_OUT_OF_MEMORY;
        case SGX_ERROR_FILE_BAD_STATUS:
            return CC_ERROR_BAD_STATE;
        case SGX_ERROR_FEATURE_NOT_SUPPORTED:
            return CC_ERROR_NOT_SUPPORTED;
        case SGX_ERROR_ENCLAVE_LOST:
            return CC_ERROR_ENCLAVE_LOST;
        case SGX_ERROR_BUSY:
            return CC_ERROR_BUSY;
        case SGX_ERROR_UNDEFINED_SYMBOL:
            return CC_ERROR_INVALID_ENCLAVE;
        case SGX_ERROR_INVALID_SIGNATURE:
            return CC_ERROR_SIGNATURE_INVALID;
        case SGX_ERROR_OCALL_NOT_ALLOWED:
            return CC_ERROR_OCALL_NOT_ALLOWED;
        case SGX_ERROR_INVALID_FUNCTION:
            return CC_ERROR_INVALID_CMD;
        case SGX_ERROR_OUT_OF_TCS:
            return CC_ERROR_OUT_OF_TCS;
        case SGX_ERROR_ENCLAVE_CRASHED:
            return CC_ERROR_ENCLAVE_DEAD;
        default:
            return CC_ERROR_UNEXPECTED;
        }
}

