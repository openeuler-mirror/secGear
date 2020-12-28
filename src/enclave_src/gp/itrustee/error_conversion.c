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

/*
 * conversion from itrustee status to cc_enclave status
 *
 */
#include "error_conversion.h"
#include "secgear_dataseal.h"
#include "tee_ext_api.h"
#include "tee_log.h"

cc_enclave_result_t conversion_res_status(uint32_t enclave_res)
{
    cc_enclave_result_t result_table1[] = {
        CC_SUCCESS,
        CC_ERROR_INVALID_CMD, CC_ERROR_SERVICE_NOT_EXIST, CC_ERROR_ENCLAVE_LOST,
        CC_ERROR_ENCLAVE_MAXIMUM, CC_ERROR_REGISTER_EXIST_SERVICE, CC_ERROR_TARGET_DEAD_FATAL,
        CC_ERROR_READ_DATA, CC_ERROR_WRITE_DATA, CC_ERROR_TRUNCATE_OBJECT, CC_ERROR_SEEK_DATA, CC_ERROR_SYNC_DATA,
        CC_ERROR_RENAME_OBJECT, CC_ERROR_INVALID_ENCLAVE,
    };
    const int res_table2_begin = 0x80000100U;
    const int res_table3_begin = 0x80001001U;
    const int res_table4_begin = 0xFFFF7000U;
    const int res_table5_begin = 0xFFFF7110U;
    const int res_table6_begin = 0xFFFF7118U;
    const int res_table7_begin = 0xFFFF9110U;
    const int shift = 7;

    if (enclave_res < res_table2_begin) {
        if (enclave_res < sizeof(result_table1) / sizeof(cc_enclave_result_t)) {
            return result_table1[enclave_res];
        }
    } else if (enclave_res < res_table3_begin) {
        return CC_ERROR_OTRP_BASE;
    } else if (enclave_res > res_table4_begin && enclave_res < res_table5_begin) {
        return CC_ERROR_RPMB_BASE;
    } else if (enclave_res < res_table6_begin && enclave_res > res_table5_begin) {
        return CC_ERROR_TUI_BASE;
    } else if (enclave_res < res_table7_begin && enclave_res > res_table6_begin) {
        return (enclave_res - shift);
    } else if (enclave_res == 0xFFFF9113) {
        return CC_FAIL;
    } else {
        return enclave_res;
    }
}
