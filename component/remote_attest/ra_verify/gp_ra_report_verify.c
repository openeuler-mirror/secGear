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

#include "gp_ra_report_verify.h"

#include "teeverifier.h"
#include "enclave_log.h"

int convert_cctype_to_gptype(cc_ra_verify_type_t type)
{
    // gp type, 1: compare image hash; 2: compare mem hash; 3: compare image and mem hash
    if (type == CC_RA_VERIFY_TYPE_LOOSE) {
        return 1;
    } else if (type == CC_RA_VERIFY_TYPE_STRICT) {
        return 3; // 3: compare image and mem hash
    } else {
        return CC_ERROR_RA_REPORT_VERIFY_INVALID_TYPE;
    }
}

cc_enclave_result_t gp_verify_report(cc_ra_buf_t *report, cc_ra_buf_t *nonce,
    cc_ra_verify_type_t type, char *basevalue)
{
    int gp_type = convert_cctype_to_gptype(type);
    if (gp_type == (int)CC_ERROR_RA_REPORT_VERIFY_INVALID_TYPE) {
        return CC_FAIL;
    }
    int ret = tee_verify_report((buffer_data *)report, (buffer_data *)nonce, gp_type, basevalue);
    switch (ret) {
        case TVS_ALL_SUCCESSED:
            return CC_SUCCESS;
        case TVS_VERIFIED_NONCE_FAILED:
            return CC_ERROR_RA_REPORT_VERIFY_NONCE;
        case TVS_VERIFIED_SIGNATURE_FAILED:
            return CC_ERROR_RA_REPORT_VERIFY_SIGNATURE;
        case TVS_VERIFIED_HASH_FAILED:
            return CC_ERROR_RA_REPORT_VERIFY_HASH;
        default:
            print_debug("verify report failed, unknown errorcode:%d!\n", ret);
    }
    return ret;
}