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

#ifndef SECGEAR_SGX_RA_REPORT_VERIFY_H
#define SECGEAR_SGX_RA_REPORT_VERIFY_H

#include "status.h"
#include "sg_report_st.h"

#ifdef __cplusplus
extern "C" {
#endif

cc_enclave_result_t sgx_verify_report(cc_ra_buf_t *report, cc_ra_buf_t *nonce,
    cc_ra_verify_type_t type, char *basevalue);

#ifdef __cplusplus
}
#endif

#endif
