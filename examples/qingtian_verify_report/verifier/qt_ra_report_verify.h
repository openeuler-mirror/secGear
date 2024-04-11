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

#ifndef QT_RA_VERIFY_REPORT_H
#define QT_RA_VERIFY_REPORT_H

#include "qt_attestation_api.h"
#include "uni_ra_verify_agent.h"

#ifdef __cplusplus
extern "C" {
#endif

extern X509 *g_qt_root_cert;

/**
* [verifier API] verify qingtian remote attestation report
*
* @param[in] report, the report of target TA
*
* @param[in] nonce, the nonce generated when get report
*
* @param[in] type, the mode of verify report
*
* @param[in] basevalue, the basevalue file path of target TA,
*
* @retval, On success, return 0.
*          On error, cc_enclave_result_t errorno is returned.
*/
cc_enclave_result_t qt_verify_report(cc_ra_buf_t *report, cc_ra_buf_t *nonce,
    cc_ra_verify_type_t type, char *basevalue);

#ifdef __cplusplus
}
#endif

#endif