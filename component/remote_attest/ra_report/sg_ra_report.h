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

#ifndef SECGEAR_REMOTE_REPORT_H
#define SECGEAR_REMOTE_REPORT_H

#include <stdint.h>
#include "status.h"
#include "secgear_defs.h"
#include "sg_report_st.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
* [host REE API] prepare attest environment before get report by attestation service
*
* @param[in] scenario, the scenario of attestation service
*
* @retval, On success, return 0. 
*          On error, cc_enclave_result_t errorno is returned.
*/
CC_API_SPEC cc_enclave_result_t cc_prepare_ra_env(cc_ra_scenario_t scenario);

/**
* [host REE API] get remote attestation report by attestation service
*
* @param[in] in, bytes of input
*
* @param[out] report, remote attestion report, 0x3000 =< len < 0x100000
*
* @retval, On success, return 0. 
*          On error, cc_enclave_result_t errorno is returned.
*/
CC_API_SPEC cc_enclave_result_t cc_get_ra_report(cc_get_ra_report_input_t *in, cc_ra_buf_t *report);

#ifdef __cplusplus
}
#endif

#endif
