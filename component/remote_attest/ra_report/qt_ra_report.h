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
#ifndef _QT_RA_REPORT_H_
#define _QT_RA_REPORT_H_

#include "uni_ra_agent.h"

#define QINGTIAN_REPORT_MAX_LENGTH 5000 // COBR encoded report should be less than 5000-byte.

/* Qingtian Enclave Remote Attestation APIs*/
#ifdef __cplusplus
extern "C" {
#endif

/**
* [Qingtian Encalve API] get remote attestation report from target enclave
*
* @param[in] in, bytes of input
*
* @param[in/out] report, remote attestion report, 0x3000 =< report->len < 0x100000
*
* @retval, On success, return 0. 
*          On error, cc_enclave_result_t errorno is returned.
*/
cc_enclave_result_t qt_get_ra_report(cc_get_ra_report_input_t *in, cc_ra_buf_t *report);

#ifdef __cplusplus
}
#endif

#endif