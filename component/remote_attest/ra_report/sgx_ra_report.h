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

#ifndef SECGEAR_SGX_RA_REPORT_H
#define SECGEAR_SGX_RA_REPORT_H

#include "status.h"
#include "sg_report_st.h"

cc_enclave_result_t sgx_prepare_ra_env(cc_ra_scenario_t scenario);

cc_enclave_result_t sgx_get_ra_report(cc_get_ra_report_input_t *in, cc_ra_buf_t *report);

#endif

