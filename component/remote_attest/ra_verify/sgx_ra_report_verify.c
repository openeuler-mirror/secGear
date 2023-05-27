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

#include "sgx_ra_report_verify.h"

#include "uni_ra_verify_agent.h"

cc_enclave_result_t sgx_verify_report(cc_ra_buf_t *report, cc_ra_buf_t *nonce,
    cc_ra_verify_type_t type, char *basevalue)
{
    (void)report;
    (void)nonce;
    (void)type;
    (void)basevalue;
    return CC_SUCCESS;
}

uni_ra_verify_agent_t g_sgx_ra_verify_agent = {
    .verify_ra_report = sgx_verify_report,
};
static __attribute__((constructor)) void gp_register_ra_agent()
{
    cc_register_ra_verify_agent(&g_sgx_ra_verify_agent);
}