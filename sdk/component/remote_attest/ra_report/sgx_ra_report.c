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
#include "uni_ra_agent.h"

static cc_enclave_result_t sgx_prepare_ra_env(cc_ra_scenario_t scenario)
{
    (void)scenario;
    return CC_SUCCESS;
}

static cc_enclave_result_t sgx_get_ra_report(cc_get_ra_report_input_t *in, cc_ra_buf_t *report)
{
    (void)in;
    (void)report;

    return CC_SUCCESS;
}

static uni_ra_agent_t g_sgx_agent = {
    .tee_type = CC_TEE_TYPE_SGX,
    .prepare_ra_env = sgx_prepare_ra_env,
    .get_ra_report = sgx_get_ra_report,
};
static __attribute__((constructor)) void sgx_register_ra_agent(void)
{
    cc_register_ra_agent(&g_sgx_agent);
}