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
#include "sg_ra_report.h"
#include "uni_ra_agent.h"

static uni_ra_agent_t *g_ra_agent = NULL;
cc_enclave_result_t cc_prepare_ra_env(cc_ra_scenario_t scenario)
{
    if (g_ra_agent == NULL) {
        return CC_ERROR_RA_AGENT_NOT_INIT;
    }
    return g_ra_agent->prepare_ra_env(scenario);
}

cc_enclave_result_t cc_get_ra_report(cc_get_ra_report_input_t *in, cc_ra_buf_t *report)
{
    if (in == NULL || in->taid == NULL || report == NULL || report->buf == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (g_ra_agent == NULL) {
        return CC_ERROR_RA_AGENT_NOT_INIT;
    }
    return g_ra_agent->get_ra_report(in, report);
}

void cc_register_ra_agent(uni_ra_agent_t *agent)
{
    g_ra_agent = agent;
}
