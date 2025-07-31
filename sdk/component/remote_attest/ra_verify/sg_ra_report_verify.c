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

#include "sg_ra_report_verify.h"
#include "uni_ra_verify_agent.h"

static uni_ra_verify_agent_t *g_ra_agent = NULL;

cc_enclave_result_t cc_verify_report(cc_ra_buf_t *report, cc_ra_buf_t *nonce, cc_ra_verify_type_t type, char *basevalue)
{
    if (report == NULL || report->buf == NULL || nonce == NULL || nonce->buf == NULL || basevalue == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (g_ra_agent == NULL) {
        return CC_ERROR_RA_VERIFY_AGENT_NOT_INIT;
    }
    return g_ra_agent->verify_ra_report(report, nonce, type, basevalue);
}

void cc_register_ra_verify_agent(uni_ra_verify_agent_t *agent)
{
    g_ra_agent = agent;
}