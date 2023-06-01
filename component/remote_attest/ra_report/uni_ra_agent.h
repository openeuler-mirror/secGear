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

#ifndef SECGEAR_UNI_RA_AGENT_H
#define SECGEAR_UNI_RA_AGENT_H

#include <stdint.h>
#include "status.h"
#include "sg_report_st.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef cc_enclave_result_t (*uni_prepare_ra_env_proc_t)(cc_ra_scenario_t scenario);
typedef cc_enclave_result_t (*uni_get_ra_report_proc_t)(cc_get_ra_report_input_t *in, cc_ra_buf_t *report);

typedef enum {
    CC_TEE_TYPE_GP,
    CC_TEE_TYPE_SGX,
} cc_tee_type_t;

typedef struct {
    cc_tee_type_t tee_type;
    uni_prepare_ra_env_proc_t prepare_ra_env;
    uni_get_ra_report_proc_t get_ra_report;
} uni_ra_agent_t;

void cc_register_ra_agent(uni_ra_agent_t *agent);

#ifdef __cplusplus
}
#endif

#endif
