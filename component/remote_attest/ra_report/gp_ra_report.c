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

#include "gp_ra_report.h"

#include <stdlib.h>
#include "gp_ra_helper.h"
#include "ra_client_api.h"
#include "enclave_log.h"

#define TEST_REPORT_OUT_LEN 0x3000
cc_enclave_result_t gp_ra_provision_no_as()
{
    cc_ra_buf_t *in = NULL;
    cc_enclave_result_t ret;

    ret = gen_provision_no_as_in_buff(&in);
    if (ret != CC_SUCCESS) {
        return ret;
    }
    uint8_t data[TEST_REPORT_OUT_LEN] = {0};
    cc_ra_buf_t report = {TEST_REPORT_OUT_LEN, data};

    TEEC_Result gp_ret = RemoteAttest((struct ra_buffer_data *)in, (struct ra_buffer_data *)&report);
    free_gp_ra_buf(in);

    if (gp_ret != TEEC_SUCCESS) {
        print_error_term("gp ra provision no as failed ret:%x\n", gp_ret);
        return CC_ERROR_RA_PROVISION_NO_AS;
    }

    return CC_SUCCESS;
}

cc_enclave_result_t gp_prepare_ra_env(cc_ra_scenario_t scenario)
{
    cc_enclave_result_t ret = CC_SUCCESS;
    switch (scenario) {
        case CC_RA_SCENARIO_NO_AS:
            ret = gp_ra_provision_no_as();
            break;
        default:
            return CC_ERROR_RA_PRE_ENV_INVALID_SCENARIO;
    }
    return ret;
}

cc_enclave_result_t gp_get_ra_report(cc_ra_buf_t *in, cc_ra_buf_t *report)
{
    TEEC_Result gp_ret = RemoteAttest((struct ra_buffer_data *)in, (struct ra_buffer_data *)report);
    if (gp_ret != TEEC_SUCCESS) {
        print_error_term("get ra report failed, ret:%x\n", gp_ret);
        return CC_ERROR_RA_GET_REPORT;
    }

    return CC_SUCCESS;
}
