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

#include "qca_demo.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/rand.h>

#include "sg_ra_report.h"
#include "sg_ra_report_verify.h"
#include "gp_ra_helper.h"
#include "enclave_log.h"


#define TEST_NONCE_LEN 32
#define TEST_REPORT_OUT_LEN 0x3000

char *g_target_taid = "7763a15a-0a9e-4e86-90cd-e4262583948a";
int main(void)
{
    // todo 添加是否初始化标志位? itrustee_sdk接口如果有独立错误码，就不用新增标志位了
    cc_enclave_result_t ret = cc_prepare_ra_env(CC_RA_SCENARIO_NO_AS);
    if (ret != CC_SUCCESS) {
        print_debug("prepare ra env error, ret:%x!\n", ret);
        return -1;
    }

    gp_get_ra_report_input_t ra_input = {0};

    ra_input.uuid = (uint8_t *)g_target_taid;
    ra_input.with_tcb = false;

    if (RAND_priv_bytes(ra_input.nonce, TEST_NONCE_LEN) <= 0) {
        return CC_FAIL;
    }
    ra_input.nonce_len = TEST_NONCE_LEN + 1;

    cc_ra_buf_t *in = NULL;
    ret = gen_ra_report_in_buff(&ra_input, &in);
    if (ret != CC_SUCCESS) {
        print_debug("gen ra report in buff error! ret:%x\n", ret);
        return -1;
    }

    uint8_t data[TEST_REPORT_OUT_LEN] = {0};
    cc_ra_buf_t report = {TEST_REPORT_OUT_LEN, data};

    ret = cc_get_ra_report(in, &report);
    free_gp_ra_buf(in);
    if (ret != CC_SUCCESS) {
        print_debug("get ra report error, ret:%x!\n", ret);
        return -1;
    }

    print_ra_report(&report);

    cc_ra_buf_t cc_nonce;
    cc_nonce.buf = ra_input.nonce;
    cc_nonce.len = ra_input.nonce_len;

    char *basevalue = "/home/hmy/secGear_ra_dev/examples/remote_attest/basevalue.txt";
    return cc_verify_report(&report, &cc_nonce, CC_RA_VERIFY_TYPE_STRICT, basevalue);
}