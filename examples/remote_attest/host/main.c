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
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "enclave.h"
#include "status.h"
#include "ra_demo_u.h"
#include "sg_ra_report.h"
#include "sg_ra_report_verify.h"

#define TEST_NONCE_LEN 32
#define TEST_REPORT_OUT_LEN 0x3000
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char taid[37] = {0};
    char basevalue_real_path[PATH_MAX] = {0};

    char *ta_basevalue_file = "../basevalue.txt";

    if (realpath(ta_basevalue_file, basevalue_real_path) == NULL) {
        printf("ta basevalue file path error\n");
        return -1;
    }
    printf("input:%s\nreal path:%s\n", ta_basevalue_file, basevalue_real_path);
    FILE *fp = fopen(basevalue_real_path, "r");
    if (!fp) {
        printf("input ta basevalue file is invalid\n");
        return -1;
    }
    int ret_f = fscanf(fp, "%s", taid);
    fclose(fp);
    if (ret_f < 0) {
        printf("read taid and hash from basevalue file failed\n");
        return -1;
    }

    cc_enclave_t context = {0};
    char *path = PATH;
    cc_enclave_result_t ret = cc_enclave_create(path, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    if (ret != CC_SUCCESS) {
        printf("create enclave error %x!\n", ret);
        return -1;
    }

    ret = cc_prepare_ra_env(CC_RA_SCENARIO_NO_AS);
    if (ret != CC_SUCCESS) {
        printf("init attestation env error\n");
        cc_enclave_destroy(&context);
        return -1;
    }

    cc_get_ra_report_input_t ra_input = {0};
    ra_input.taid = (uint8_t *)taid;
    ra_input.with_tcb = false;

    if (RAND_priv_bytes(ra_input.nonce, TEST_NONCE_LEN) <= 0) {
        cc_enclave_destroy(&context);
        return CC_FAIL;
    }
    ra_input.nonce_len = TEST_NONCE_LEN + 1;

    uint8_t data[TEST_REPORT_OUT_LEN] = {0};
    cc_ra_buf_t report = {TEST_REPORT_OUT_LEN, data};

    ret = cc_get_ra_report(&ra_input, &report);
    if (ret != CC_SUCCESS) {
        printf("get ra report error, ret:%x!\n", ret);
        cc_enclave_destroy(&context);
        return -1;
    }
    printf("get ra report success\n");

    cc_ra_buf_t cc_nonce;
    cc_nonce.buf = ra_input.nonce;
    cc_nonce.len = ra_input.nonce_len;

    ret = cc_verify_report(&report, &cc_nonce, CC_RA_VERIFY_TYPE_STRICT, basevalue_real_path);
    if (ret != CC_SUCCESS) {
        printf("verify report error\n");
        cc_enclave_destroy(&context);
        return -1;
    }
    printf("verify report success\n");
  
    cc_enclave_destroy(&context);

    return 0;
}
