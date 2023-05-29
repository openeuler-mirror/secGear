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
#include "enclave.h"
#include "status.h"
#include "la_demo_u.h"
#include "sg_ra_report.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int ecall_ret;
    char taid[37] = {0};
    char img_hash[65] = {0};
    char mem_hash[65] = {0};

    if (argc == 2) { // param num is 2
        FILE *fp = fopen(argv[1], "r");
        if (!fp) {
            printf("input ta basevalue file is invalid\n");
            return -1;
        }
        int ret = fscanf(fp, "%s %s %s", taid, img_hash, mem_hash);
        fclose(fp);
        if (ret < 0) {
            printf("read taid and hash from basevalue file failed\n");
            return -1;
        }
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

    ret = local_attest_test(&context, &ecall_ret, taid, img_hash, mem_hash);
    if (ret != CC_SUCCESS || ecall_ret != CC_SUCCESS) {
        printf("local attest error\n");
        cc_enclave_destroy(&context);
        return -1;
    }
    printf("local attest success\n");
  
    cc_enclave_destroy(&context);

    return 0;
}
