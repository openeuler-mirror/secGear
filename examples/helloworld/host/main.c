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
#include <unistd.h>
#include <linux/limits.h>
#include "enclave.h"
#include "helloworld_u.h"
#include "string.h"
#include "sg_ra_report.h"

#define BUF_LEN 32
#define MAX_BUFFER_LEN 5120

int main()
{
    int  retval = 0;
    char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t context;
    cc_enclave_result_t res;

    printf("Create secgear enclave\n");
    memset(&context, 0, sizeof(context));

    res = cc_enclave_create(path, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        return res;
    }

    res = get_string(&context, &retval, buf);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error\n");
    } else {
        printf("%s\n", buf);
    }

    uint8_t random[BUF_LEN] = {0}; 
    res = get_random(&context, &retval , random, BUF_LEN);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("get random from enclave error\n");
    } else {
        printf("get random from enclave success:\n");
        for (int i = 0; i < BUF_LEN; i++) {
            printf("%02X", random[i]);
        }
        printf("\n");
    }

    cc_get_ra_report_input_t in = {0};
    in.taid = (uint8_t *)&context;
    in.nonce_len = BUF_LEN;
    memcpy(in.nonce, random, BUF_LEN);

    uint8_t out_buf[MAX_BUFFER_LEN] = {0};
    cc_ra_buf_t out = {MAX_BUFFER_LEN, (uint8_t *)out_buf};
    res = cc_get_ra_report(&in, &out);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("get report from enclave error\n");
    } else {
        printf("get report from enclave success\n");
    }

    res = cc_enclave_destroy(&context);
    if(res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    }
    return res;
}
