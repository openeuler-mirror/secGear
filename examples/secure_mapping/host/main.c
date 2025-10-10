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
#include <string.h>

#include "enclave.h"
#include "sm_demo_u.h"
#include "secure_mapping_host.h"

#define BUF_LEN 256

static const unsigned char cipher1[] = {
    0x67, 0xe2, 0x78, 0xfd, 0x1f, 0x03, 0xe4, 0x94,
    0x87, 0x38, 0x3e, 0x4f, 0x39, 0xc3, 0xdf, 0xdc
};
static const unsigned char cipher2[] = {
    0x25, 0xac, 0xee, 0x6a, 0xb7, 0x64, 0x94, 0xd2,
    0x7c, 0x15, 0x03, 0x1c, 0xa0, 0xa2, 0x3e, 0xed
};
static const unsigned char cipher3[] = {
    0xbf, 0x94, 0x20, 0x1c, 0x99, 0x79, 0x10, 0x57,
    0x50, 0x81, 0xa6, 0x3a, 0x0e, 0x64, 0xe2, 0xea
};

int main()
{
    int  retval = 0;
    size_t len = 0;
    char *path = PATH;
    char buf[BUF_LEN];
    uint64_t fid1;
    uint64_t fid2;
    uint64_t sum_fid;
    cc_enclave_result_t res = CC_FAIL;
    cc_enclave_t context = {0};

    res = cc_enclave_create(path, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        return res;
    }

    // 插入
    res = cc_sm_transition_c2i(&context, &retval, 0, cipher1, sizeof(cipher1), INVALID_MAPPING_ID, &fid1);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error, fid = %lx\n", fid1);
    }
    res = cc_sm_transition_c2i(&context, &retval, 0, cipher2, sizeof(cipher2), INVALID_MAPPING_ID, &fid2);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error\n");
    }
    
    // 计算
    res = tee_uint32_val_add(&context, &retval, fid1, fid2, &sum_fid);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error\n");
    }

    // 获取结果
    res = cc_sm_transition_i2c(&context, &retval, 0, &sum_fid, buf, &len);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error\n");
    }

    if (strcmp(cipher3, buf) == 0) {
        printf("Success!\n");
    } else {
        printf("Failed!\n");
    }

    res = cc_enclave_destroy(&context);
    if (res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    } else {
        printf("Destroy enclave success\n");
    }
    return res;
}
