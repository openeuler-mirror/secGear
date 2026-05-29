/*
 * Copyright (c) 2026 secGear contributors.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include "enclave.h"
#include "starterkit_u.h"

#define BUF_LEN 64
#define LEFT_ADDEND 7
#define RIGHT_ADDEND 35
#define EXPECTED_ADD_RESULT 42

#define ENCLAVE_PATH "./enclave.signed.so"

int main(void)
{
    cc_enclave_t context = {0};
    cc_enclave_result_t res;
    int retval = 0;

    char buf[BUF_LEN] = {0};
    int sum = 0;

    res = cc_enclave_create(ENCLAVE_PATH,
                            AUTO_ENCLAVE_TYPE,
                            0,
                            SECGEAR_DEBUG_FLAG,
                            NULL,
                            0,
                            &context);
    if (res != CC_SUCCESS) {
        printf("cc_enclave_create failed: 0x%x\n", res);
        return 1;
    }

    res = GetMessage(&context, &retval, buf);
    if (res != CC_SUCCESS || retval != 0) {
        printf("GetMessage failed: res=0x%x retval=%d\n", res, retval);
        cc_enclave_destroy(&context);
        return 1;
    }
    printf("message from enclave: %s\n", buf);

    res = AddNumbers(&context, &retval, LEFT_ADDEND, RIGHT_ADDEND, &sum);
    if (res != CC_SUCCESS || retval != 0) {
        printf("AddNumbers failed: res=0x%x retval=%d\n", res, retval);
        cc_enclave_destroy(&context);
        return 1;
    }
    printf("sum from enclave: %d\n", sum);

    res = cc_enclave_destroy(&context);
    if (res != CC_SUCCESS) {
        printf("cc_enclave_destroy failed: 0x%x\n", res);
        return 1;
    }

    return 0;
}
