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
#include <string.h>
#include "enclave.h"
#include "seal_data_u.h"

#define BUF_LEN 256
#define ENCLAVE_PATH "./enclave.signed.so"

int main(void)
{
    cc_enclave_t context = {0};
    cc_enclave_result_t res;
    int retval = 0;

    char plain[] = "secret-for-demo";
    char sealed[BUF_LEN] = {0};
    char unsealed[BUF_LEN] = {0};
    int sealedLen = 0;
    int plainLen = 0;

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

    res = SealData(&context, &retval,
                   plain, (int)strlen(plain),
                   sealed, BUF_LEN,
                   &sealedLen);
    if (res != CC_SUCCESS || retval != 0) {
        printf("SealData failed: res=0x%x retval=%d\n", res, retval);
        cc_enclave_destroy(&context);
        return 1;
    }

    printf("sealed result: %s\n", sealed);
    printf("sealed length: %d\n", sealedLen);

    res = UnsealData(&context, &retval,
                     sealed, sealedLen,
                     unsealed, BUF_LEN,
                     &plainLen);
    if (res != CC_SUCCESS || retval != 0) {
        printf("UnsealData failed: res=0x%x retval=%d\n", res, retval);
        cc_enclave_destroy(&context);
        return 1;
    }

    unsealed[plainLen] = '\0';
    printf("unsealed result: %s\n", unsealed);
    printf("unsealed length: %d\n", plainLen);

    res = cc_enclave_destroy(&context);
    if (res != CC_SUCCESS) {
        printf("cc_enclave_destroy failed: 0x%x\n", res);
        return 1;
    }

    return 0;
}
