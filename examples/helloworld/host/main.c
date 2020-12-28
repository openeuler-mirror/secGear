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
#include "enclave.h"
#include "helloworld_u.h"

#define BUF_LEN 32

int main()
{
    int  retval = 0;
    char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t *context = NULL;
    cc_enclave_result_t res;

    printf("Create secgear enclave\n");

    res = cc_enclave_create(path, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        return res;
    }

    res = get_string(context, &retval, buf);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error\n");
    } else {
        printf("%s\n", buf);
    }

    if (context != NULL) {
        res = cc_enclave_destroy(context);
        if(res != CC_SUCCESS) {
            printf("Destroy enclave error\n");
        }
    }
    return res;
}
