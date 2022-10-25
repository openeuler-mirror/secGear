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
#include <sys/time.h>
#include <string.h>
#include "enclave.h"
#include "secgear_uswitchless.h"
#include "secgear_shared_memory.h"

#include "switchless_u.h"

#define BUF_LEN 32

int main()
{
    int  retval = 0;
    char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t context = {0};
    cc_enclave_result_t res = CC_FAIL;

    printf("Create secgear enclave\n");

    char real_p[PATH_MAX];
    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == NULL) {
        if (getcwd(real_p, sizeof(real_p)) == NULL) {
            printf("Cannot find enclave.sign.so");
            goto end;
        }
        if (PATH_MAX - strlen(real_p) <= strlen("/enclave.signed.so")) {
            printf("Failed to strcat enclave.sign.so path");
            goto end;
        }
        (void)strcat(real_p, "/enclave.signed.so");
    }

    /* switchless configuration */
    cc_sl_config_t sl_cfg = CC_USWITCHLESS_CONFIG_INITIALIZER;
    sl_cfg.num_tworkers = 2; /* 2 tworkers */
    sl_cfg.sl_call_pool_size_qwords = 2; /* 2 * 64 tasks */
    enclave_features_t features = {ENCLAVE_FEATURE_SWITCHLESS, (void *)&sl_cfg};

    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &features, 1, &context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        goto end;
    }

    char *shared_buf = (char *)cc_malloc_shared_memory(&context, BUF_LEN);
    if (shared_buf == NULL) {
        printf("Malloc shared memory failed.\n");
        goto error;
    }

    /* normal ecall */
    res = get_string(&context, &retval, buf);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Normal ecall error\n");
    } else {
        printf("buf: %s\n", buf);
    }

    /* switchless ecall */
    res = get_string_switchless(&context, &retval, shared_buf);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Switchless ecall error\n");
    } else {
        printf("shared_buf: %s\n", shared_buf);
    }

    res = cc_free_shared_memory(&context, shared_buf);
    if (res != CC_SUCCESS) {
        printf("Free shared memory failed:%x.\n", res);
    }

error:
    res = cc_enclave_destroy(&context);
    if(res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    }
end:
    return res;
}

