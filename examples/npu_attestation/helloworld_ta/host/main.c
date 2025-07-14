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
#include <signal.h>
#include <stdlib.h>
#include <linux/limits.h>
#include "enclave.h"
#include "helloworld_u.h"
#include "string.h"

#define BUF_LEN 32

volatile sig_atomic_t g_exit_flag = 0;
volatile sig_atomic_t g_force_exit = 0;
uint32_t g_sleep_time = 10;

void sigint_handler(int signum)
{
    static int count = 0;
    count++;
    if (count == 1) {
        g_exit_flag = 1; // first ctrl+c triggers elegant exit
    } else {
        g_force_exit = 1; // second ctrl+c triggers immediate exit
    }
}

int main()
{
    int  retval = 0;
    char *path = PATH;
    char buf[BUF_LEN];
    struct sigaction sa;
    
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigint_handler;
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        perror("Failed to set up SIGINT handler\n");
        return 1;
    }

    cc_enclave_t context = {0};
    cc_enclave_result_t res = CC_FAIL;

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

    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    if (res != CC_SUCCESS) {
        printf("host create enclave error\n");
        goto end; 
    }
    printf("host create enclave success\n");

    // Keep TA alive during attestation, unless user ctrl+c exits.
    while (!g_exit_flag && !g_force_exit) {
        res = get_string(&context, &retval, buf);
        if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
            printf("Ecall enclave error\n");
        } else {
            printf("enclave say:%s\n", buf);
        }

        sleep(g_sleep_time);
    }

    res = cc_enclave_destroy(&context);
    if (res != CC_SUCCESS) {
        printf("host destroy enclave error\n");
    } else {
        printf("host destroy enclave success\n");
    }
end:
    return g_force_exit ? 1 : res;
}
