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
#include <stdbool.h>
#include <linux/limits.h>
#include "enclave.h"
#include "switchless_u.h"
#include "string.h"
#include "secgear_uswitchless.h"
#include "secgear_shared_memory.h"
#include <sys/time.h>

cc_enclave_t g_enclave;

bool init_enclave(enclave_features_t *features)
{
    char *path = PATH;
    cc_enclave_result_t ret;
    char real_p[PATH_MAX];

    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == NULL) {
        if (getcwd(real_p, sizeof(real_p)) == NULL) {
            printf("Cannot find enclave.sign.so");
            return false;
        }

        if (PATH_MAX - strlen(real_p) <= strlen("/enclave.signed.so")) {
            printf("Failed to strcat enclave.sign.so path");
            return false;
        }

        (void)strcat(real_p, "/enclave.signed.so");
    }

    ret = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, features, 1, &g_enclave);
    if (ret != CC_SUCCESS) {
        printf("Create enclave error: %d\n", ret);
        return false;
    }

    return true;
}

void fini_enclave(cc_enclave_t *enclave)
{
    cc_enclave_result_t ret = cc_enclave_destroy(enclave);
    if (ret != CC_SUCCESS) {
        printf("Error: destroy enclave failed: %x\n", ret);
    }
}

void benchmark_ecall_empty(bool is_switchless, unsigned long nrepeats)
{
    struct timespec time_start;
    struct timespec time_end;
    struct timespec duration = {0, 0};
    cc_enclave_result_t(*ecall_fn)(cc_enclave_t *) = is_switchless ? ecall_empty_switchless : ecall_empty;

    clock_gettime(CLOCK_REALTIME, &time_start);
    unsigned long tmp_nrepeats = nrepeats;
    while (tmp_nrepeats--) {
        ecall_fn(&g_enclave);
    }
    clock_gettime(CLOCK_REALTIME, &time_end);

    duration.tv_sec += time_end.tv_sec - time_start.tv_sec;
    duration.tv_nsec += time_end.tv_nsec - time_start.tv_nsec;

    printf("Repeating an %s empty ecall for %lu times takes %lu.%09lus\n",
        is_switchless ? "[switchless]" : "[ ordinary ]", nrepeats, duration.tv_sec, duration.tv_nsec);
}

#define TEST_STR "switchless"

void transfer_data_using_shared_memory()
{
    cc_enclave_result_t ret;
    int len = 32;

    char *buf = (char *)cc_malloc_shared_memory(&g_enclave, len);
    if (buf == NULL) {
        printf("Error: malloc shared memory failed.\n");
        return;
    }

    ret = cc_register_shared_memory(&g_enclave, buf);
    if (ret != CC_SUCCESS) {
        (void)cc_free_shared_memory(&g_enclave, buf);
        printf("Error: register shared memory failed:%x.\n", ret);
        return;
    }

    (void)strcpy(buf, TEST_STR);
    printf("before test_toupper, buf=%s\n", buf);
    test_toupper(&g_enclave, buf, strlen(TEST_STR));
    printf("after test_toupper, buf=%s\n\n", buf);

    ret = cc_unregister_shared_memory(&g_enclave, buf);
    if (ret != CC_SUCCESS) {
        (void)cc_free_shared_memory(&g_enclave, buf);
        printf("Error: unregister shared memory failed:%x.\n", ret);
        return;
    }

    ret = cc_free_shared_memory(&g_enclave, buf);
    if (ret != CC_SUCCESS) {
        printf("Error: free shared memory failed:%x.\n", ret);
    }
}

int main()
{
    cc_sl_config_t sl_cfg = CC_USWITCHLESS_CONFIG_INITIALIZER;
    sl_cfg.num_tworkers = 2; /* 2 tworkers */
    sl_cfg.sl_call_pool_size_qwords = 2; /* 2 * 64 tasks */
    enclave_features_t features = {ENCLAVE_FEATURE_SWITCHLESS, (void *)&sl_cfg};

    if (!init_enclave(&features)) {
        printf("Error: init enclave failed\n");
        return -1;
    }

    printf("\n1. Running a benchmark that compares [ordinary] and [switchless] ecall\n");
    unsigned long nrepeats = 100000;
    benchmark_ecall_empty(false, nrepeats);
    benchmark_ecall_empty(true, nrepeats);

    printf("\n2. Transfer data using shared memory\n");
    transfer_data_using_shared_memory();

    fini_enclave(&g_enclave);

    return 0;
}
