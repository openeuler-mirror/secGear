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
#include "qt_rpc_proxy.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>


cc_enclave_result_t handle_ecall_function(uint8_t *input, size_t input_len, uint8_t **output, size_t *output_len)
{
    char *ecall_ret = "ecall ret end";
    size_t ret_len = input_len + strlen(ecall_ret) + 1;
    uint8_t *rsp = calloc(1, ret_len);

    memcpy(rsp, input, input_len);
    memcpy(rsp + input_len, ecall_ret, strlen(ecall_ret) + 1);

    usleep(5000 * 10);

    *output = (uint8_t *)rsp;
    *output_len = ret_len;

    return 0;
}

cc_enclave_result_t handle_ocall_function(uint8_t *input, size_t input_len, uint8_t **output, size_t *output_len)
{
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_len;

    return 0;
}

int ecall_test(size_t input_len, size_t output_len)
{
    uint8_t *input = NULL;
    uint8_t *output = NULL;
    uint8_t *expect = NULL;
    int ret = 0;
    char *ecall_ret = "ecall ret end";

    if (output_len < input_len + strlen(ecall_ret) + 1) {
        printf("test input len error\n");
        return -1;
    }

    input = (uint8_t *)calloc(1, input_len);
    if (input == NULL) {
        printf("ecall_normal malloc failed\n");
        ret = -2;
        goto end;
    }
    memset(input, 'A', input_len);

    output = (uint8_t *)calloc(1, output_len);
    if (output == NULL) {
        printf("ecall_normal malloc failed\n");
        ret = -2;
        goto end;
    }
    memset(output, 'O', output_len);

    size_t ret_len = input_len + strlen(ecall_ret) + 1;
    expect = calloc(1, ret_len);
    memcpy(expect, input, input_len);
    memcpy(expect + input_len, ecall_ret, strlen(ecall_ret) + 1);
    
    ret = qt_rpc_proxy_call(input, input_len, output, &output_len);
    if (ret != 0) {
        printf("ecall failed\n");
        ret = -1;
        goto end;
    }

    if (memcmp(output, expect, output_len) != 0) {
        printf("output is not match with expect\n");
        ret = 1;
    }

end:
    free(expect);
    free(input);
    free(output);
    return ret;
}

int testcase_ecall_data_len(void)
{
    int len[] = {10, 1024, 1024 * 10, 1024 * 20, 1024 * 30, 1024 * 40, 1024 * 60, 1024 * 1024};
    printf("[%s] begin\n", __FUNCTION__);
    for (size_t i = 0; i < sizeof(len) / sizeof(int); i++) {
        int ret = ecall_test(len[i], len[i] + 14);
        if (ret != 0) {
            printf("testcase_ecall_data_len len:%d failed, ret:%d\n", len[i], ret);
            return ret;
        }
    }
    printf("[%s] end successful\n", __FUNCTION__);

    return 0;
}

int testcase_ecall_data_len_exceed_1M(void)
{
    printf("[%s] begin\n", __FUNCTION__);
    size_t exceed_limit_len = 1024 * 1024 + 512;
    int ret = ecall_test(exceed_limit_len, exceed_limit_len + 14);
    if (ret != 0) {
        printf("testcase_ecall_data_len len:%lu failed, ret:%d\n", exceed_limit_len, ret);
        return ret;
    }

    printf("[%s] end successful\n", __FUNCTION__);
    return 0;
}

#define TEST_MULTI_THREADS_NUM 40
extern void *ecall_thread(void *arg);
int testcase_ecall_multi_threads(void)
{
    printf("[%s] begin\n", __FUNCTION__);
    pthread_t tid[TEST_MULTI_THREADS_NUM];
    for (int i = 0; i < TEST_MULTI_THREADS_NUM; i++) {
        pthread_create(&tid[i], NULL, ecall_thread, NULL);
    }

    for (int i = 0; i < TEST_MULTI_THREADS_NUM; i++) {
        pthread_join(tid[i], NULL);
    }
    printf("[%s] end successful\n", __FUNCTION__);
    return 0;
}

typedef int (*testcase_fun_t)(void);
testcase_fun_t g_all_testcase[] = {
    testcase_ecall_data_len,
    // testcase_ecall_data_len_exceed_1M,
    testcase_ecall_multi_threads,
};

void *ecall_thread(void *arg)
{
    (void)arg;

    int ret = testcase_ecall_data_len();
    if (ret != 0) {
        printf("run testcase failed\n");
        return NULL;
    }

    return NULL;
}

int main(void)
{
#ifndef QT_SERVER
    // proxy host init
    int ret = qt_rpc_proxy_init(4, handle_ocall_function);
    if (ret != 0) {
        printf("main qt rpc proxy init failed\n");
        return -1;
    }
    
    printf("run testcase begin\n");
    // run all testcase
    for (size_t i = 0; i < sizeof(g_all_testcase) / sizeof(testcase_fun_t); i++) {
        ret = (g_all_testcase[i])();
        if (ret != 0) {
            printf("run testcase failed\n");
            return -1;
        }
    }
    // proxy host destroy
    printf("run testcase successful end\n");
    sleep(3);
    qt_rpc_proxy_destroy();
    return 0;

#else
    printf("proxy enclave server start\n");
    int cnt = 20;
    while (cnt-- >= 0) {
        sleep(1);
    }
    printf("proxy enclave server stop success\n");
#endif

    return 0;
}

