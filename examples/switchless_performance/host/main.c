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
    struct timeval tval_before;
    struct timeval tval_after;
    struct timeval duration;
    cc_enclave_result_t(*ecall_fn)(cc_enclave_t *) = is_switchless ? ecall_empty_switchless : ecall_empty;

    gettimeofday(&tval_before, NULL);
    unsigned long tmp_nrepeats = nrepeats;
    while (tmp_nrepeats--) {
        ecall_fn(&g_enclave);
    }

    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &duration);

    printf("Repeating an %s empty ecall for %lu times takes %ld.%06lds\n",
        is_switchless ? "[switchless]" : "[ ordinary ]", nrepeats, (long)duration.tv_sec, (long)duration.tv_usec);
}

/* ecall_empty_switchless */
void benchmark_ecall_empty_sl_async(unsigned long nrepeats)
{
    cc_enclave_result_t ret_code;
    cc_enclave_result_t ret;
    struct timeval tval_before;
    struct timeval tval_after;
    struct timeval duration;
    int processed_cursor = 0;
    int retry_count = 0;

    int *arr = (int *)calloc(nrepeats, sizeof(int));
    if (arr == NULL) {
        return;
    }

    // BEGIN
    gettimeofday(&tval_before, NULL);

    for (int i = 0; i < nrepeats; ++i) {
        ret_code = ecall_empty_switchless_async(&g_enclave, &arr[i]);
        if (ret_code != CC_SUCCESS) {
            if (ret_code == CC_ERROR_SWITCHLESS_TASK_POOL_FULL) {
                // The task pool is full. You should try again later.
                --i;
                ++retry_count;
            } else {
                // Asynchronous invocation failed
                printf("Asynchronous invocation failed, ret=%x\n", ret_code);
            }
        }

        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], NULL);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded
            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    while (processed_cursor < nrepeats) {
        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], NULL);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
            continue;
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded
            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    // END
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &duration);

    free(arr);

    printf("retry_count:%d, processed_cursor:%d\n", retry_count, processed_cursor);
    printf("Repeating an empty sl async ecall for %lu times takes %ld.%06lds\n", nrepeats,
        (long int)duration.tv_sec, (long int)duration.tv_usec);
}

void benchmark_ecall_empty_sl_async_rollback(unsigned long nrepeats)
{
    cc_enclave_result_t ret_code;
    cc_enclave_result_t ret;
    struct timeval tval_before;
    struct timeval tval_after;
    struct timeval duration;
    int processed_cursor = 0;
    int rollback_count = 0;
    unsigned long tmp_nrepeats = nrepeats;

    int *arr = (int *)calloc(nrepeats, sizeof(int));
    if (arr == NULL) {
        return;
    }

    // BEGIN
    gettimeofday(&tval_before, NULL);

    for (int i = 0; i < tmp_nrepeats; ++i) {
        ret_code = ecall_empty_switchless_async(&g_enclave, &arr[i]);
        if (ret_code == CC_SUCCESS) {
            if (arr[i] == -1) {
                // rollback to common invoking when asynchronous switchless fails, and the common call is successful now
                --i;
                --tmp_nrepeats;
                rollback_count++;
            }
        } else {
            // Asynchronous invocation failed
            printf("Asynchronous invocation failed, ret=%x\n", ret_code);
        }

        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], NULL);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded
            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    while (processed_cursor < tmp_nrepeats) {
        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], NULL);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
            continue;
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded
            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    // END
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &duration);

    free(arr);

    printf("rollback_count:%d, processed_cursor:%d\n", rollback_count, processed_cursor);
    printf("Repeating an empty sl async ecall rollback for %lu times takes %ld.%06lds\n", nrepeats,
        (long int)duration.tv_sec, (long int)duration.tv_usec);
}


/* ecall_empty_switchless1 */
void benchmark_ecall_empty_sl_async1(unsigned long nrepeats)
{
    cc_enclave_result_t ret_code;
    cc_enclave_result_t ret;
    struct timeval tval_before;
    struct timeval tval_after;
    struct timeval duration;
    int processed_cursor = 0;
    int retry_count = 0;
    int one_share_buf_len = 32;
    int retval;

    int *arr = (int *)calloc(nrepeats, sizeof(int));
    if (arr == NULL) {
        return;
    }

    char *sharebuf = (char *)cc_malloc_shared_memory(&g_enclave, nrepeats * one_share_buf_len);
    if (sharebuf == NULL) {
        free(arr);
        printf("Error: malloc shared memory failed.\n");
        return;
    }

    // BEGIN
    gettimeofday(&tval_before, NULL);

    for (int i = 0; i < nrepeats; ++i) {
        strcpy(sharebuf + i * one_share_buf_len, "aAbBcCdD");
        ret_code = ecall_empty_switchless1_async(&g_enclave, &arr[i], NULL, sharebuf + i * one_share_buf_len,
            sizeof("aAbBcCdD"));
        if (ret_code != CC_SUCCESS) {
            if (ret_code == CC_ERROR_SWITCHLESS_TASK_POOL_FULL) {
                // The task pool is full. You should try again later.
                --i;
                ++retry_count;
            } else {
                // Asynchronous invocation failed
                printf("Asynchronous invocation failed, ret=%x\n", ret_code);
            }
        }

        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], &retval);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded, and check the execution result.
            if (retval != 1) {
                printf("get result retval err:%d, index:%d\n", retval, processed_cursor);
            }

            if (strcmp("AABBCCDD", sharebuf + processed_cursor * one_share_buf_len)) {
                printf("get result buffer err:%s, index:%d\n", sharebuf + processed_cursor * one_share_buf_len,
                    processed_cursor);
            }

            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    while (processed_cursor < nrepeats) {
        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], &retval);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
            continue;
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded, and check the execution result.
            if (retval != 1) {
                printf("get result retval err:%d, index:%d\n", retval, processed_cursor);
            }

            if (strcmp("AABBCCDD", sharebuf + processed_cursor * one_share_buf_len)) {
                printf("get result buffer err:%s, index:%d\n", sharebuf + processed_cursor * one_share_buf_len,
                    processed_cursor);
            }

            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    // END
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &duration);

    free(arr);

    ret = cc_free_shared_memory(&g_enclave, sharebuf);
    if (ret != CC_SUCCESS) {
        printf("Error: free shared memory failed:%x.\n", ret);
    }

    printf("retry_count:%d, processed_cursor:%d\n", retry_count, processed_cursor);
    printf("Repeating an empty sl async ecall [1] for %lu times takes %ld.%06lds\n", nrepeats,
        (long int)duration.tv_sec, (long int)duration.tv_usec);
}

void benchmark_ecall_empty_sl_async_rollback1(unsigned long nrepeats)
{
    cc_enclave_result_t ret_code;
    cc_enclave_result_t ret;
    struct timeval tval_before;
    struct timeval tval_after;
    struct timeval duration;
    int processed_cursor = 0;
    int one_share_buf_len = 32;
    int rollback_count = 0;
    int retval;
    unsigned long tmp_nrepeats = nrepeats;

    int *arr = (int *)calloc(nrepeats, sizeof(int));
    if (arr == NULL) {
        return;
    }

    char *sharebuf = (char *)cc_malloc_shared_memory(&g_enclave, nrepeats * one_share_buf_len);
    if (sharebuf == NULL) {
        free(arr);
        printf("Error: malloc shared memory failed.\n");
        return;
    }

    // BEGIN
    gettimeofday(&tval_before, NULL);

    for (int i = 0; i < tmp_nrepeats; ++i) {
        strcpy(sharebuf + i * one_share_buf_len, "aAbBcCdD");
        ret_code = ecall_empty_switchless1_async(&g_enclave, &arr[i], &retval, sharebuf + i * one_share_buf_len,
            sizeof("aAbBcCdD"));
        if (ret_code == CC_SUCCESS) {
            if (arr[i] == -1) {
                /*
                 * rollback to common invoking when asynchronous switchless fails, and the common call
                 * is successful now, check the execution result.
                 */
                if (retval != 1) {
                    printf("get result retval err:%d, index:%d\n", retval, i);
                }

                if (strcmp("AABBCCDD", sharebuf + i * one_share_buf_len)) {
                    printf("get result buffer err:%s, index:%d\n", sharebuf + i * one_share_buf_len, i);
                }

                --i;
                --tmp_nrepeats;
                rollback_count++;
            }
        } else {
            // Asynchronous invocation failed
            printf("Asynchronous invocation failed, ret=%x\n", ret_code);
        }

        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], &retval);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded, check the execution result.
            if (retval != 1) {
                printf("get result retval err:%d, index:%d\n", retval, processed_cursor);
            }

            if (strcmp("AABBCCDD", sharebuf + processed_cursor * one_share_buf_len)) {
                printf("get result buffer err:%s, index:%d\n", sharebuf + processed_cursor * one_share_buf_len,
                    processed_cursor);
            }

            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    while (processed_cursor < tmp_nrepeats) {
        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], &retval);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
            continue;
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded, check the execution result.
            if (retval != 1) {
                printf("get result retval err:%d, index:%d\n", retval, processed_cursor);
            }

            if (strcmp("AABBCCDD", sharebuf + processed_cursor * one_share_buf_len)) {
                printf("get result buffer err:%s, index:%d\n", sharebuf + processed_cursor * one_share_buf_len,
                    processed_cursor);
            }

            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    // END
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &duration);

    free(arr);
    ret = cc_free_shared_memory(&g_enclave, sharebuf);
    if (ret != CC_SUCCESS) {
        printf("Error: free shared memory failed:%x.\n", ret);
    }

    printf("rollback_count:%d, processed_cursor:%d\n", rollback_count, processed_cursor);
    printf("Repeating an empty sl async ecall rollback [1] for %lu times takes %ld.%06lds\n", nrepeats,
        (long int)duration.tv_sec, (long int)duration.tv_usec);
}

/* ecall_empty_switchless2 */
void benchmark_ecall_empty_sl_async2(unsigned long nrepeats)
{
    cc_enclave_result_t ret_code;
    cc_enclave_result_t ret;
    struct timeval tval_before;
    struct timeval tval_after;
    struct timeval duration;
    int processed_cursor = 0;
    int retry_count = 0;
    int one_share_buf_len = 32;
    int half_one_share_buf_len = 16;
    int retval;

    int *arr = (int *)calloc(nrepeats, sizeof(int));
    if (arr == NULL) {
        return;
    }

    char *sharebuf = (char *)cc_malloc_shared_memory(&g_enclave, nrepeats * one_share_buf_len);
    if (sharebuf == NULL) {
        free(arr);
        printf("Error: malloc shared memory failed.\n");
        return;
    }
    memset(sharebuf, 0, nrepeats * one_share_buf_len);

    // BEGIN
    gettimeofday(&tval_before, NULL);

    for (int i = 0; i < nrepeats; ++i) {
        strcpy(sharebuf + i * one_share_buf_len, "aAbBcCdD");
        ret_code = ecall_empty_switchless2_async(&g_enclave, &arr[i], NULL, sharebuf + i * one_share_buf_len,
            sizeof("aAbBcCdD"), sharebuf + i * one_share_buf_len + half_one_share_buf_len, sizeof("aAbBcCdD"));
        if (ret_code != CC_SUCCESS) {
            if (ret_code == CC_ERROR_SWITCHLESS_TASK_POOL_FULL) {
                // The task pool is full. You should try again later.
                --i;
                ++retry_count;
            } else {
                // Asynchronous invocation failed
                printf("Asynchronous invocation failed, ret=%x\n", ret_code);
            }
        }

        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], &retval);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded, check the execution result.
            if (retval != 2) {
                printf("get result retval err:%d, index:%d\n", retval, processed_cursor);
            }

            if (strcmp("AABBCCDD", sharebuf + processed_cursor * one_share_buf_len + half_one_share_buf_len)) {
                printf("get result buffer err:%s, index:%d\n",
                    sharebuf + processed_cursor * one_share_buf_len + half_one_share_buf_len, processed_cursor);
            }

            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    while (processed_cursor < nrepeats) {
        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], &retval);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
            continue;
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded, check the execution result.
            if (retval != 2) {
                printf("get result retval err:%d, index:%d\n", retval, processed_cursor);
            }

            if (strcmp("AABBCCDD", sharebuf + processed_cursor * one_share_buf_len + half_one_share_buf_len)) {
                printf("get result buffer err:%s, index:%d\n",
                    sharebuf + processed_cursor * one_share_buf_len + half_one_share_buf_len, processed_cursor);
            }

            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    // END
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &duration);

    free(arr);

    ret = cc_free_shared_memory(&g_enclave, sharebuf);
    if (ret != CC_SUCCESS) {
        printf("Error: free shared memory failed:%x.\n", ret);
    }

    printf("retry_count:%d, processed_cursor:%d\n", retry_count, processed_cursor);
    printf("Repeating an empty sl async ecall [2] for %lu times takes %ld.%06lds\n", nrepeats,
        (long int)duration.tv_sec, (long int)duration.tv_usec);
}

void benchmark_ecall_empty_sl_async_rollback2(unsigned long nrepeats)
{
    cc_enclave_result_t ret_code;
    cc_enclave_result_t ret;
    struct timeval tval_before;
    struct timeval tval_after;
    struct timeval duration;
    int processed_cursor = 0;
    int one_share_buf_len = 32;
    int half_one_share_buf_len = 16;
    int rollback_count = 0;
    int retval;
    unsigned long tmp_nrepeats = nrepeats;

    int *arr = (int *)calloc(nrepeats, sizeof(int));
    if (arr == NULL) {
        return;
    }

    char *sharebuf = (char *)cc_malloc_shared_memory(&g_enclave, nrepeats * one_share_buf_len);
    if (sharebuf == NULL) {
        free(arr);
        printf("Error: malloc shared memory failed.\n");
        return;
    }

    // BEGIN
    gettimeofday(&tval_before, NULL);

    for (int i = 0; i < tmp_nrepeats; ++i) {
        strcpy(sharebuf + i * one_share_buf_len, "aAbBcCdD");
        ret_code = ecall_empty_switchless2_async(&g_enclave, &arr[i], &retval, sharebuf + i * one_share_buf_len,
            sizeof("aAbBcCdD"), sharebuf + i * one_share_buf_len + half_one_share_buf_len, sizeof("aAbBcCdD"));
        if (ret_code == CC_SUCCESS) {
            if (arr[i] == -1) {
                /*
                 * rollback to common invoking when asynchronous switchless fails, and the common call
                 * is successful now, check the execution result.
                 */
                if (retval != 2) {
                    printf("get result retval err:%d, index:%d\n", retval, i);
                }

                if (strcmp("AABBCCDD", sharebuf + i * one_share_buf_len + half_one_share_buf_len)) {
                    printf("get result buffer err:%s, index:%d\n",
                        sharebuf + i * one_share_buf_len + half_one_share_buf_len, i);
                }

                --i;
                --tmp_nrepeats;
                rollback_count++;
            }
        } else {
            // Asynchronous invocation failed
            printf("Asynchronous invocation failed, ret=%x\n", ret_code);
        }

        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], &retval);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded, check the execution result.
            if (retval != 2) {
                printf("get result retval err:%d, index:%d\n", retval, processed_cursor);
            }

            if (strcmp("AABBCCDD", sharebuf + processed_cursor * one_share_buf_len + half_one_share_buf_len)) {
                printf("get result buffer err:%s, index:%d\n",
                    sharebuf + processed_cursor * one_share_buf_len + half_one_share_buf_len, processed_cursor);
            }

            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    while (processed_cursor < tmp_nrepeats) {
        ret = cc_sl_get_async_result(&g_enclave, arr[processed_cursor], &retval);
        if (ret == CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
            // Invoking processing
            continue;
        } else if (ret == CC_SUCCESS) {
            // Obtaining the result succeeded, check the execution result.
            if (retval != 2) {
                printf("get result retval err:%d, index:%d\n", retval, processed_cursor);
            }

            if (strcmp("AABBCCDD", sharebuf + processed_cursor * one_share_buf_len + half_one_share_buf_len)) {
                printf("get result buffer err:%s, index:%d\n",
                    sharebuf + processed_cursor * one_share_buf_len + half_one_share_buf_len, processed_cursor);
            }

            processed_cursor++;
        } else {
            // Failed to obtain the result
            processed_cursor++;
        }
    }

    // END
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &duration);

    free(arr);
    ret = cc_free_shared_memory(&g_enclave, sharebuf);
    if (ret != CC_SUCCESS) {
        printf("Error: free shared memory failed:%x.\n", ret);
    }

    printf("rollback_count:%d, processed_cursor:%d\n", rollback_count, processed_cursor);
    printf("Repeating an empty sl async ecall rollback [2] for %lu times takes %ld.%06lds\n", nrepeats,
        (long int)duration.tv_sec, (long int)duration.tv_usec);
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

    (void)strcpy(buf, TEST_STR);
    printf("before test_toupper, buf=%s\n", buf);
    test_toupper(&g_enclave, buf, strlen(TEST_STR));
    printf("after test_toupper, buf=%s\n\n", buf);

    ret = cc_free_shared_memory(&g_enclave, buf);
    if (ret != CC_SUCCESS) {
        printf("Error: free shared memory failed:%x.\n", ret);
    }
}

void onetime_normal(void)
{
    cc_enclave_result_t ret;
    int retval;

    char buf[] = "aAbBcCdD";
    ret = ecall_empty1(&g_enclave, &retval, buf, sizeof(buf));
    if (ret != CC_SUCCESS) {
        printf("Error: ecall_empty1, ret:%x.\n", ret);
        return;
    }
    printf("buf:%s, retval:%d\n", buf, retval);

    char buf1[] = "aAbBcCdD";
    char buf2[32] = {0};
    ret = ecall_empty2(&g_enclave, &retval, buf1, sizeof(buf1), buf2, sizeof(buf1) - 3);
    if (ret != CC_SUCCESS) {
        printf("Error: ecall_empty2, ret:%x.\n", ret);
        return;
    }
    printf("buf2:%s, retval:%d\n", buf2, retval);
}

int main(void)
{
    cc_sl_config_t sl_cfg = CC_USWITCHLESS_CONFIG_INITIALIZER;
    sl_cfg.num_tworkers = 2; /* 2 tworkers */
    sl_cfg.sl_call_pool_size_qwords = 8; /* 2 * 64 tasks */
    sl_cfg.rollback_to_common = false;
    enclave_features_t features = {ENCLAVE_FEATURE_SWITCHLESS, (void *)&sl_cfg};

    if (!init_enclave(&features)) {
        printf("Error: init enclave failed\n");
        return -1;
    }

    printf("\n1. Running a benchmark that compares [ordinary] and [switchless] ecall\n");
    unsigned long nrepeats = 10000;
    benchmark_ecall_empty(false, nrepeats);
    benchmark_ecall_empty(true, nrepeats);

    benchmark_ecall_empty_sl_async(nrepeats);
    benchmark_ecall_empty_sl_async1(nrepeats);
    benchmark_ecall_empty_sl_async2(nrepeats);

    printf("\n2. Transfer data using shared memory\n");
    transfer_data_using_shared_memory();

    printf("\n3. normal ecall\n");
    onetime_normal();

    fini_enclave(&g_enclave);

#if 1
    printf("\n=================================================\n");

    sl_cfg.rollback_to_common = true;
    if (!init_enclave(&features)) {
        printf("Error: init enclave failed\n");
        return -1;
    }

    printf("\n1. Running a benchmark that compares [ordinary] and [switchless] ecall\n");
    benchmark_ecall_empty(false, nrepeats);
    benchmark_ecall_empty(true, nrepeats);

    benchmark_ecall_empty_sl_async_rollback(nrepeats);
    benchmark_ecall_empty_sl_async_rollback1(nrepeats);
    benchmark_ecall_empty_sl_async_rollback2(nrepeats);

    printf("\n2. Transfer data using shared memory\n");
    transfer_data_using_shared_memory();

    printf("\n3. normal ecall\n");
    onetime_normal();

    fini_enclave(&g_enclave);
#endif

    return 0;
}
