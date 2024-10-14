/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

// gcc example.c -o aa-test -L. -lattestation_agent -lcrypto
#include "rust_attestation_agent.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <pthread.h>

#define CHALLENGE_LEN 32
#define TEST_THREAD_NUM 1

void *thread_proc(void *arg)
{
    // step1: generate random numers
    uint8_t nonce[CHALLENGE_LEN];
    RAND_priv_bytes(nonce, CHALLENGE_LEN);
    Vec_uint8_t challenge = {
        .ptr = (uint8_t *)&nonce,
        .len = CHALLENGE_LEN,
        .cap = CHALLENGE_LEN,
    };

    // step2: define ima input param
    Tuple2_bool_bool_t ima = {  // define input ima = Some(false)
        ._0 = true,
        ._1 = false,    // true: enable to get report with ima
    };

    // step3: get report
    Vec_uint8_t report = get_report(&challenge, &ima);
    Vec_uint8_t claim;
    if (report.len != 0) {
        report.ptr[report.len] = '\0'; // rust return string has no '\0'
        printf("get report success, report:%s\n", report.ptr);

        // parse report
        Vec_uint8_t claim_no_verify = parse_report(&report);
        if (claim_no_verify.len != 0) {
            claim_no_verify.ptr[claim_no_verify.len] = '\0';
            printf("parse report success: %s\n", claim_no_verify.ptr);
        }
        free_rust_vec(claim_no_verify);

        // step4: verify report
        claim = verify_report(&challenge, &report);
    }

    if (claim.len != 0) {
        claim.ptr[claim.len] = '\0';  // rust return string has no '\0'
        printf("verify report success, return claim:%s\n", claim.ptr);
    }

    // step5: free rust resource
    free_rust_vec(report);
    free_rust_vec(claim);
}
int main()
{
    char *level = "info";
    Vec_uint8_t log_level = {
        .ptr = (uint8_t *)level,
        .len = strlen(level),
        .cap = strlen(level),
    };
    init_env_logger(&log_level);

    pthread_t tids[TEST_THREAD_NUM];
    for (int i = 0; i < TEST_THREAD_NUM; i++) {
        pthread_create(&tids[i], NULL, thread_proc, NULL);
    }

    for (int i = 0; i < TEST_THREAD_NUM; i++) {
        pthread_join(tids[i], NULL);
    }

    return 0;
}
