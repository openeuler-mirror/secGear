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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "rust_attestation_agent.h"

#define CHALLENGE_LEN 32
int main()
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
        ._1 = false,
    };
    
    // Tuple2_bool_bool_t ima = {   // define input ima = Some(true)
    //     ._0 = true,
    //     ._1 = true,
    // };

    // step3: get report
    Vec_uint8_t report = get_report(&challenge, &ima);
    Vec_uint8_t claim;
    if (report.len != 0) {
        report.ptr[report.len] = '\0'; // rust return string has no '\0'
        printf("get report success, report:%s\n", report.ptr);
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
    return 0;
}
