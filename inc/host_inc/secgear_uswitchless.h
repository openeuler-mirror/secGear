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

#ifndef __SECGEAR_USWITCHLESS_H__
#define __SECGEAR_USWITCHLESS_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* number of untrusted (for ocalls) worker threads */
    uint32_t num_uworkers;

    /* number of trusted (for ecalls) worker threads */
    uint32_t num_tworkers;

    /* number of switchless calls pool size. (actual number is x64) */
    uint32_t sl_call_pool_size_qwords;

    /* max number of parameters, only for GP */
    uint32_t num_max_params;

    /*
     * how many times to execute assembly pause instruction while waiting for worker thread to start executing
     * switchless call before failing back to direct ECall/OCall, only for SGX
     */
    uint32_t retries_before_fallback;

    /*
     * how many times a worker thread executes assembly pause instruction while waiting for switchless call request
     * before going to sleep, only for SGX
     */
    uint32_t retries_before_sleep;
} cc_sl_config_t;

#ifdef __cplusplus
}
#endif

#endif