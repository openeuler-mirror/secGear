/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef SECGEAR_USWITCHLESS_H
#define SECGEAR_USWITCHLESS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* Worker threads work all the time. */
    WORKERS_POLICY_BUSY,
    /* The worker thread is only woken up when the task arrives and goes to sleep after the task is processed. */
    WORKERS_POLICY_WAKEUP,
    WORKERS_POLICY_MAX
} cc_workers_policy_t;

typedef struct {
    /* number of untrusted (for ocalls) worker threads */
    uint32_t num_uworkers;

    /* number of trusted (for ecalls) worker threads */
    uint32_t num_tworkers;

    /* number of switchless calls pool size. (actual number is x 64) */
    uint32_t sl_call_pool_size_qwords;

    /* max number of parameters, only for GP */
    uint32_t num_max_params;

    /*
     * how many times to execute assembly pause instruction while waiting for worker thread to start executing
     * switchless call before falling back to direct ECall/OCall, only for SGX
     */
    uint32_t retries_before_fallback;

    /*
     * how many times a worker thread executes assembly pause instruction while waiting for switchless call request
     * before going to sleep, only for SGX
     */
    uint32_t retries_before_sleep;

    /* Worker thread scheduling policy, refer to cc_workers_policy_t, only for GP */
    uint64_t workers_policy;
} cc_sl_config_t;

#define CC_USWITCHLESS_CONFIG_INITIALIZER   {1, 1, 1, 16, 0, 0, WORKERS_POLICY_BUSY}

#ifdef __cplusplus
}
#endif

#endif
