/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * CloudEnclave is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef SECURE_CHANNEL_HOST_H
#define SECURE_CHANNEL_HOST_H

#include "enclave.h"
#include "secure_channel.h"
#ifdef  __cplusplus
extern "C" {
#endif

typedef struct {
    int timerfd;
    int eventfd;
} sec_chl_timer_t;

typedef struct {
    cc_enclave_t *enclave_ctx;
    sec_chl_timer_t timer;
    bool is_init;
} cc_sec_chl_svr_ctx_t;

typedef struct {
    cc_sec_chl_svr_ctx_t *svr_ctx;
    cc_conn_kit_t conn_kit;
} cc_sec_chl_conn_ctx_t;
/**
* start seucre channel service
* @param[in] ctx, The pointer of secure channel context
*
* @retval, On success, return 0.
*          On error, cc_enclave_result_t errorno is returned.
*/
cc_enclave_result_t cc_sec_chl_svr_init(cc_sec_chl_svr_ctx_t *ctx);

/**
* secure channel service uninit function, destory secure channel server resource
*
* @param[in] ctx, The pointer of secure channel context
*
* @retval, On success, return 0.
*          On error, cc_enclave_result_t errorno is returned.
*/
cc_enclave_result_t cc_sec_chl_svr_fini(cc_sec_chl_svr_ctx_t *ctx);

/**
* secure channel msg handle callback on server host. NOTE:does not support multithreading now
* @param[in] ctx, The cc_sec_chl_conn_ctx_t instance
*
* @param[in] buf, Server host receive message buffer
* @param[in] buf_len, The length of receive buffer
*
* @retval On success, 0 is returned. On error, cc_enclave_result_t is returned.
*/
cc_enclave_result_t cc_sec_chl_svr_callback(cc_sec_chl_conn_ctx_t *ctx, void *buf, size_t buf_len);

# ifdef  __cplusplus
}
# endif
#endif
