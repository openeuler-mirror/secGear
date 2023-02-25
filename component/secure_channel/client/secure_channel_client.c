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
#include "secure_channel_client.h"

#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "status.h"
#include "enclave_log.h"
#include "secure_channel_common.h"

#define SEC_CHL_RECV_BUF_MAX_LEN 1024

struct cc_sec_chl_handle {
    sec_chl_ecdh_ctx_t *ecdh_ctx;   // key exchange context
    pthread_mutex_t lock;           // proctect recv_buf and recv_buf_len
    uint8_t recv_buf[SEC_CHL_RECV_BUF_MAX_LEN];  // secure channel init msg max len
    size_t  recv_buf_len;                        // secure channel init msg real len
    uint8_t *svr_pubkey;
    size_t   svr_pubkey_len;
    cc_sec_chl_algo_t algo;
};

typedef enum {
    STATE_ORIGIN = 0,
    STATE_WAIT_SVRPUBKEY,
    STATE_SVRPUBKEY_READY,
    STATE_WAIT_RA_REPORT,
    STATE_RA_REPORT_READY,
    STATE_VERIFY_RA_SUCCESS,
    STATE_VERIFY_SVRPUBKEY_SUCCESS,
    STATE_WAIT_SVR_PARAM,
    STATE_SVR_PARAM_READY,
    STATE_LOCAL_PARAM_READY,
    STATE_WAIT_SET_PARAM_RET,
    STATE_ALL_READY,
    STATE_SUCCESS,
    STATE_FAIL
} sec_chl_init_fsm_state_t;

typedef enum {
    EVENT_GET_SVRPUBKEY = 0,
    EVENT_RECV_SVRPUBKEY,
    EVENT_GET_RA_REPORT,
    EVENT_RECV_RA_REPORT,
    EVENT_VERIFY_RA_REPORT,
    EVENT_VERIFY_SVRPUBKEY,
    EVENT_GET_SVR_PARAM,
    EVENT_RECV_SVR_PARAM,
    EVENT_GEN_LOCAL_PARAM,
    EVENT_SET_PARAM_TO_PEER,
    EVENT_RECV_SET_PARAM_RET,
    EVENT_COMPUTE_SESSIONKEY,
} sec_chl_init_fsm_event_id_t;

typedef cc_enclave_result_t (*sec_chl_init_fsm_action_t)(cc_sec_chl_ctx_t *ctx);

typedef struct {
    sec_chl_init_fsm_state_t cur_state;
    sec_chl_init_fsm_event_id_t event_id;
    sec_chl_init_fsm_state_t next_state;
    sec_chl_init_fsm_action_t action;
} sec_chl_fsm_state_transform_t;

static cc_enclave_result_t sec_chl_send_request(cc_conn_kit_t *conn_kit, sec_chl_msg_t *req_msg)
{
    int ret;
    size_t req_msg_len = sizeof(sec_chl_msg_t) + req_msg->data_len;

    // send request to server
    ret = conn_kit->send(conn_kit->conn, (uint8_t *)req_msg, req_msg_len);
    if (ret < 0) {
        print_error_term("client send request failed\n");
        return CC_ERROR_SEC_CHL_SEND_MSG;
    }

    return CC_SUCCESS;
}

static void del_local_sec_chl_ctx(cc_sec_chl_ctx_t *ctx)
{
    pthread_mutex_destroy(&ctx->handle->lock);
    if (ctx->handle->ecdh_ctx != NULL) {
        del_ecdh_ctx(ctx->handle->ecdh_ctx);
    }
    if (ctx->handle->svr_pubkey != NULL) {
        free(ctx->handle->svr_pubkey);
    }
    free(ctx->handle);
    ctx->handle = NULL;
    return;
}

cc_enclave_result_t cc_sec_chl_client_encrypt(cc_sec_chl_ctx_t *ctx, void *plain, size_t plain_len,
    void *encrypt, size_t *encrypt_len)
{
    if (ctx == NULL || plain == NULL || plain_len == 0 || encrypt_len == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (ctx->handle == NULL) {
        return CC_ERROR_SEC_CHL_NOTREADY;
    }

    size_t need_len = DATA_SIZE_LEN + plain_len + DATA_SIZE_LEN + GCM_TAG_LEN;
    if (encrypt == NULL || *encrypt_len < need_len) {
        *encrypt_len = need_len;
        return CC_ERROR_SEC_CHL_LEN_NOT_ENOUGH;
    }

    return sec_chl_encrypt(ctx->handle->ecdh_ctx, plain, plain_len, encrypt, encrypt_len);
}

cc_enclave_result_t cc_sec_chl_client_decrypt(cc_sec_chl_ctx_t *ctx, void *encrypt, size_t encrypt_len,
    void *plain, size_t *plain_len)
{
    if (ctx == NULL || encrypt == NULL || encrypt_len == 0 || plain_len == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (ctx->handle == NULL) {
        return CC_ERROR_SEC_CHL_NOTREADY;
    }
    size_t need_len = buf_to_num(encrypt, DATA_SIZE_LEN);
    if (plain == NULL || *plain_len < need_len) {
        *plain_len = need_len;
        return CC_ERROR_SEC_CHL_LEN_NOT_ENOUGH;
    }

    return sec_chl_decrypt(ctx->handle->ecdh_ctx, encrypt, encrypt_len, plain, plain_len);
}

static cc_enclave_result_t sec_chl_destroy_svr(cc_sec_chl_ctx_t *ctx)
{
    sec_chl_msg_t msg = {0};
    msg.msg_type = SEC_CHL_MSG_DESTROY;
    msg.session_id = ctx->session_id;
    cc_enclave_result_t ret = sec_chl_send_request(&(ctx->conn_kit), &msg);
    if (ret != CC_SUCCESS) {
        print_error_term("secure channel destroy server request failed\n");
        return CC_ERROR_SEC_CHL_DESTROY_SVR;
    }
    return ret;
}

void cc_sec_chl_client_fini(cc_sec_chl_ctx_t *ctx)
{
    if (ctx == NULL || ctx->handle == NULL) {
        return;
    }
    (void)sec_chl_destroy_svr(ctx);
    del_local_sec_chl_ctx(ctx);

    return;
}

cc_enclave_result_t cc_sec_chl_client_callback(cc_sec_chl_ctx_t *ctx, void *buf, size_t len)
{
    if (ctx == NULL || buf == NULL || len == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (len > SEC_CHL_RECV_BUF_MAX_LEN) {
        print_error_term("call back recv buf len:%lu is invalid", len);
        return CC_ERROR_SEC_CHL_RECV_MSG_LEN_INVALID;
    }
    pthread_mutex_lock(&ctx->handle->lock);
    memset(ctx->handle->recv_buf, 0, sizeof(ctx->handle->recv_buf));
    memcpy(ctx->handle->recv_buf, buf, len);
    ctx->handle->recv_buf_len = len;
    pthread_mutex_unlock(&ctx->handle->lock);

    return CC_SUCCESS;
}

static cc_enclave_result_t get_svr_pubkey(cc_sec_chl_ctx_t *ctx)
{
    sec_chl_msg_t msg = {0};
    msg.msg_type = SEC_CHL_MSG_GET_SVR_PUBKEY;
    cc_enclave_result_t ret = sec_chl_send_request(&(ctx->conn_kit), &msg);
    if (ret != CC_SUCCESS) {
        return CC_ERROR_SEC_CHL_GET_SVR_PUBKEY;
    }

    return CC_SUCCESS;
}

static cc_enclave_result_t recv_svr_pubkey(cc_sec_chl_ctx_t *ctx)
{
    sec_chl_msg_t *msg = NULL;

    pthread_mutex_lock(&ctx->handle->lock);
    if (ctx->handle->recv_buf_len == 0) {
        pthread_mutex_unlock(&ctx->handle->lock);
        return CC_ERROR_SEC_CHL_WAITING_RECV_MSG;
    }
    msg = (sec_chl_msg_t *)ctx->handle->recv_buf;
    ctx->handle->svr_pubkey = calloc(1, msg->data_len);
    if (ctx->handle->svr_pubkey == NULL) {
        pthread_mutex_unlock(&ctx->handle->lock);
        return CC_ERROR_SEC_CHL_MEMORY;
    }
    memcpy(ctx->handle->svr_pubkey, msg->data, msg->data_len);
    ctx->handle->svr_pubkey_len = msg->data_len;
    ctx->session_id = msg->session_id;
    pthread_mutex_unlock(&ctx->handle->lock);

    return CC_SUCCESS;
}

static cc_enclave_result_t get_ra_report(cc_sec_chl_ctx_t *ctx)
{
    (void)ctx;
    return CC_SUCCESS;
}

static cc_enclave_result_t recv_ra_report(cc_sec_chl_ctx_t *ctx)
{
    (void)ctx;
    return CC_SUCCESS;
}

static cc_enclave_result_t verify_ra_report(cc_sec_chl_ctx_t *ctx)
{
    (void)ctx;
    return CC_SUCCESS;
}

static cc_enclave_result_t verify_svr_pubkey(cc_sec_chl_ctx_t *ctx)
{
    (void)ctx;
    return CC_SUCCESS;
}

static cc_enclave_result_t get_svr_param(cc_sec_chl_ctx_t *ctx)
{
    sec_chl_msg_t msg = {0};
    msg.msg_type = SEC_CHL_MSG_GET_SVR_EXCH_PARAM;
    msg.session_id = ctx->session_id;
    cc_enclave_result_t ret = sec_chl_send_request(&(ctx->conn_kit), &msg);
    if (ret != CC_SUCCESS) {
        return CC_ERROR_SEC_CHL_GET_PEER_EXCH_PARAM;
    }
    return CC_SUCCESS;
}

static cc_enclave_result_t recv_svr_param(cc_sec_chl_ctx_t *ctx)
{
    int ec_nid;
    sec_chl_msg_t *msg = NULL;
    cc_enclave_result_t ret;

    pthread_mutex_lock(&ctx->handle->lock);
    if (ctx->handle->recv_buf_len == 0) {
        pthread_mutex_unlock(&ctx->handle->lock);
        return CC_ERROR_SEC_CHL_WAITING_RECV_MSG;
    }
    msg = (sec_chl_msg_t *)ctx->handle->recv_buf;
    memcpy(&ec_nid, msg->data + RANDOM_LEN, sizeof(int));

    ret = verify_signature(ctx->handle->svr_pubkey, ctx->handle->svr_pubkey_len, msg->data, msg->data_len);
    if (ret != CC_SUCCESS) {
        print_error_term("client key exchange, verify server exch param signature failed\n");
        pthread_mutex_unlock(&ctx->handle->lock);
        return ret;
    }

    sec_chl_ecdh_ctx_t *ecdh_ctx = new_local_ecdh_ctx(ec_nid);
    if (ecdh_ctx == NULL) {
        print_error_term("client key exchange, new local ecdh ctx failed\n");
        pthread_mutex_unlock(&ctx->handle->lock);
        return CC_ERROR_SEC_CHL_GEN_LOCAL_EXCH_PARAM;
    }

    ecdh_ctx->svr_exch_param_buf = (uint8_t *)calloc(1, msg->data_len);
    if (ecdh_ctx->svr_exch_param_buf == NULL) {
        del_ecdh_ctx(ecdh_ctx);
        pthread_mutex_unlock(&ctx->handle->lock);
        return CC_ERROR_SEC_CHL_MEMORY;
    }
    memcpy(ecdh_ctx->svr_exch_param_buf, msg->data, msg->data_len);
    ecdh_ctx->svr_exch_param_buf_len = msg->data_len;
    ctx->handle->ecdh_ctx = ecdh_ctx;

    pthread_mutex_unlock(&ctx->handle->lock);

    return CC_SUCCESS;
}

static cc_enclave_result_t gen_local_param(cc_sec_chl_ctx_t *ctx)
{
    return gen_local_exch_buf(ctx->handle->ecdh_ctx);
}

static cc_enclave_result_t set_local_param_to_peer(cc_sec_chl_ctx_t *ctx)
{
    int ret;
    sec_chl_msg_t *msg = NULL;
    sec_chl_ecdh_ctx_t *ecdh_ctx = ctx->handle->ecdh_ctx;
    size_t len = sizeof(sec_chl_msg_t) + ecdh_ctx->local_exch_param_buf_len;

    msg = (sec_chl_msg_t *)calloc(1, len);
    if (msg == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }

    memcpy(msg->data, ecdh_ctx->local_exch_param_buf, ecdh_ctx->local_exch_param_buf_len);
    msg->data_len = ecdh_ctx->local_exch_param_buf_len;

    msg->session_id = ctx->session_id;
    msg->msg_type = SEC_CHL_MSG_SEND_CLI_EXCH_PARAM;

    ret = sec_chl_send_request(&ctx->conn_kit, msg);
    free(msg);
    if (ret != CC_SUCCESS) {
        ret = CC_ERROR_SEC_CHL_SET_PARAM_TO_PEER;
    }
    return ret;
}

static cc_enclave_result_t recv_set_param_ret(cc_sec_chl_ctx_t *ctx)
{
    sec_chl_msg_t *msg = NULL;
    cc_enclave_result_t ret;

    pthread_mutex_lock(&ctx->handle->lock);
    if (ctx->handle->recv_buf_len == 0) {
        pthread_mutex_unlock(&ctx->handle->lock);
        return CC_ERROR_SEC_CHL_WAITING_RECV_MSG;
    }
    msg = (sec_chl_msg_t *)ctx->handle->recv_buf;
    ret = msg->ret;
    pthread_mutex_unlock(&ctx->handle->lock);

    return ret;
}

static cc_enclave_result_t sec_chl_compute_session_key(cc_sec_chl_ctx_t *ctx)
{
    sec_chl_exch_param_t *local_exch_param = NULL;
    sec_chl_exch_param_t *svr_exch_param_buf = NULL;
    int ret = get_exch_param_from_buf(ctx->handle->ecdh_ctx->svr_exch_param_buf,
        ctx->handle->ecdh_ctx->svr_exch_param_buf_len, &svr_exch_param_buf);
    if (ret != CC_SUCCESS) {
        return ret;
    }
    
    ret = get_exch_param_from_buf(ctx->handle->ecdh_ctx->local_exch_param_buf,
        ctx->handle->ecdh_ctx->local_exch_param_buf_len, &local_exch_param);
    if (ret != CC_SUCCESS) {
        del_exch_param(svr_exch_param_buf);
        return ret;
    }
    ret = compute_session_key(ctx->handle->ecdh_ctx, local_exch_param, svr_exch_param_buf);
    if (ret != CC_SUCCESS) {
        print_error_term("client key exchange, compute session key failed\n");
        del_exch_param(svr_exch_param_buf);
        del_exch_param(local_exch_param);
        return ret;
    }

    del_exch_param(svr_exch_param_buf);
    del_exch_param(local_exch_param);
    return CC_SUCCESS;
}

static sec_chl_fsm_state_transform_t g_state_transform_table[] = {
    {STATE_ORIGIN, EVENT_GET_SVRPUBKEY, STATE_WAIT_SVRPUBKEY, get_svr_pubkey},
    {STATE_WAIT_SVRPUBKEY, EVENT_RECV_SVRPUBKEY, STATE_SVRPUBKEY_READY, recv_svr_pubkey},
    {STATE_SVRPUBKEY_READY, EVENT_GET_RA_REPORT, STATE_WAIT_RA_REPORT, get_ra_report},
    {STATE_WAIT_RA_REPORT, EVENT_RECV_RA_REPORT, STATE_RA_REPORT_READY, recv_ra_report},
    {STATE_RA_REPORT_READY, EVENT_VERIFY_RA_REPORT, STATE_VERIFY_RA_SUCCESS, verify_ra_report},
    {STATE_VERIFY_RA_SUCCESS, EVENT_VERIFY_SVRPUBKEY, STATE_VERIFY_SVRPUBKEY_SUCCESS, verify_svr_pubkey},
    {STATE_VERIFY_SVRPUBKEY_SUCCESS, EVENT_GET_SVR_PARAM, STATE_WAIT_SVR_PARAM, get_svr_param},
    {STATE_WAIT_SVR_PARAM, EVENT_RECV_SVR_PARAM, STATE_SVR_PARAM_READY, recv_svr_param},
    {STATE_SVR_PARAM_READY, EVENT_GEN_LOCAL_PARAM, STATE_LOCAL_PARAM_READY, gen_local_param},
    {STATE_LOCAL_PARAM_READY, EVENT_SET_PARAM_TO_PEER, STATE_WAIT_SET_PARAM_RET, set_local_param_to_peer},
    {STATE_WAIT_SET_PARAM_RET, EVENT_RECV_SET_PARAM_RET, STATE_ALL_READY, recv_set_param_ret},
    {STATE_ALL_READY, EVENT_COMPUTE_SESSIONKEY, STATE_SUCCESS, sec_chl_compute_session_key},
};

#define RECV_MSG_TIMEOUT_CNT 30
#define RECV_MSG_INTERVAL (60 * 1000)
cc_enclave_result_t sec_chl_run_fsm(cc_sec_chl_ctx_t *ctx)
{
    cc_enclave_result_t ret;
    int cnt = 0;
    for (size_t i = 0; i < sizeof(g_state_transform_table) / sizeof(g_state_transform_table[0]);) {
        ret = g_state_transform_table[i].action(ctx);
        if (ret == CC_ERROR_SEC_CHL_WAITING_RECV_MSG && cnt < RECV_MSG_TIMEOUT_CNT) {
            cnt++;
            usleep(RECV_MSG_INTERVAL);
            continue;
        }
        if (ret != CC_SUCCESS) {
            return ret;
        }
        i++;
        cnt = 0;
    }
    return CC_SUCCESS;
}

static bool is_valid_algo(cc_sec_chl_algo_t algo)
{
    if (algo >= 0 && algo < CC_SEC_CHL_ALGO_MAX) {
        return true;
    }
    return false;
}

cc_enclave_result_t cc_sec_chl_client_init(cc_sec_chl_algo_t algo, cc_sec_chl_ctx_t *ctx)
{
    if (ctx == NULL || !is_valid_algo(algo)) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    if (!is_valid_conn_kit(&ctx->conn_kit)) {
        return CC_ERROR_SEC_CHL_INVALID_CONN;
    }
    ctx->handle = (cc_sec_chl_handle_t *)calloc(1, sizeof(cc_sec_chl_handle_t));
    if (ctx->handle == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }
    ctx->handle->algo = algo;
    pthread_mutex_init(&ctx->handle->lock, NULL);

    cc_enclave_result_t ret = sec_chl_run_fsm(ctx);
    if (ret != CC_SUCCESS) {
        print_error_term("secure channel client init error:%x\n", ret);
        cc_sec_chl_client_fini(ctx);
    } else {
        print_notice("secure channel client init success\n\n");
    }

    return ret;
}
