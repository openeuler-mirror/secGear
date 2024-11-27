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

#include "secure_channel_host.h"

#include <stdio.h>
#include <string.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "enclave.h"
#include "status.h"
#include "enclave_log.h"
#include "secure_channel_u.h"
#include "secure_channel_common.h"
#include "sg_ra_report.h"
#include "enclave_internal.h"

#define RSA_PUBKEY_LEN 640
static int sec_chl_gen_pubkey(cc_enclave_t *context, sec_chl_msg_t *msg, sec_chl_msg_t **rsp_msg, size_t *rsp_msg_len)
{
    int res;
    cc_enclave_result_t ret_val;
    size_t session_id = msg->session_id;
    uint8_t rsa_pubkey[RSA_PUBKEY_LEN] = {0};
    size_t rsa_pubkey_len = RSA_PUBKEY_LEN;
    sec_chl_msg_t *rsp = NULL;

    // get_enclave_pubkey
    ret_val = get_enclave_pubkey(context, &res, &session_id, rsa_pubkey, &rsa_pubkey_len);
    if (ret_val != CC_SUCCESS || res != (int)CC_SUCCESS) {
        print_error_term("call enclave get pubkey error!\n");
        return CC_FAIL;
    }

    rsp = (sec_chl_msg_t *)calloc(1, sizeof(sec_chl_msg_t) + rsa_pubkey_len);
    if (rsp == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }
    rsp->session_id = session_id;
    rsp->data_len = rsa_pubkey_len;
    rsp->sub_type = GET_SVRPUBKEY_SUBTYPE_SVR_GEN;
    memcpy(rsp->data, rsa_pubkey, rsa_pubkey_len);
    *rsp_msg = rsp;
    *rsp_msg_len = sizeof(sec_chl_msg_t) + rsa_pubkey_len;

    return CC_SUCCESS;
}

static int sec_chl_get_ra_report(cc_enclave_t *context, sec_chl_msg_t *msg,
    sec_chl_msg_t **rsp_msg, size_t *rsp_msg_len)
{
    (void)context;
    cc_enclave_result_t ret_val;
    sec_chl_msg_t *rsp = NULL;

    sec_chl_ra_req_t *ra_req = (sec_chl_ra_req_t *)(msg->data);

    cc_get_ra_report_input_t ra_input = {0};
    ra_input.taid = (uint8_t *)ra_req->taid;
    (void)memcpy(ra_input.nonce, ra_req->nonce, SEC_CHL_REQ_NONCE_LEN);
    ra_input.nonce_len = SEC_CHL_REQ_NONCE_LEN + 1;
    ra_input.with_tcb = ra_req->with_tcb;
    ra_input.req_key = ra_req->req_key;

    uint8_t data[REPORT_OUT_LEN] = {0};
    cc_ra_buf_t report = {REPORT_OUT_LEN, data};

    ret_val = cc_get_ra_report(&ra_input, &report);

    if (ret_val != CC_SUCCESS) {
        print_error_term("secure channel host get ra report failed\n");
        return CC_ERROR_SEC_CHL_GET_RA_REPORT;
    }
    rsp = (sec_chl_msg_t *)calloc(1, sizeof(sec_chl_msg_t) + report.len);
    (void)memcpy(rsp->data, report.buf, report.len);
    rsp->data_len = report.len;
    rsp->sub_type = GET_SVRPUBKEY_SUBTYPE_REPORT;
    rsp->session_id = msg->session_id;

    *rsp_msg = rsp;
    *rsp_msg_len = sizeof(sec_chl_msg_t) + report.len;

    return CC_SUCCESS;
}

static int sec_chl_get_pubkey(cc_enclave_t *context, sec_chl_msg_t *msg, sec_chl_msg_t **rsp_msg, size_t *rsp_msg_len)
{
    if (is_support_remote_attest(context)) {
        int ret;
        cc_enclave_result_t ret_val;
        size_t session_id = 0;
        ret_val = init_session(context, &ret, &session_id);
        if (ret_val != CC_SUCCESS || ret != CC_SUCCESS) {
            print_error_term("init session failed\n");
            return CC_ERROR_SEC_CHL_INIT_SESSEION;
        }
        msg->session_id = session_id;
        return sec_chl_get_ra_report(context, msg, rsp_msg, rsp_msg_len);
    } else {
        return sec_chl_gen_pubkey(context, msg, rsp_msg, rsp_msg_len);
    }
}

static int sec_chl_set_enc_key(cc_enclave_t *context, sec_chl_msg_t *msg,
    sec_chl_msg_t **rsp_msg, size_t *rsp_msg_len)
{
    int res;
    cc_enclave_result_t ret_val;
    size_t  session_id = msg->session_id;

    ret_val = set_enc_key(context, &res, session_id, msg->data, msg->data_len);
    if (ret_val != CC_SUCCESS || res != (int)CC_SUCCESS) {
        print_error_term("set enc key error!\n");
        return CC_FAIL;
    }

    sec_chl_msg_t *rsp = (sec_chl_msg_t *)calloc(1, sizeof(sec_chl_msg_t));
    if (rsp == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }

    *rsp_msg = rsp;
    *rsp_msg_len = sizeof(sec_chl_msg_t);

    return CC_SUCCESS;
}

static int sec_chl_get_svr_exch_param(cc_enclave_t *context, sec_chl_msg_t *msg,
    sec_chl_msg_t **rsp_msg, size_t *rsp_msg_len)
{
    cc_enclave_result_t ret_val;
    int res;
    uint8_t *exch_param = NULL;
    size_t  exch_param_len = 0;
    size_t  session_id = msg->session_id;

    ret_val = get_enclave_exch_param_len(context, &res, session_id, &exch_param_len);
    if (ret_val != CC_SUCCESS || res != (int)CC_SUCCESS || exch_param_len == 0) {
        print_error_term("call enclave get exch param len error!\n");
        return CC_FAIL;
    }

    exch_param = (uint8_t *)calloc(1, exch_param_len);
    if (exch_param == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }

    ret_val = get_enclave_exch_param(context, &res, session_id, exch_param, exch_param_len);
    if (ret_val != CC_SUCCESS || res != (int)CC_SUCCESS) {
        print_error_term("call enclave get_enclave_exch_param error!\n");
        free(exch_param);
        return -1;
    }

    sec_chl_msg_t *rsp = (sec_chl_msg_t *)calloc(1, sizeof(sec_chl_msg_t) + exch_param_len);
    if (rsp == NULL) {
        free(exch_param);
        return CC_ERROR_SEC_CHL_MEMORY;
    }

    rsp->data_len = exch_param_len;
    memcpy(rsp->data, exch_param, exch_param_len);
    *rsp_msg = rsp;
    *rsp_msg_len = sizeof(sec_chl_msg_t) + exch_param_len;
    free(exch_param);

    return CC_SUCCESS;
}

static int sec_chl_set_client_exch_param(cc_enclave_t *context, sec_chl_msg_t *msg,
    sec_chl_msg_t **rsp_msg, size_t *rsp_msg_len)
{
    int res;
    cc_enclave_result_t ret_val;
    size_t  session_id = msg->session_id;

    ret_val = set_peer_exch_param(context, &res, session_id, msg->data, msg->data_len);
    if (ret_val != CC_SUCCESS || res != (int)CC_SUCCESS) {
        print_error_term("set peer exch param error!\n");
        return CC_FAIL;
    }

    sec_chl_msg_t *rsp = (sec_chl_msg_t *)calloc(1, sizeof(sec_chl_msg_t));
    if (rsp == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }

    *rsp_msg = rsp;
    *rsp_msg_len = sizeof(sec_chl_msg_t);

    return CC_SUCCESS;
}
static int sec_chl_destroy(cc_enclave_t *context, sec_chl_msg_t *msg, sec_chl_msg_t **rsp_msg, size_t *rsp_msg_len)
{
    cc_enclave_result_t ret_val;
    size_t session_id = msg->session_id;

    ret_val = del_enclave_sec_chl(context, session_id);
    if (ret_val != CC_SUCCESS) {
        print_error_term("del enclave secure channel error!\n");
        return CC_FAIL;
    }
    sec_chl_msg_t *rsp = (sec_chl_msg_t *)calloc(1, sizeof(sec_chl_msg_t));
    if (rsp == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }

    *rsp_msg = rsp;
    *rsp_msg_len = sizeof(sec_chl_msg_t);

    return CC_SUCCESS;
}

#define TIMER_WHEN_START 1 // timer start after 1 second, since call timerfd_settime
#define TIMER_INTERVAL 60 // 60 second
#define TIMER_MAX_EVENTS 2
#define TIMER_EXIT_CODE 0XFFFF
static int init_timer_interval(int timerfd)
{
    struct itimerspec new_value = {};
    new_value.it_value.tv_sec = TIMER_WHEN_START;
    new_value.it_value.tv_nsec = 0;
    new_value.it_interval.tv_sec = TIMER_INTERVAL;
    new_value.it_interval.tv_nsec = 0;

    return timerfd_settime(timerfd, 0, &new_value, NULL);
}

static void handle_timer(cc_sec_chl_svr_ctx_t *ctx)
{
    uint64_t exp = 0;
    int timerfd = ctx->timer.timerfd;

    int ret = read(timerfd, &exp, sizeof(uint64_t));
    if (ret == sizeof(uint64_t)) {
        (void)enclave_check_session_timeout(ctx->enclave_ctx);
    }
    return;
}

static void handle_exit_event(int eventfd, bool *is_continue)
{
    uint64_t exp = 0;
    int ret = read(eventfd, &exp, sizeof(uint64_t));
    if (ret == sizeof(uint64_t)) {
        *is_continue = (exp == TIMER_EXIT_CODE) ? false : true;
    }
    return;
}

static void handle_events(cc_sec_chl_svr_ctx_t *ctx, int nfd, struct epoll_event* events, bool *is_continue)
{
    int timerfd = ctx->timer.timerfd;
    int eventfd = ctx->timer.eventfd;

    for (int i = 0; i < nfd && i < TIMER_MAX_EVENTS; i++) {
        if (events[i].data.fd == timerfd) {
            handle_timer(ctx);
        } else if (events[i].data.fd == eventfd) {
            handle_exit_event(eventfd, is_continue);
        }
    }
    return;
}

void *check_session_timeout(void *arg)
{
    cc_sec_chl_svr_ctx_t *ctx = (cc_sec_chl_svr_ctx_t *)arg;
    int timerfd = ctx->timer.timerfd;
    int eventfd = ctx->timer.eventfd;

    if (init_timer_interval(timerfd) == -1) {
        print_error_term("start timer failed\n");
        return NULL;
    }

    int epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd == -1) {
        print_error_term("epoll create failed\n");
        return NULL;
    }

    struct epoll_event ep_timer;
    ep_timer.events = EPOLLIN;
    ep_timer.data.fd = timerfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &ep_timer);

    struct epoll_event ep_event;
    ep_event.events = EPOLLIN;
    ep_event.data.fd = eventfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, eventfd, &ep_event);

    struct epoll_event events[TIMER_MAX_EVENTS];

    bool flag = true;
    while (flag) {
        int nfd = epoll_wait(epollfd, events, TIMER_MAX_EVENTS, -1);
        if (nfd <= 0) {
            continue;
        }
        handle_events(ctx, nfd, events, &flag);
    }
    close(epollfd);

    return NULL;
}

static cc_enclave_result_t sec_chl_create_timer(cc_sec_chl_svr_ctx_t *ctx)
{
    pthread_t tid;

    ctx->timer.timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (ctx->timer.timerfd == -1) {
        print_error_term("timerfd create failed\n");
        return CC_FAIL;
    }

    ctx->timer.eventfd = eventfd(0, 0);
    if (ctx->timer.eventfd == -1) {
        print_error_term("create eventfd failed\n");
        close(ctx->timer.timerfd);
        return CC_FAIL;
    }
    pthread_create(&tid, NULL, check_session_timeout, ctx);

    return CC_SUCCESS;
}

static void sec_chl_stop_timer(sec_chl_timer_t *timer)
{
    struct itimerspec new_value = {};
    new_value.it_value.tv_sec = 0;
    new_value.it_value.tv_nsec = 0;
    new_value.it_interval.tv_sec = 0;
    new_value.it_interval.tv_nsec = 0;
    if (timerfd_settime(timer->timerfd, 0, &new_value, NULL) == -1) {
        print_error_term("stop timer failed\n");
    }
    close(timer->timerfd);

    uint64_t timer_thread_exit = TIMER_EXIT_CODE;
    int ret = write(timer->eventfd, &timer_thread_exit, sizeof(uint64_t));
    if (ret == -1) {
        print_error_term("stop timer failed\n");
    }
    close(timer->eventfd);
    print_notice("stop timer\n");

    return;
}

cc_enclave_result_t cc_sec_chl_svr_init(cc_sec_chl_svr_ctx_t *ctx)
{
    int ret_val, res;
    if (ctx == NULL || ctx->enclave_ctx == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (ctx->is_init) {
        print_warning("secure channel already started\n");
        return CC_SUCCESS;
    }
    if (is_support_remote_attest(ctx->enclave_ctx)) {
        cc_enclave_result_t ret = cc_prepare_ra_env(CC_RA_SCENARIO_NO_AS);
        if (ret != CC_SUCCESS) {
            print_error_term("prepare ra env error, ret:%x!\n", ret);
            return -1;
        }
    }

    ret_val = enclave_start_sec_chl(ctx->enclave_ctx, &res);
    if (ret_val != CC_SUCCESS || res != CC_SUCCESS) {
        return CC_ERROR_SEC_CHL_SVR_INIT;
    }

    ret_val = sec_chl_create_timer(ctx);
    if (ret_val != CC_SUCCESS) {
        print_error_term("sec chl svr init create timer failed\n");
    }
    ctx->is_init = true;

    return CC_SUCCESS;
}

cc_enclave_result_t cc_sec_chl_svr_fini(cc_sec_chl_svr_ctx_t *ctx)
{
    if (ctx == NULL || ctx->enclave_ctx == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (!ctx->is_init) {
        print_warning("secure channel is not started\n");
        return CC_SUCCESS;
    }
    sec_chl_stop_timer(&(ctx->timer));
    enclave_stop_sec_chl(ctx->enclave_ctx);
    ctx->is_init = false;
    return CC_SUCCESS;
}

static cc_enclave_result_t handle_recv_msg(cc_enclave_t *context, sec_chl_msg_t *msg,
    sec_chl_msg_t **rsp_msg, size_t *rsp_msg_len)
{
    cc_enclave_result_t ret = CC_FAIL;
    switch (msg->msg_type) {
        case SEC_CHL_MSG_GET_SVR_PUBKEY:
            ret = sec_chl_get_pubkey(context, msg, rsp_msg, rsp_msg_len);
            break;
        case SEC_CHL_MSG_SET_ENC_KEY_TO_SVR:
            ret = sec_chl_set_enc_key(context, msg, rsp_msg, rsp_msg_len);
            break;
        case SEC_CHL_MSG_GET_SVR_EXCH_PARAM:
            ret = sec_chl_get_svr_exch_param(context, msg, rsp_msg, rsp_msg_len);
            break;
        case SEC_CHL_MSG_SEND_CLI_EXCH_PARAM:
            ret = sec_chl_set_client_exch_param(context, msg, rsp_msg, rsp_msg_len);
            break;
        case SEC_CHL_MSG_DESTROY:
            ret = sec_chl_destroy(context, msg, rsp_msg, rsp_msg_len);
            break;
        default:
            print_error_term("error msg type:%d\n", msg->msg_type);
            break;
    }
    return ret;
}

static int handle_respon_msg(cc_sec_chl_conn_ctx_t *ctx, cc_enclave_result_t ret,
    sec_chl_msg_t *rsp_msg, size_t rsp_msg_len)
{
    if (rsp_msg == NULL) {
        rsp_msg = (sec_chl_msg_t *)calloc(1, sizeof(sec_chl_msg_t));
        if (rsp_msg == NULL) {
            return CC_ERROR_SEC_CHL_MEMORY;
        }
        rsp_msg_len = sizeof(sec_chl_msg_t);
    }
    rsp_msg->ret = ret;
    return ctx->conn_kit.send(ctx->conn_kit.conn, (void *)rsp_msg, rsp_msg_len);
}

static cc_enclave_result_t handle_msg(cc_sec_chl_conn_ctx_t *ctx, sec_chl_msg_t *msg)
{
    size_t rsp_msg_len = 0;
    sec_chl_msg_t *rsp_msg = NULL;

    cc_enclave_result_t ret = handle_recv_msg(ctx->svr_ctx->enclave_ctx, msg, &rsp_msg, &rsp_msg_len);

    int result = handle_respon_msg(ctx, ret, rsp_msg, rsp_msg_len);
    free(rsp_msg);
    if (result < 0) {
        (void)del_enclave_sec_chl(ctx->svr_ctx->enclave_ctx, msg->session_id);
        print_error_term("cc_sec_chl_svr_callback send response, msg failed\n");
        return CC_ERROR_SEC_CHL_SEND_MSG;
    }
    return ret;
}

static cc_enclave_result_t check_callback_param(cc_sec_chl_conn_ctx_t *ctx, void *buf, size_t buf_len)
{
    if (ctx == NULL || ctx->svr_ctx == NULL || ctx->svr_ctx->enclave_ctx == NULL
        || buf == NULL || buf_len <= 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (!is_valid_conn_kit(&ctx->conn_kit)) {
        return CC_ERROR_SEC_CHL_INVALID_CONN;
    }

    return CC_SUCCESS;
}

cc_enclave_result_t cc_sec_chl_svr_callback(cc_sec_chl_conn_ctx_t *ctx, void *buf, size_t buf_len)
{
    sec_chl_msg_t *msg = NULL;

    cc_enclave_result_t ret = check_callback_param(ctx, buf, buf_len);
    if (ret != CC_SUCCESS) {
        return ret;
    }
    if (!ctx->svr_ctx->is_init) {
        print_warning("secure channel server is not started\n");
        return CC_ERROR_SEC_CHL_NOTREADY;
    }
    msg = (sec_chl_msg_t *)buf;
    return handle_msg(ctx, msg);
}