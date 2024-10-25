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
#include <openssl/rand.h>
#include <openssl/pem.h>

#include "status.h"
#include "enclave_log.h"
#include "secure_channel_common.h"
#include "sg_ra_report_verify.h"
#include "cJSON.h"
#include "base64url.h"


#define SEC_CHL_RECV_BUF_MAX_LEN REPORT_OUT_LEN
struct cc_sec_chl_handle {
    sec_chl_ecdh_ctx_t *ecdh_ctx;   // key exchange context
    pthread_mutex_t lock;           // protect recv_buf and recv_buf_len
    uint8_t recv_buf[SEC_CHL_RECV_BUF_MAX_LEN];  // secure channel init msg max len
    size_t  recv_buf_len;                        // secure channel init msg real len
    cc_sec_chl_algo_t algo;
    sec_chl_ra_req_t ra_req;
    char *b64_enc_key;
    RSA *rsa_svr_pubkey;
};

typedef enum {
    STATE_ORIGIN = 0,
    STATE_WAIT_SVRPUBKEY,
    STATE_SVRPUBKEY_READY,
    STATE_WAIT_SET_ENC_KEY,
    STATE_SET_ENC_KEY_SUCCESS,
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
    EVENT_SET_ENC_KEY_TO_SVR,
    EVENT_RECV_SET_ENC_KEY_RET,
    EVENT_GET_SVR_PARAM,
    EVENT_RECV_SVR_PARAM,
    EVENT_GEN_LOCAL_PARAM,
    EVENT_SET_PARAM_TO_PEER,
    EVENT_RECV_SET_PARAM_RET,
    EVENT_COMPUTE_SESSIONKEY,
} sec_chl_init_fsm_event_id_t;

typedef cc_enclave_result_t (*sec_chl_init_fsm_action_t)(cc_sec_chl_ctx_t *ctx);

typedef struct {
    sec_chl_init_fsm_action_t action;
} sec_chl_fsm_state_transform_t;

static cc_enclave_result_t sec_chl_send_request(cc_conn_kit_t *conn_kit, sec_chl_msg_t *req_msg)
{
    int ret;
    size_t req_msg_len = sizeof(sec_chl_msg_t) + req_msg->data_len;

    // send request to server
    ret = conn_kit->send(conn_kit->conn, (uint8_t *)req_msg, req_msg_len);
    if (ret < 0) {
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
    if (ctx->handle->b64_enc_key != NULL) {
        free(ctx->handle->b64_enc_key);
    }
    if (ctx->handle->rsa_svr_pubkey != NULL) {
        RSA_free(ctx->handle->rsa_svr_pubkey);
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

    size_t need_len = get_encrypted_buf_len(plain_len);
    if (encrypt == NULL || *encrypt_len < need_len) {
        *encrypt_len = need_len;
        return CC_ERROR_SEC_CHL_LEN_NOT_ENOUGH;
    }

    return sec_chl_encrypt(ctx->handle->ecdh_ctx, ctx->session_id, plain, plain_len, encrypt, encrypt_len);
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
    size_t need_len = get_plain_buf_len((uint8_t *)encrypt, encrypt_len);
    if (need_len == 0) {
        return CC_ERROR_SEC_CHL_ENCRYPTED_LEN_INVALID;
    }
    if (plain == NULL || *plain_len < need_len) {
        *plain_len = need_len;
        return CC_ERROR_SEC_CHL_LEN_NOT_ENOUGH;
    }

    return sec_chl_decrypt(ctx->handle->ecdh_ctx, ctx->session_id, encrypt, encrypt_len, plain, plain_len);
}

static cc_enclave_result_t sec_chl_destroy_svr(cc_sec_chl_ctx_t *ctx)
{
    sec_chl_msg_t msg = {0};
    msg.msg_type = SEC_CHL_MSG_DESTROY;
    msg.session_id = ctx->session_id;
    cc_enclave_result_t ret = sec_chl_send_request(&(ctx->conn_kit), &msg);
    if (ret != CC_SUCCESS) {
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
    if (ctx == NULL || ctx->handle == NULL || buf == NULL || len == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (len > SEC_CHL_RECV_BUF_MAX_LEN) {
        return CC_ERROR_SEC_CHL_RECV_MSG_LEN_INVALID;
    }
    pthread_mutex_lock(&ctx->handle->lock);
    memset(ctx->handle->recv_buf, 0, sizeof(ctx->handle->recv_buf));
    memcpy(ctx->handle->recv_buf, buf, len);
    ctx->handle->recv_buf_len = len;
    pthread_mutex_unlock(&ctx->handle->lock);

    return CC_SUCCESS;
}

static cc_enclave_result_t get_taid_from_file(char *file, char *taid)
{
    FILE *fp = fopen(file, "r");
    if (!fp) {
        printf("secure channel init read taid failed\n");
        return CC_ERROR_SEC_CHL_INIT_GET_TAID;
    }

    int ret = fscanf(fp, "%s", taid);    // only read taid from line
    fclose(fp);
    if (ret < 0) {
        printf("secure channel init read taid and hash from file failed\n");
        return CC_ERROR_SEC_CHL_INIT_GET_TAID;
    }

    return CC_SUCCESS;
}

static cc_enclave_result_t request_report(cc_sec_chl_ctx_t *ctx, sec_chl_msg_type_t type, bool with_request_key)
{
    cc_enclave_result_t ret;
    sec_chl_msg_t *msg = NULL;
    size_t data_len = 0;

    if (ctx->basevalue != NULL) {
        data_len = sizeof(sec_chl_ra_req_t);
    }

    msg = (sec_chl_msg_t *)calloc(1, sizeof(sec_chl_msg_t) + data_len);
    if (msg == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }
    msg->msg_type = type;

    if (ctx->basevalue != NULL) {
        sec_chl_ra_req_t *ra_req = (sec_chl_ra_req_t *)msg->data;
        ra_req->with_tcb = false;
        ra_req->req_key = with_request_key;

        ret = get_taid_from_file(ctx->basevalue, ra_req->taid);
        if (ret != CC_SUCCESS) {
            free(msg);
            return ret;
        }
        if (RAND_priv_bytes(ra_req->nonce, SEC_CHL_REQ_NONCE_LEN) <= 0) {
            free(msg);
            return CC_FAIL;
        }
        memcpy(&ctx->handle->ra_req, ra_req, sizeof(sec_chl_ra_req_t));
    }

    msg->data_len = data_len;
    ret = sec_chl_send_request(&(ctx->conn_kit), msg);
    free(msg);
    if (ret != CC_SUCCESS) {
        return CC_ERROR_SEC_CHL_GET_SVR_PUBKEY;
    }

    return CC_SUCCESS;
}

static cc_enclave_result_t get_svr_pubkey(cc_sec_chl_ctx_t *ctx)
{
    return request_report(ctx, SEC_CHL_MSG_GET_SVR_PUBKEY, true);
}

static cc_enclave_result_t get_svr_key_from_report(cc_sec_chl_ctx_t *ctx, cc_ra_buf_t *report)
{
    cc_enclave_result_t ret = CC_ERROR_SEC_CHL_INVALID_REPORT;
    uint8_t *n = NULL;
    uint8_t *e = NULL;

    cJSON *cj_report = cJSON_ParseWithLength((char *)report->buf, report->len);
    if (cj_report == NULL) {
        printf("report to json failed\n");
        return CC_ERROR_SEC_CHL_INVALID_REPORT;
    }
    cJSON *cj_payload = cJSON_GetObjectItemCaseSensitive(cj_report, "payload");
    if (cj_payload == NULL) {
        printf("report payload failed!\n");
        goto end;
    }
    cJSON *cj_key = cJSON_GetObjectItemCaseSensitive(cj_payload, "key");
    if (cj_key == NULL) {
        printf("report key failed!\n");
        goto end;
    }
    // comput pubkey
    cJSON *cj_pub_key = cJSON_GetObjectItemCaseSensitive(cj_key, "pub_key");
    if (cj_pub_key == NULL) {
        printf("report pub_key failed!\n");
        goto end;
    }
    char *b64_n = cJSON_GetStringValue(cJSON_GetObjectItem(cj_pub_key, "n"));
    if (b64_n == NULL) {
        printf("parse n from json pub_key failed\n");
        goto end;
    }
    size_t n_len = 0;
    n = kpsecl_base64urldecode(b64_n, strlen(b64_n), &n_len);
    char *b64_e = cJSON_GetStringValue(cJSON_GetObjectItem(cj_pub_key, "e"));
    if (b64_e == NULL) {
        printf("parse e from json pub_key failed\n");
        goto end;
    }
    size_t e_len = 0;
    e = kpsecl_base64urldecode(b64_e, strlen(b64_e), &e_len);

    RSA *svr_pub_key = RSA_new();
    BIGNUM *modulus = BN_new();
    BIGNUM *pub_exponent = BN_new();
    BN_hex2bn(&modulus, (char *)n);
    BN_hex2bn(&pub_exponent, (char *)e);
    RSA_set0_key(svr_pub_key, modulus, pub_exponent, NULL);
    // svr pub key
    ctx->handle->rsa_svr_pubkey = svr_pub_key;

    // save enc key to ctx
    cJSON *cj_enc_key = cJSON_GetObjectItemCaseSensitive(cj_key, "enc_key");
    if(cj_enc_key == NULL) {
        printf("report enc_key failed!\n");
        goto fail;
    }
    ctx->handle->b64_enc_key = calloc(1, strlen(cj_enc_key->valuestring) + 1);
    if (ctx->handle->b64_enc_key == NULL) {
        printf("malloc enc key buff failed\n");
        ret = CC_ERROR_SEC_CHL_MEMORY;
        goto fail;
    }
    (void)memcpy(ctx->handle->b64_enc_key, cj_enc_key->valuestring, strlen(cj_enc_key->valuestring));

    ret = CC_SUCCESS;
    goto end;

fail:
    if (svr_pub_key != NULL) {
        RSA_free(svr_pub_key);
    }
end:
    if (n != NULL) {
        free(n);
    }
    if (e != NULL) {
        free(e);
    }
    cJSON_Delete(cj_report);

    return ret;
}

RSA *get_rsakey_from_buffer(const uint8_t *rsa_key_buffer, size_t rsa_key_buffer_len, bool is_private_key)
{
    BIO *r_key = NULL;
    RSA *rsa_key = NULL;
    r_key = BIO_new_mem_buf(rsa_key_buffer, rsa_key_buffer_len);
    if (r_key == NULL) {
        goto end;
    }
    if (is_private_key) {
        rsa_key = PEM_read_bio_RSAPrivateKey(r_key, NULL, NULL, NULL);
    } else {
        rsa_key = PEM_read_bio_RSAPublicKey(r_key, NULL, NULL, NULL);
    }

    if (rsa_key == NULL) {
        goto end;
    }

end:
    BIO_free(r_key);
    r_key = NULL;
    return rsa_key;
}

static cc_enclave_result_t parse_svrpubkey_from_recv_msg(cc_sec_chl_ctx_t *ctx, sec_chl_msg_t *msg)
{
    cc_enclave_result_t ret;
    if (msg->sub_type == GET_SVRPUBKEY_SUBTYPE_REPORT) {
        cc_ra_buf_t report = {0};
        report.buf = msg->data;
        report.len = msg->data_len;
        cc_ra_buf_t nonce = {0};
        nonce.len = SEC_CHL_REQ_NONCE_LEN;
        nonce.buf = ctx->handle->ra_req.nonce;

        ret = cc_verify_report(&report, &nonce, CC_RA_VERIFY_TYPE_STRICT, ctx->basevalue);
        if (ret != CC_SUCCESS) {
            printf("verify report failed ret:%u\n", ret);
            return CC_ERROR_SEC_CHL_INIT_VERIFY_REPORT;
        }

        ret = get_svr_key_from_report(ctx, &report);
        if (ret != CC_SUCCESS) {
            return ret;
        }
    } else {
        RSA *rsa_pubkey = get_rsakey_from_buffer(msg->data, msg->data_len, false);
        if (rsa_pubkey == NULL) {
            return CC_ERROR_SEC_CHL_PARSE_SVR_PUBKEY;
        }
        ctx->handle->rsa_svr_pubkey = rsa_pubkey;
        ret = CC_SUCCESS;
    }

    return ret;
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
    cc_enclave_result_t ret = parse_svrpubkey_from_recv_msg(ctx, msg);
    if (ret != CC_SUCCESS) {
        pthread_mutex_unlock(&ctx->handle->lock);
        return ret;
    }

    ctx->session_id = msg->session_id;
    ctx->handle->recv_buf_len = 0;
    pthread_mutex_unlock(&ctx->handle->lock);

    return CC_SUCCESS;
}

static cc_enclave_result_t set_encrypt_key_to_server_ta(cc_sec_chl_ctx_t *ctx)
{
    int ret;
    sec_chl_msg_t *msg = NULL;

    if (ctx->handle->b64_enc_key == NULL) {
        return CC_SUCCESS;
    }

    char *b64_enc_key = ctx->handle->b64_enc_key;
    size_t len = sizeof(sec_chl_msg_t) + strlen(b64_enc_key);

    msg = (sec_chl_msg_t *)calloc(1, len);
    if (msg == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }

    memcpy(msg->data, b64_enc_key, strlen(b64_enc_key));
    msg->data_len = strlen(b64_enc_key);

    msg->session_id = ctx->session_id;
    msg->msg_type = SEC_CHL_MSG_SET_ENC_KEY_TO_SVR;

    ret = sec_chl_send_request(&ctx->conn_kit, msg);
    free(msg);
    if (ret != CC_SUCCESS) {
        ret = CC_ERROR_SEC_CHL_SET_PARAM_TO_PEER;
    }
    return ret;
}

static cc_enclave_result_t recv_set_enc_key_ret(cc_sec_chl_ctx_t *ctx)
{
    sec_chl_msg_t *msg = NULL;
    cc_enclave_result_t ret;
    
    if (ctx->handle->b64_enc_key == NULL) {
        return CC_SUCCESS;
    }

    pthread_mutex_lock(&ctx->handle->lock);
    if (ctx->handle->recv_buf_len == 0) {
        pthread_mutex_unlock(&ctx->handle->lock);
        return CC_ERROR_SEC_CHL_WAITING_RECV_MSG;
    }
    msg = (sec_chl_msg_t *)ctx->handle->recv_buf;
    ret = msg->ret;
    ctx->handle->recv_buf_len = 0;
    pthread_mutex_unlock(&ctx->handle->lock);

    return ret;
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

    ret = verify_signature(ctx->handle->rsa_svr_pubkey, msg->data, msg->data_len);
    if (ret != CC_SUCCESS) {
        pthread_mutex_unlock(&ctx->handle->lock);
        return ret;
    }

    sec_chl_ecdh_ctx_t *ecdh_ctx = new_local_ecdh_ctx(ec_nid);
    if (ecdh_ctx == NULL) {
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
    ctx->handle->recv_buf_len = 0;

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
    ctx->handle->recv_buf_len = 0;
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
        del_exch_param(svr_exch_param_buf);
        del_exch_param(local_exch_param);
        return ret;
    }

    del_exch_param(svr_exch_param_buf);
    del_exch_param(local_exch_param);
    return CC_SUCCESS;
}

static sec_chl_fsm_state_transform_t g_state_transform_table[] = {
    {get_svr_pubkey},
    {recv_svr_pubkey},
    {set_encrypt_key_to_server_ta},
    {recv_set_enc_key_ret},
    {get_svr_param},
    {recv_svr_param},
    {gen_local_param},
    {set_local_param_to_peer},
    {recv_set_param_ret},
    {sec_chl_compute_session_key},
};

#define RECV_MSG_TIMEOUT_CNT 1000
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
        cc_sec_chl_client_fini(ctx);
    }

    return ret;
}
