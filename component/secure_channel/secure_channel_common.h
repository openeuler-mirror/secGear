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

#ifndef SECURE_CHANNEL_COMMON_H
#define SECURE_CHANNEL_COMMON_H
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>

#include "status.h"

#define SECURE_CHANNEL_ERROR (-1)

#define SECURE_KEY_LEN 32
#define SECURE_IV_LEN 16
typedef struct sec_chl_ecdh_ctx {
    RSA     *svr_rsa_key;      // svr use private key sign exch msg; client use pubkey verify exch msg signature
    size_t  signature_len;      // RSA_size(svr_rsa_key);
    int     ec_nid;             // Elliptic Curve nid
    EC_KEY  *ecdh_key;          // generate from ec_nid; include ecdh pubkey and privatekey
    size_t  ecdh_pubkey_len;    // calculate from ecdh_key
    size_t  shared_key_len;
    uint8_t *shared_key;        // ecdh output shared secret
    uint8_t session_key[SECURE_KEY_LEN];  // derived from shared key, used to encrypt/decrypt user data
    size_t  local_exch_param_buf_len;
    uint8_t *local_exch_param_buf;
    size_t  svr_exch_param_buf_len;
    uint8_t *svr_exch_param_buf;
} sec_chl_ecdh_ctx_t;

#define DATA_SIZE_LEN 2
#define GCM_TAG_LEN 16
#define BYTE_TO_BIT_LEN 8

typedef enum {
    SEC_CHL_MSG_GET_SVR_PUBKEY = 1,
    SEC_CHL_MSG_GET_SVR_PUBKEY_RSP,
    SEC_CHL_MSG_GET_RA_REPORT,
    SEC_CHL_MSG_GET_RA_REPORT_RSP,
    SEC_CHL_MSG_SET_ENC_KEY_TO_SVR,
    SEC_CHL_MSG_GET_SVR_EXCH_PARAM,
    SEC_CHL_MSG_GET_SVR_EXCH_PARAM_RSP,
    SEC_CHL_MSG_GEN_LOCAL_EXCH_PARAM,
    SEC_CHL_MSG_SEND_CLI_EXCH_PARAM,
    SEC_CHL_MSG_SEND_CLI_EXCH_PARAM_RSP,
    SEC_CHL_MSG_DESTROY,
    SEC_CHL_MSG_DESTROY_RSP,
    SEC_CHL_MSG_MAX,
} sec_chl_msg_type_t;

#define REPORT_OUT_LEN 0x3000
typedef enum {
    GET_SVRPUBKEY_SUBTYPE_SVR_GEN,
    GET_SVRPUBKEY_SUBTYPE_REPORT,
} sec_chl_get_svrpubkey_subtype_t;

#define CC_TAID_LEN 36
#define SEC_CHL_REQ_NONCE_LEN 32
typedef struct {
    char taid[CC_TAID_LEN + 1];
    uint8_t nonce[SEC_CHL_REQ_NONCE_LEN + 1];
    bool with_tcb;
    bool req_key;
} sec_chl_ra_req_t;

#define RSP_BUF_LEN 640
typedef struct sec_chl_msg {
    sec_chl_msg_type_t msg_type;
    sec_chl_get_svrpubkey_subtype_t sub_type;
    size_t session_id;
    int32_t ret;
    size_t data_len;
    uint8_t data[];
} sec_chl_msg_t;

#define RANDOM_LEN 32
typedef struct {
    uint8_t random[RANDOM_LEN];
    int ec_nid;
    size_t ecdh_pubkey_len;
    uint8_t *ecdh_pubkey;
    size_t signature_len;
    // uint8_t *signature;
} sec_chl_exch_param_t;

size_t buf_to_num(uint8_t *buf, size_t len);
void num_to_buf(size_t num, uint8_t *buf, size_t len);

sec_chl_ecdh_ctx_t *new_local_ecdh_ctx(int ec_nid);
void del_ecdh_ctx(sec_chl_ecdh_ctx_t *ecdh_ctx);
cc_enclave_result_t compute_session_key(sec_chl_ecdh_ctx_t *ecdh_ctx, sec_chl_exch_param_t *local_exch_param,
    sec_chl_exch_param_t *peer_exch_param);
cc_enclave_result_t get_exch_param_from_buf(uint8_t *exch_buf, size_t buf_len, sec_chl_exch_param_t **exch_param);
cc_enclave_result_t verify_signature(RSA *rsa_pubkey, uint8_t *exch_buf, size_t buf_len);
int get_exch_buf_len(sec_chl_ecdh_ctx_t *ecdh_ctx);
int get_exch_buf(sec_chl_ecdh_ctx_t *ecdh_ctx, uint8_t *exch_param, size_t exch_param_len);
void del_exch_param(sec_chl_exch_param_t *exch_param);
int sec_chl_encrypt(sec_chl_ecdh_ctx_t *ecdh_ctx, size_t session_id, uint8_t *plain, size_t plain_len,
    uint8_t *out_buf, size_t *out_buf_len);
int sec_chl_decrypt(sec_chl_ecdh_ctx_t *ecdh_ctx, size_t session_id, uint8_t *recv_buf, int recv_buf_len,
    uint8_t *out_buf, size_t *out_buf_len);

int gen_local_exch_buf(sec_chl_ecdh_ctx_t *ecdh_ctx);

size_t get_encrypted_buf_len(size_t plain_len);
size_t get_plain_buf_len(uint8_t *encrypt, size_t encrypt_len);

#endif
