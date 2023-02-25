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

#ifndef SECURE_CHANNEL_CLIENT_H
#define SECURE_CHANNEL_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "status.h"
#include "secure_channel.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*******************************************************************************
* secure channel is a confidential computing service of secGear.
* user can request service by integrate secure_channel_client.h and libs,
* call function to new a secure channel success, generate a shared key between client and server enclave
* then user can send private data security to server enclave,
* the client of secure channel will encrypt private data by shared key, only server enclave can decrypt.
*
* Note: secure channel just generate sessionkey between client and server enclave, and provide interface to send data
* excluding implement of network transmission connection, which expect register by user
*******************************************************************************/

typedef struct cc_sec_chl_handle cc_sec_chl_handle_t;

/* secure channel client context */
typedef struct cc_sec_chl_ctx {
    size_t session_id;              // unique value return by server
    cc_conn_kit_t conn_kit;         // network transmission connection kit need register by user
    cc_sec_chl_handle_t *handle;
} cc_sec_chl_ctx_t;

typedef enum {
    CC_SEC_CHL_ALGO_RSA_ECDH_AES_GCM,   // international Data Encryption Algorithm suite
    // some algos suite to implement below
    // CC_SEC_CHL_ALGO_SM2_ECDH_SM4,       // shang mi suite
    // CC_SEC_CHL_ALGO_RSA,                // RSA public private key
    // CC_SEC_CHL_ALGO_SM2,                // SM2 public private key
    CC_SEC_CHL_ALGO_MAX
} cc_sec_chl_algo_t;

/**
* secure channel init function
*
* @param[in] algo, The algorithm suite of secure channel
*
* @param[in/out] ctx, The pointer of secure channel context
*          input need init conn_kit;
*          output session_id and cc_sec_chl_handle_t
*
* @retval, On success, return 0. generate session_key between client and enclave.
*          On error, cc_enclave_result_t errorno is returned.
*/
cc_enclave_result_t cc_sec_chl_client_init(cc_sec_chl_algo_t algo, cc_sec_chl_ctx_t *ctx);

/**
* secure channel uninit function, destory secure channel resource
*
* @param[in] ctx, The pointer of secure channel context
*
* @retval, On success, return 0.
*          On error, cc_enclave_result_t errorno is returned.
*/
void cc_sec_chl_client_fini(cc_sec_chl_ctx_t *ctx);

/**
* client secure channel msg handle callback.
* @param[in] ctx, The cc_sec_chl_ctx_t instance
*
* @param[in] buf, client receive message buffer
* @param[in] buf_len, The length of receive buffer
*
* @retval On success, 0 is returned. On error, cc_enclave_result_t is returned.
*/
cc_enclave_result_t cc_sec_chl_client_callback(cc_sec_chl_ctx_t *ctx, void *buf, size_t len);

/**
* This function will encrypt data by secure channel's shared key
*
* @param[in] ctx, The secure channel connection context
*
* @param[int] plain, The buf to be encrypt
*
* @param[in] plain_len, The number of bytes expect to encrypt
*
* @param[out] encrypt, The buf of encrypted. If NULL return error, and assign the needed length to encrypt_len
*
* @param[in/out] encrypt_len, The pointer of encrypted buffer length. If encrypt_len is not enough, will return error,
* and assign the needed length to encrypt_len
*
* @retval On success, 0 is returned. On error, cc_enclave_result_t is returned.
*/
cc_enclave_result_t cc_sec_chl_client_encrypt(cc_sec_chl_ctx_t *ctx, void *plain, size_t plain_len,
    void *encrypt, size_t *encrypt_len);

/**
* This function will decrypt data by secure channel's shared key
*
* @param[in] ctx, The secure channel connection context
*
* @param[in] encrypt, The buf to be decrypt.
*
* @param[in] encrypt_len, The length of encrypted buffer.
*
* @param[int] plain, The buf to store decrypt data, If NULL return error, and assign the needed length to plain_len
*
* @param[in/out] plain_len, The pointer of plain buffer length. If plain_len is not enough, will return error,
* and assign the needed length to plain_len
*
* @retval On success, 0 is returned. On error, cc_enclave_result_t is returned.
*/
cc_enclave_result_t cc_sec_chl_client_decrypt(cc_sec_chl_ctx_t *ctx, void *encrypt, size_t encrypt_len,
    void *plain, size_t *plain_len);

# ifdef  __cplusplus
}
# endif
#endif
