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

#ifndef SECURE_CHANNEL_ENCLAVE_H
#define SECURE_CHANNEL_ENCLAVE_H

#ifdef  __cplusplus
extern "C" {
#endif

/**
* This function will encrypt data by secure channel's shared key
*
* @param[in] session_id, The secure channel index
*
* @param[int] plain, The buf to be encrypt
*
* @param[in] plain_len, The number of bytes expect to encrypt
*
* @param[out] encrypt, The buf of encrypted. If NULL return error, and assign the needed length to encrypt_len
*
* @param[in/out] encrypt_len, The length of encrypted buffer. If encrypt_len is not enough, will return error,
* and assign the needed length to encrypt_len
*
* @retval On success, 0 is returned. On error, -1 is returned.
*/
int cc_sec_chl_enclave_encrypt(size_t session_id, void *plain, size_t plain_len, void *encrypt, size_t *encrypt_len);

/**
* This function will decrypt data by secure channel's shared key
*
* @param[in] session_id, The secure channel index
*
* @param[in] encrypt, The buf to be decrypt.
*
* @param[in] encrypt_len, The length of encrypted buffer.
*
* @param[int] plain, The buf to store decrypt data, If NULL return error, and assign the needed length to plain_len
*
* @param[in/out] plain_len, The length of plain buffer. If plain_len is not enough, will return error,
* and assign the needed length to plain_len
*
* @retval On success, 0 is returned. On error, -1 is returned.
*/
int cc_sec_chl_enclave_decrypt(size_t session_id, void *encrypt, size_t encrypt_len, void *plain, size_t *plain_len);

# ifdef  __cplusplus
}
# endif
#endif
