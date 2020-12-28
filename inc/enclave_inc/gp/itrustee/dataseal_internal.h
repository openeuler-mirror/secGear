/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef _ITRUSTEE_SEAL_H_
#define _ITRUSTEE_SEAL_H_

#include <stdint.h>
#include <stdio.h>
#include "tee_ext_api.h"
#include "tee_log.h"

#define SEAL_DATA_FN(in, inl, out, outl, aad, aadl) itrustee_seal_data(in, inl, out, outl, aad, aadl)
#define UNSEAL_DATA_FN(in, out, outl, aad, aadl) itrustee_unseal_data(in, out, outl, aad, aadl)
#define GET_SEALED_DATA_SIZE(len1, len2) itrustee_sealed_data_size(len1, len2)


#define SEAL_KEY_LEN 32
#define SEAL_KEY_SALT_LEN 16
#define SEAL_DATA_IV_LEN 16
#define SEAL_DATA_TAG_LEN 16
#define SEAL_DATA_TAG_BIT_LEN SEAL_DATA_TAG_LEN*8
#define SEAL_DATA_NONCE_LEN 12
#define SEAL_MAX_OBJ_LEN 256


typedef struct _itrustee_seal_data {
    uint8_t nonce[SEAL_DATA_IV_LEN];
    uint8_t salt[SEAL_KEY_SALT_LEN];
    uint32_t aad_len;
    uint8_t tag[SEAL_DATA_TAG_LEN];
    uint32_t tag_len;
    uint32_t encrypted_data_len;
    uint8_t payload_data[];
} itrustee_seal_data_t;

uint32_t get_sealed_data_size_ex(const uint32_t seal_data_len, const uint32_t aad_len);
uint32_t get_encrypted_text_size_ex(const void *sealed_data);
uint32_t get_add_text_size_ex(const void *sealed_data);

TEE_Result itrustee_seal_data(uint8_t *seal_data, uint32_t seal_data_len, void *sealed_data, uint32_t sealed_data_len,
    uint8_t *mac_data, uint32_t mac_data_len);

TEE_Result itrustee_unseal_data(void *cc_enclave_sealed_data, uint8_t *decrypted_data, uint32_t *decrypted_data_size,
    uint8_t *mac_data, uint32_t *mac_data_len);

TEE_Result aes_seal_unseal_data(uint8_t *key_buf, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint32_t mode,
    uint8_t *src_data, uint32_t src_len, uint8_t *dest_data, uint32_t *dest_len, uint8_t *tag, uint32_t *tag_len);




#endif
