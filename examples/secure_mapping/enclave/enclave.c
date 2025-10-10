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

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "mapping_cache.h"
#include "secure_mapping_enclave.h"
#include "sm_demo_t.h"

/* Implementation of en/decryption */
static const unsigned char key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/* Implementation of secure mapping hooks */
int cipher2plain(uint32_t session_id, const char *cipher, size_t clen, unsigned char *plain, size_t *plen)
{
    if (cipher == NULL || clen == 0 || plain == NULL || plen == NULL) {
        return SM_ERR_INVALID_PARAMETER_VALUE;
    }

    int32_t dec_res = aes_decrypt((const unsigned char *)cipher, clen, plain);
    if (dec_res <= 0) {
        return SM_ERR_NO_KEY;
    }
    *plen = dec_res;
    return SM_ERR_NO_ERROR;
}

int plain2cipher(uint32_t session_id, const char *plain, size_t plen, unsigned char *cipher, size_t *clen)
{
    *clen = aes_encrypt((const unsigned char*)plain, plen, cipher);

    if (*clen <= 0) {
        return SM_ERR_NO_KEY;
    }
    cipher[*clen] = '\0';
    return SM_ERR_NO_ERROR;
}

int c2i_post_process(uint32_t session_id, const uint8_t *in_data, size_t in_size, uint64_t SM_id, uint64_t *id_res)
{
    return SM_ERR_NO_ERROR;
}

int i2c_pre_process(uint32_t session_id, uint64_t *plain_id, uint8_t *out_data, size_t *out_size)
{
    return SM_ERR_NO_ERROR;
}

/* Expression operator */
int tee_uint32_val_add(uint64_t fid1, uint64_t fid2, uint64_t *sum_fid)
{
    unsigned char plain1[128] = {0};
    int plain_len1 = 0;
    unsigned char plain2[128] = {0};
    int plain_len2 = 0;

    int ret = mapping_cache_get(&mapping_cache, fid1, (uint8_t *)plain1, (size_t *)&plain_len1);
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }

    ret = mapping_cache_get(&mapping_cache, fid2, (uint8_t *)plain2, (size_t *)&plain_len2);
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }

    uint32_t sum = *((uint32_t *)plain1) + *((uint32_t *)plain2);

    ret = mapping_cache_put(&mapping_cache, (uint8_t *)(&sum), sizeof(uint32_t), sum_fid);
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }

    return SM_ERR_NO_ERROR;
}
