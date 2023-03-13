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

#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include "secure_channel_common.h"
#include "status.h"

typedef struct _aes_algorithm_param {
    uint8_t *plain;
    int plain_len;
    uint8_t *cipher;
    int cipher_len;
    uint8_t *aad;
    int aad_len;
    uint8_t *key;
    int key_len;
    uint8_t *iv;
    int iv_len;
    uint8_t *tag;
    int tag_len;
} aes_param_t;

size_t buf_to_num(uint8_t *buf, size_t len)
{
    size_t ret_val = 0;
    if (len > sizeof(size_t)) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        ret_val = (ret_val << BYTE_TO_BIT_LEN) + buf[i];
    }
    return ret_val;
}

void num_to_buf(size_t num, uint8_t *buf, size_t len)
{
    uint8_t *out = buf + len - 1;
    for (int i = len; i > 0; i--) {
        *out = num & 0xff;
        num = num >> BYTE_TO_BIT_LEN;
        out--;
    }
    return;
}

static RSA *get_rsakey_from_buffer(const uint8_t *rsa_key_buffer, size_t rsa_key_buffer_len, bool is_private_key)
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

int verify_rsa_signature(const uint8_t *rsa_pubkey, size_t rsa_pubkey_len, const uint8_t *signature, size_t sig_len,
    const uint8_t *buf, size_t buf_len)
{
    RSA *sign_rsa = NULL;
    EVP_PKEY *evp_sign_key = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret_val = CC_FAIL;

    sign_rsa = get_rsakey_from_buffer(rsa_pubkey, rsa_pubkey_len, 0);
    evp_sign_key = EVP_PKEY_new();
    if (evp_sign_key == NULL || !EVP_PKEY_set1_RSA(evp_sign_key, sign_rsa) || ((size_t)RSA_size(sign_rsa) != sig_len)) {
        goto end;
    }
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        goto end;
    }
    if (EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sha256(), NULL, evp_sign_key) <= 0) {
        goto end;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        goto end;
    }
    if (EVP_DigestVerify(md_ctx, signature, sig_len, buf, buf_len) <= 0) {
        goto end;
    }

    ret_val = CC_SUCCESS;
end:
    EVP_MD_CTX_free(md_ctx);
    md_ctx = NULL;
    pctx = NULL;
    EVP_PKEY_free(evp_sign_key);
    evp_sign_key = NULL;
    RSA_free(sign_rsa);
    sign_rsa = NULL;
    return ret_val;
}

static int drive_key_hkdf(uint8_t *secret, size_t secret_len, uint8_t *salt, size_t salt_len,
    uint8_t *label, size_t label_len, uint8_t *out, size_t out_len)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return CC_FAIL;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CC_FAIL;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CC_FAIL;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CC_FAIL;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CC_FAIL;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, label, label_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CC_FAIL;
    }
    if (EVP_PKEY_derive(pctx, out, &out_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return CC_FAIL;
    }
    EVP_PKEY_CTX_free(pctx);
    return CC_SUCCESS;
}

#define KEY_LEN_128 (128 / 8)
#define KEY_LEN_192 (192 / 8)
#define KEY_LEN_256 (256 / 8)
static const EVP_CIPHER *get_cipher(int key_len)
{
    const EVP_CIPHER *cipher = NULL;
    if (key_len == KEY_LEN_128) {
        cipher = EVP_aes_128_gcm();
    } else if (key_len == KEY_LEN_192) {
        cipher = EVP_aes_192_gcm();
    } else if (key_len == KEY_LEN_256) {
        cipher = EVP_aes_256_gcm();
    } else {
        cipher = NULL;
    }

    return cipher;
}

#define AES_BATCH_LEN 128
static int aes_gcm_encrypt(aes_param_t *aes_enc)
{
    int howmany;
    int len = 0;
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const int batch_len = AES_BATCH_LEN; // bytes
    int res = 0;

    cipher = get_cipher(aes_enc->key_len);
    if (cipher == NULL || aes_enc->tag == NULL || aes_enc->tag_len == 0) {
        return SECURE_CHANNEL_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return SECURE_CHANNEL_ERROR;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto enc_out;
    }
    // set aes_enc->key & aes_enc->iv
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, aes_enc->iv_len, NULL) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto enc_out;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aes_enc->key, aes_enc->iv) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto enc_out;
    }

    if (aes_enc->aad && aes_enc->aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &howmany, aes_enc->aad, aes_enc->aad_len) <= 0) {
            res = SECURE_CHANNEL_ERROR;
            goto enc_out;
        }
    }
    while (len <= aes_enc->plain_len - batch_len) {
        if (EVP_EncryptUpdate(ctx, aes_enc->cipher + len, &howmany, aes_enc->plain + len, batch_len) <= 0) {
            res = SECURE_CHANNEL_ERROR;
            goto enc_out;
        }
        len += batch_len;
        aes_enc->cipher_len += howmany;
    }
    if (EVP_EncryptUpdate(ctx, aes_enc->cipher + len, &howmany, aes_enc->plain + len, (aes_enc->plain_len - len)) <=
        0) {
        res = SECURE_CHANNEL_ERROR;
        goto enc_out;
    }
    aes_enc->cipher_len += howmany;

    if (EVP_EncryptFinal_ex(ctx, aes_enc->cipher + aes_enc->plain_len, &howmany) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto enc_out;
    }
    aes_enc->cipher_len += howmany;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, aes_enc->tag_len, aes_enc->tag) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto enc_out;
    }

    res = 0;
enc_out:
    EVP_CIPHER_CTX_free(ctx);
    if (res < 0) {
        return res;
    }
    return (int)aes_enc->cipher_len;
}

static int aes_gcm_decrypt(aes_param_t *aes_dec)
{
    int howmany;
    int len = 0;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx = NULL;
    const int batch_len = AES_BATCH_LEN; // bytes
    int res = 0;

    cipher = get_cipher(aes_dec->key_len);
    if (cipher == NULL || aes_dec->tag == NULL || aes_dec->tag_len == 0) {
        return SECURE_CHANNEL_ERROR;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return SECURE_CHANNEL_ERROR;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto dec_out;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, aes_dec->iv_len, NULL) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto dec_out;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, aes_dec->key, aes_dec->iv) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto dec_out;
    }

    if (aes_dec->aad != NULL && aes_dec->aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &howmany, aes_dec->aad, aes_dec->aad_len) <= 0) {
            res = SECURE_CHANNEL_ERROR;
            goto dec_out;
        }
    }
    while (len <= aes_dec->cipher_len - batch_len) {
        if (EVP_DecryptUpdate(ctx, aes_dec->plain + len, &howmany, aes_dec->cipher + len, batch_len) <= 0) {
            res = SECURE_CHANNEL_ERROR;
            goto dec_out;
        }
        len += batch_len;
        aes_dec->plain_len += howmany;
    }
    if (EVP_DecryptUpdate(ctx, aes_dec->plain + len, &howmany, aes_dec->cipher + len, (aes_dec->cipher_len - len)) <=
        0) {
        res = SECURE_CHANNEL_ERROR;
        goto dec_out;
    }
    aes_dec->plain_len += howmany;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, aes_dec->tag_len, aes_dec->tag) <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto dec_out;
    }
    res = EVP_DecryptFinal_ex(ctx, aes_dec->plain + aes_dec->cipher_len, &howmany);
    aes_dec->plain_len += howmany;

    if (res <= 0) {
        res = SECURE_CHANNEL_ERROR;
        goto dec_out;
    }

    res = 0;
dec_out:
    EVP_CIPHER_CTX_free(ctx);
    if (res < 0) {
        return res;
    }
    return aes_dec->plain_len;
}

typedef struct {
    size_t      session_id;
    size_t      data_len;
    uint8_t     iv[SECURE_IV_LEN];
    uint8_t     gcm_tag[GCM_TAG_LEN];
    uint8_t     data[0];          // encrypted data, len is data_len
} sec_chl_encrypt_data_t;

size_t get_encrypted_buf_len(size_t plain_len)
{
    return sizeof(sec_chl_encrypt_data_t) + plain_len;
}

size_t get_plain_buf_len(uint8_t *encrypt, size_t encrypt_len)
{
    sec_chl_encrypt_data_t tmp = {0};

    size_t expect_plain_len = encrypt_len - sizeof(sec_chl_encrypt_data_t);
    size_t real_plain_len = 0;
    memcpy(&real_plain_len, encrypt + sizeof(tmp.session_id), sizeof(tmp.data_len));
    if (real_plain_len != expect_plain_len) {
        return 0;
    }
    return real_plain_len;
}

int sec_chl_decrypt(sec_chl_ecdh_ctx_t *ecdh_ctx, size_t session_id, uint8_t *recv_buf, int recv_buf_len,
    uint8_t *out_buf, size_t *out_buf_len)
{
    int out_len;
    uint8_t iv[SECURE_IV_LEN];
    uint8_t *p_buf = recv_buf;
    uint8_t *aad = NULL;
    uint8_t *cipher = NULL;
    uint8_t *tag = NULL;
    int aad_len;
    size_t data_len;
    aes_param_t aes_dec;

    (void)recv_buf_len;
    aes_dec.key = ecdh_ctx->session_key;

    size_t real_session_id;
    memcpy(&real_session_id, p_buf, sizeof(real_session_id));
    p_buf += sizeof(real_session_id);

    if (session_id != real_session_id) {
        return CC_ERROR_SEC_CHL_DECRYPT_SESSIONID_INVALID;
    }

    memcpy(&data_len, p_buf, sizeof(data_len));
    p_buf += sizeof(data_len);

    memcpy(iv, p_buf, SECURE_IV_LEN);
    p_buf += SECURE_IV_LEN;

    aad = recv_buf; // session_id和data_len作为附加信息，使用tag保护附加信息的完整性
    aad_len = sizeof(session_id) + sizeof(data_len) + SECURE_IV_LEN;
    
    tag = p_buf;
    p_buf += GCM_TAG_LEN;

    cipher = p_buf;

    aes_dec.plain = out_buf;
    aes_dec.plain_len = 0;
    aes_dec.cipher = cipher;
    aes_dec.cipher_len = data_len;
    aes_dec.aad = aad;
    aes_dec.aad_len = aad_len;
    aes_dec.key_len = SECURE_KEY_LEN;
    aes_dec.iv = iv;
    aes_dec.iv_len = SECURE_IV_LEN;
    aes_dec.tag = tag;
    aes_dec.tag_len = GCM_TAG_LEN;
    out_len = aes_gcm_decrypt(&aes_dec);
    memset(&aes_dec, 0, sizeof(aes_param_t));
    if (out_len <= 0 || out_len != (int)data_len) {
        return CC_ERROR_SEC_CHL_DECRYPT;
    }
    *out_buf_len =  out_len;

    return CC_SUCCESS;
}

int sec_chl_encrypt(sec_chl_ecdh_ctx_t *ecdh_ctx, size_t session_id, uint8_t *plain, size_t plain_len,
    uint8_t *out_buf, size_t *out_buf_len)
{
    uint8_t *p_buf = out_buf;
    uint8_t *aad = NULL;
    uint8_t *iv = NULL;
    uint8_t *enc = NULL;
    uint8_t *tag = NULL;
    int aad_len;
    int enc_len;
    aes_param_t aes_enc;

    aes_enc.key = ecdh_ctx->session_key;

    memcpy(p_buf, &session_id, sizeof(session_id));
    p_buf += sizeof(session_id);
    
    memcpy(p_buf, &plain_len, sizeof(plain_len));
    p_buf += sizeof(plain_len);

    iv = p_buf;
    int ret = RAND_priv_bytes(iv, SECURE_IV_LEN);
    if (ret != 1) {
        return CC_ERROR_SEC_CHL_GEN_RANDOM;
    }
    p_buf += SECURE_IV_LEN;

    aad = out_buf; // session_id、data_len、iv作为附加信息，使用tag保护附加信息的完整性
    aad_len = sizeof(session_id) + sizeof(plain_len) + SECURE_IV_LEN;

    tag = p_buf;
    p_buf += GCM_TAG_LEN;

    enc = p_buf;

    aes_enc.plain = plain;
    aes_enc.plain_len = plain_len;
    aes_enc.cipher = enc;
    aes_enc.cipher_len = 0;
    aes_enc.aad = aad;
    aes_enc.aad_len = aad_len;
    aes_enc.key_len = SECURE_KEY_LEN;
    aes_enc.iv = iv;
    aes_enc.iv_len = SECURE_IV_LEN;
    aes_enc.tag = tag;
    aes_enc.tag_len = GCM_TAG_LEN;
    enc_len = aes_gcm_encrypt(&aes_enc);
    memset(&aes_enc, 0, sizeof(aes_param_t));
    if (enc_len <= 0 || enc_len != (int)plain_len) {
        return CC_ERROR_SEC_CHL_ENCRYPT;
    }

    *out_buf_len = get_encrypted_buf_len(enc_len);

    return CC_SUCCESS;
}

void del_ecdh_ctx(sec_chl_ecdh_ctx_t *ecdh_ctx)
{
    if (ecdh_ctx->svr_rsa_key != NULL) {
        RSA_free(ecdh_ctx->svr_rsa_key);
    }
    if (ecdh_ctx->ecdh_key != NULL) {
        EC_KEY_free(ecdh_ctx->ecdh_key);
    }
    if (ecdh_ctx->shared_key != NULL) {
        free(ecdh_ctx->shared_key);
    }
    if (ecdh_ctx->local_exch_param_buf != NULL) {
        free(ecdh_ctx->local_exch_param_buf);
    }
    if (ecdh_ctx->svr_exch_param_buf != NULL) {
        free(ecdh_ctx->svr_exch_param_buf);
    }
    free(ecdh_ctx);
    return;
}

#define ECC_POINT_COMPRESSED_MULTIPLY 2
#define MAX_ECC_PUBKEY_LEN 255
static int get_key_len(sec_chl_ecdh_ctx_t *ecdh_ctx)
{
    const EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;
    point_conversion_form_t form;
    size_t ecdh_pubkey_len = 0;
    EC_KEY *ecdh_key = ecdh_ctx->ecdh_key;

    point = EC_KEY_get0_public_key(ecdh_key);
    group = EC_KEY_get0_group(ecdh_key);
    if (point == NULL || group == NULL) {
        return -1;
    }
    form = EC_GROUP_get_point_conversion_form(group);
    ecdh_pubkey_len = EC_POINT_point2oct(group, point, form, NULL, 0, NULL);
    if (ecdh_pubkey_len == 0 || ecdh_pubkey_len > MAX_ECC_PUBKEY_LEN) {
        return -1;
    }
    ecdh_ctx->ecdh_pubkey_len = ecdh_pubkey_len;
    ecdh_ctx->shared_key_len = (form == POINT_CONVERSION_COMPRESSED) ?
        (ecdh_pubkey_len - 1) : ((ecdh_pubkey_len - 1) / ECC_POINT_COMPRESSED_MULTIPLY);
    return 0;
}

static size_t get_exch_param_signature(RSA *sign_key, uint8_t *sign_data, size_t data_len,
    uint8_t *signature, size_t signature_len)
{
    EVP_PKEY *evp_sign_key = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t sig_len = 0;

    evp_sign_key = EVP_PKEY_new();
    if (evp_sign_key == NULL || !EVP_PKEY_set1_RSA(evp_sign_key, sign_key)) {
        goto end;
    }
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        goto end;
    }
    if (EVP_DigestSignInit(md_ctx, &pctx, EVP_sha256(), NULL, evp_sign_key) <= 0) {
        goto end;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        goto end;
    }
    if (EVP_DigestSignUpdate(md_ctx, sign_data, data_len) <= 0) {
        goto end;
    }
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) {
        goto end;
    }
    if (sig_len > signature_len) {
        goto end;
    }
    if (EVP_DigestSignFinal(md_ctx, signature, &sig_len) <= 0) {
        goto end;
    }

end:
    EVP_MD_CTX_free(md_ctx);
    md_ctx = NULL;
    pctx = NULL;
    EVP_PKEY_free(evp_sign_key);
    evp_sign_key = NULL;
    return sig_len;
}

int get_exch_buf_len(sec_chl_ecdh_ctx_t *ecdh_ctx)
{
    return sizeof(sec_chl_exch_param_t) + ecdh_ctx->ecdh_pubkey_len + ecdh_ctx->signature_len;
}

static int get_ecdh_pubkey(sec_chl_ecdh_ctx_t *ecdh_ctx, uint8_t *ecdh_pubkey, size_t ecdh_pubkey_len)
{
    const EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;
    point_conversion_form_t form;
    EC_KEY *ecdh_key = ecdh_ctx->ecdh_key;

    if (ecdh_key == NULL) {
        return -1;
    }
    point = EC_KEY_get0_public_key(ecdh_key);
    group = EC_KEY_get0_group(ecdh_key);
    if (point == NULL || group == NULL) {
        return -1;
    }
    form = EC_GROUP_get_point_conversion_form(group);
    if (!EC_POINT_point2oct(group, point, form, ecdh_pubkey, ecdh_pubkey_len, NULL)) {
        return -1;
    }

    return 0;
}

int gen_local_exch_buf(sec_chl_ecdh_ctx_t *ecdh_ctx)
{
    int ret;
    uint8_t *ptr = NULL;
    size_t exch_buf_len = get_exch_buf_len(ecdh_ctx);
    ecdh_ctx->local_exch_param_buf = (uint8_t *)calloc(1, exch_buf_len);
    if (ecdh_ctx->local_exch_param_buf == NULL) {
        return CC_FAIL;
    }

    ptr = ecdh_ctx->local_exch_param_buf;
    // random
    uint8_t random[RANDOM_LEN];
    if (RAND_priv_bytes(random, RANDOM_LEN) <= 0) {
        return CC_FAIL;
    }
    memcpy(ptr, random, RANDOM_LEN);
    ptr += RANDOM_LEN;

    // ecc cure id
    memcpy(ptr, &(ecdh_ctx->ec_nid), sizeof(ecdh_ctx->ec_nid));
    ptr += sizeof(ecdh_ctx->ec_nid);

    // ecdh_pubkey_len
    memcpy(ptr, &(ecdh_ctx->ecdh_pubkey_len), sizeof(ecdh_ctx->ecdh_pubkey_len));
    ptr += sizeof(ecdh_ctx->ecdh_pubkey_len);

    // ecdh_pubkey
    ret = get_ecdh_pubkey(ecdh_ctx, ptr, ecdh_ctx->ecdh_pubkey_len);
    if (ret != CC_SUCCESS) {
        return CC_FAIL;
    }
    ptr += ecdh_ctx->ecdh_pubkey_len;
    
    // signature_len
    if (ecdh_ctx->signature_len > 0) {
        memcpy(ptr, &(ecdh_ctx->signature_len), sizeof(ecdh_ctx->signature_len));
        ptr += sizeof(ecdh_ctx->signature_len);

        // signature
        size_t sign_data_len = RANDOM_LEN + sizeof(ecdh_ctx->ec_nid) + 
            sizeof(ecdh_ctx->ecdh_pubkey_len) +ecdh_ctx->ecdh_pubkey_len;
        if (get_exch_param_signature(ecdh_ctx->svr_rsa_key, ecdh_ctx->local_exch_param_buf, sign_data_len,
            ptr, ecdh_ctx->signature_len) != ecdh_ctx->signature_len) {
                goto end;
        }
        ptr += ecdh_ctx->signature_len;
    }
    if ((size_t)(ptr - ecdh_ctx->local_exch_param_buf) > exch_buf_len) {
        goto end;
    }
    ecdh_ctx->local_exch_param_buf_len = exch_buf_len;

    return CC_SUCCESS;
end:
    free(ecdh_ctx->local_exch_param_buf);
    ecdh_ctx->local_exch_param_buf = NULL;
    return CC_FAIL;
}

int get_exch_buf(sec_chl_ecdh_ctx_t *ecdh_ctx, uint8_t *exch_param, size_t exch_param_len)
{
    if (exch_param_len < ecdh_ctx->local_exch_param_buf_len) {
        return CC_FAIL;
    }
    memcpy(exch_param, ecdh_ctx->local_exch_param_buf, ecdh_ctx->local_exch_param_buf_len);

    return CC_SUCCESS;
}

sec_chl_ecdh_ctx_t *new_local_ecdh_ctx(int ec_nid)
{
    EC_KEY *ecdh_key = NULL;
    sec_chl_ecdh_ctx_t *ecdh_ctx = NULL;
    int ret;

    ecdh_ctx = calloc(1, sizeof(sec_chl_ecdh_ctx_t));
    if (ecdh_ctx == NULL) {
        return ecdh_ctx;
    }

    ecdh_key = EC_KEY_new_by_curve_name(ec_nid);
    if (ecdh_key == NULL) {
        goto fail;
    }
    if (!EC_KEY_generate_key(ecdh_key)) {
        goto fail;
    }
    ecdh_ctx->ecdh_key = ecdh_key;
    ecdh_ctx->ec_nid = ec_nid;
    ret = get_key_len(ecdh_ctx);
    if (ret < 0) {
        goto fail;
    }
    ecdh_ctx->shared_key = (uint8_t *)calloc(1, ecdh_ctx->shared_key_len);
    if (ecdh_ctx->shared_key == NULL) {
        goto fail;
    }

    return ecdh_ctx;
fail:
    del_ecdh_ctx(ecdh_ctx);
    return NULL;
}

static cc_enclave_result_t drive_session_key(sec_chl_ecdh_ctx_t *ecdh_ctx, sec_chl_exch_param_t *local_exch_param,
    sec_chl_exch_param_t *peer_exch_param)
{
    uint8_t salt[RANDOM_LEN];
    uint8_t key_label[] = "sessionkey";

    for (int i = 0; i < RANDOM_LEN; i++) {
        salt[i] = local_exch_param->random[i] ^ peer_exch_param->random[i];
    }
    if (drive_key_hkdf(ecdh_ctx->shared_key, ecdh_ctx->shared_key_len, salt, sizeof(salt), key_label,
        strlen((char *)key_label), ecdh_ctx->session_key, SECURE_KEY_LEN) != CC_SUCCESS) {
        return CC_ERROR_DRIVE_SESSIONKEY;
    }
    return CC_SUCCESS;
}

cc_enclave_result_t compute_session_key(sec_chl_ecdh_ctx_t *ecdh_ctx, sec_chl_exch_param_t *local_exch_param,
    sec_chl_exch_param_t *peer_exch_param)
{
    const EC_GROUP *group = NULL;
    EC_KEY *ecdh_key = ecdh_ctx->ecdh_key;
    EC_POINT *peer_point = NULL;
    int ret = CC_FAIL;

    group = EC_KEY_get0_group(ecdh_key);
    peer_point = EC_POINT_new(group);;
    if (group == NULL || peer_point == NULL) {
        goto end;
    }
    if (!EC_POINT_oct2point(group, peer_point, peer_exch_param->ecdh_pubkey, peer_exch_param->ecdh_pubkey_len, NULL)) {
        goto end;
    }
    if (!ECDH_compute_key(ecdh_ctx->shared_key, ecdh_ctx->shared_key_len, peer_point, ecdh_key, NULL)) {
        goto end;
    }
    ret = drive_session_key(ecdh_ctx, local_exch_param, peer_exch_param);
    if (ret != CC_SUCCESS) {
        goto end;
    }

    ret = CC_SUCCESS;
end:
    EC_POINT_free(peer_point);
    peer_point = NULL;
    return ret;
}

cc_enclave_result_t get_exch_param_from_buf(uint8_t *exch_buf, size_t buf_len, sec_chl_exch_param_t **exch_param)
{
    sec_chl_exch_param_t *msg = (sec_chl_exch_param_t *)calloc(1, sizeof(sec_chl_exch_param_t));
    if (msg == NULL) {
        return CC_ERROR_SEC_CHL_MEMORY;
    }
    
    uint8_t *p_buf = exch_buf;

    memcpy(msg->random, p_buf, RANDOM_LEN);
    p_buf += RANDOM_LEN;

    memcpy(&msg->ec_nid, p_buf, sizeof(msg->ec_nid));
    p_buf += sizeof(msg->ec_nid);

    memcpy(&msg->ecdh_pubkey_len, p_buf, sizeof(msg->ecdh_pubkey_len));
    p_buf += sizeof(msg->ecdh_pubkey_len);

    if (p_buf - exch_buf + msg->ecdh_pubkey_len > buf_len) {
        del_exch_param(msg);
        return CC_ERROR_SEC_CHL_INVALID_EXCH_BUF;
    }

    msg->ecdh_pubkey = (uint8_t *)calloc(1, msg->ecdh_pubkey_len);
    if (msg->ecdh_pubkey == NULL) {
        del_exch_param(msg);
        return CC_ERROR_SEC_CHL_MEMORY;
    }
    memcpy(msg->ecdh_pubkey,p_buf, msg->ecdh_pubkey_len);

    *exch_param = msg;

    return CC_SUCCESS;
}

cc_enclave_result_t verify_signature(uint8_t *pubkey, size_t pubkey_len, uint8_t *exch_buf, size_t buf_len)
{
    size_t ecdh_pubkey_len;
    size_t signature_len;
    uint8_t *p_buf = exch_buf;

    p_buf += RANDOM_LEN;

    p_buf += sizeof(int); // ec_nid

    memcpy(&ecdh_pubkey_len, p_buf, sizeof(ecdh_pubkey_len));
    p_buf += sizeof(ecdh_pubkey_len);

    if (p_buf - exch_buf + ecdh_pubkey_len > buf_len) {
        return CC_ERROR_SEC_CHL_INVALID_EXCH_BUF;
    }

    p_buf += ecdh_pubkey_len;

    memcpy(&signature_len, p_buf, sizeof(signature_len));
    p_buf += sizeof(signature_len);

    if (signature_len == 0) {
        return CC_SUCCESS;
    }
    if (p_buf - exch_buf + signature_len > buf_len) {
        return CC_ERROR_SEC_CHL_INVALID_EXCH_BUF;
    }

    // verify signature
    size_t data_len = p_buf - exch_buf - sizeof(signature_len);
    int ret = verify_rsa_signature(pubkey, pubkey_len, p_buf, signature_len, exch_buf, data_len);
    if (ret != CC_SUCCESS) {
        return CC_ERROR_SEC_CHL_VERIFY_PEER_EXCH_BUF_SIGNATURE;
    }

    return CC_SUCCESS;
}

void del_exch_param(sec_chl_exch_param_t *exch_param)
{
    if (exch_param == NULL) {
        return;
    }
    free(exch_param->ecdh_pubkey);
    free(exch_param);
    return;
}
