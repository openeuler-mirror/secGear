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

#include <string.h>
#include "tee_mem_mgmt_api.h"
#include "tee_crypto_api.h"
#include "dataseal_internal.h"
#include "tee_trusted_storage.h"
uint32_t get_sealed_data_size_ex(uint32_t seal_data_len, uint32_t aad_len)
{
    if (UINT32_MAX - aad_len <= seal_data_len) {
        return UINT32_MAX;
    }
    if (UINT32_MAX - (aad_len + seal_data_len) <= (uint32_t)sizeof(itrustee_seal_data_t)) {
        return UINT32_MAX;
    }
    return (uint32_t)(aad_len + seal_data_len + (uint32_t)sizeof(itrustee_seal_data_t));
}

uint32_t get_encrypted_text_size_ex(const void *sealed_data)
{
    const itrustee_seal_data_t *tmp_sealed_data = (const itrustee_seal_data_t *)sealed_data;
    if (tmp_sealed_data == NULL) {
        return UINT32_MAX;
    }
    return tmp_sealed_data->encrypted_data_len;
}

uint32_t get_add_text_size_ex(const void *sealed_data)
{
    const itrustee_seal_data_t *tmp_sealed_data = (const itrustee_seal_data_t *)sealed_data;
    if (tmp_sealed_data == NULL) {
        return UINT32_MAX;
    }
    return tmp_sealed_data->aad_len;
}


/* generate a TEE_ObjectHandle from a key buffer
 * @import_key  ------the pointer to key buffer
 * @keysize     ------the length of key buffer
 *  */
static TEE_ObjectHandle generate_obj(uint8_t *import_key, uint32_t keysize)
{
    TEE_Attribute pattrib;
    TEE_Result ret;
    TEE_ObjectHandle gen_key;

    if (!import_key)
        return NULL;

    ret = TEE_AllocateTransientObject(TEE_TYPE_AES, SEAL_MAX_OBJ_LEN, &gen_key);
    if (TEE_SUCCESS != ret) {
        SLogError("Failed to execute TEE_AllocateTransientObject:ret = %x", ret);
        return NULL;
    }
    TEE_InitRefAttribute(&pattrib, TEE_ATTR_SECRET_VALUE, import_key, keysize);

    ret = TEE_PopulateTransientObject(gen_key, &pattrib, 1);
    if (TEE_SUCCESS != ret) {
        SLogError("TEE_PopulateTransientObject failed, ret %x\n", ret);
        TEE_FreeTransientObject(gen_key);
        return NULL;
    }

    return gen_key;
}

/*
 * implement of seal_data under itrustee sdk
 *
 *
 *
 *  */
TEE_Result data_copy(itrustee_seal_data_t *sealed_data, uint8_t *salt, uint8_t *nonce,
                     uint8_t *mac_data, uint8_t mac_data_len)
{
    uint32_t encrypted_data_len;
    memcpy(sealed_data->salt, salt, SEAL_KEY_SALT_LEN);
    memcpy(sealed_data->nonce, nonce, SEAL_DATA_NONCE_LEN);
    encrypted_data_len = sealed_data->encrypted_data_len;
    if (mac_data != NULL && mac_data_len != 0) {
        memcpy(&(sealed_data->payload_data[encrypted_data_len]), mac_data, mac_data_len);
    }
    sealed_data->aad_len = mac_data_len;
    return TEE_SUCCESS;
}

TEE_Result itrustee_seal_data(uint8_t *seal_data, uint32_t seal_data_len, void *sealed_data, uint32_t sealed_data_len,
    uint8_t *mac_data, uint32_t mac_data_len)
{
    TEE_Result result;
    itrustee_seal_data_t *tmp_sealed_data = (itrustee_seal_data_t *)sealed_data;
    uint8_t *key_buf = NULL;
    uint8_t *salt = NULL;
    key_buf = (uint8_t *)TEE_Malloc(SEAL_KEY_LEN, 0);
    if (key_buf == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    salt = (uint8_t *)TEE_Malloc(SEAL_KEY_SALT_LEN, 0);
    if (salt == NULL) {
        result = TEE_ERROR_OUT_OF_MEMORY;
        goto error2;
    }
    TEE_GenerateRandom(salt, SEAL_KEY_SALT_LEN);
    result = TEE_EXT_DeriveTARootKey((const uint8_t *)salt, SEAL_KEY_SALT_LEN, key_buf, SEAL_KEY_LEN);
    if (result != TEE_SUCCESS) {
        SLogError("DeriveTARootKey failed");
        goto error1;
    }
    uint8_t *nonce = NULL;
    nonce = (uint8_t *)TEE_Malloc(SEAL_DATA_NONCE_LEN, 0);
    if (nonce == NULL) {
        result = TEE_ERROR_OUT_OF_MEMORY;
        goto error1;
    }
    TEE_GenerateRandom(nonce, SEAL_DATA_NONCE_LEN);

    tmp_sealed_data->encrypted_data_len = seal_data_len;
    tmp_sealed_data->tag_len = SEAL_DATA_TAG_LEN;
    result = aes_seal_unseal_data(key_buf, SEAL_KEY_LEN, nonce, SEAL_DATA_NONCE_LEN, 
                    TEE_MODE_ENCRYPT, seal_data, seal_data_len, 
                    (uint8_t *)&(tmp_sealed_data->payload_data), (uint32_t *)&(tmp_sealed_data->encrypted_data_len),
                    (uint8_t *)&(tmp_sealed_data->tag), (uint32_t *)&(tmp_sealed_data->tag_len));
    if (result != TEE_SUCCESS) {
        SLogError("aes_seal_unseal_data failed");
        goto error0;
    }

    result = data_copy(tmp_sealed_data, salt, nonce, mac_data, mac_data_len);

error0:
    explicit_bzero(nonce, SEAL_DATA_NONCE_LEN);
    TEE_Free(nonce);
error1:
    explicit_bzero(salt, SEAL_KEY_SALT_LEN);
    TEE_Free(salt);
error2:
    explicit_bzero(key_buf, SEAL_KEY_LEN);
    TEE_Free(key_buf);
    return result;
}

TEE_Result aes_seal_unseal_data(uint8_t *key_buf, uint32_t key_len, uint8_t *nonce, uint32_t nonce_len, uint32_t mode,
    uint8_t *src_data, uint32_t src_len, uint8_t *dest_data, uint32_t *dest_len, uint8_t *tag, uint32_t *tag_len)
{
    TEE_Result ret;
    TEE_ObjectHandle key_object;
    TEE_OperationHandle crypto_ops = NULL;
    key_object = generate_obj(key_buf, key_len);
    if (NULL == key_object) {
        SLogError("importKey failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = TEE_AllocateOperation(&crypto_ops, TEE_ALG_AES_GCM, mode, SEAL_MAX_OBJ_LEN);
    if (TEE_SUCCESS != ret) {
        SLogError("TEE_AllocateOperation, fail %x\n", ret);
        goto error;
    }

    ret = TEE_SetOperationKey(crypto_ops, key_object);
    if (TEE_SUCCESS != ret) {
        SLogError("TEE_SetOperationKey, fail %x\n", ret);
        goto error2;
    }
    ret = TEE_AEInit(crypto_ops, nonce, nonce_len, SEAL_DATA_TAG_BIT_LEN, 0, src_len);
    if (TEE_SUCCESS != ret) {
        SLogError("TEE_AEInit failed, ret %x\n", ret);
        goto error2;
    }

    size_t temp_dest_len = *dest_len;
    size_t temp_tag_len = *tag_len;
    if (TEE_MODE_ENCRYPT == mode) {
        ret = TEE_AEEncryptFinal(crypto_ops, src_data, src_len, dest_data, &temp_dest_len, tag, &temp_tag_len);
        if (TEE_SUCCESS != ret) {
            SLogError("TEE_AEEncryptFinal failed, ret %x\n", ret);
            *dest_len = 0;
            goto error2;
        }
    } else if (TEE_MODE_DECRYPT == mode) {
        ret = TEE_AEDecryptFinal(crypto_ops, src_data, src_len, dest_data, &temp_dest_len, tag, temp_tag_len);
        if (TEE_SUCCESS != ret) {
            SLogError("TEE_AEDecryptFinal failed, ret %x\n", ret);
            *dest_len = 0;
            goto error2;
        }
    } else {
        SLogError("invalid mode %d\n", mode);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }

error2:
    TEE_FreeOperation(crypto_ops);
error:
    TEE_FreeTransientObject(key_object);
    return ret;
}

TEE_Result itrustee_unseal_data(void *sealed_data, uint8_t *decrypted_data, uint32_t *decrypted_data_len,
    uint8_t *mac_data, uint32_t *mac_data_len)
{
    TEE_Result result;
    itrustee_seal_data_t *tmp_sealed_data = (itrustee_seal_data_t *)sealed_data;

    uint8_t *salt = (uint8_t *)&(tmp_sealed_data->salt);
    char *key_buf = NULL;
    uint32_t key_len = SEAL_KEY_LEN;
    key_buf = (char *)TEE_Malloc(key_len, 0);
    if (key_buf == NULL) {
        SLogError("malloc key_buf failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    result = TEE_EXT_DeriveTARootKey(salt, SEAL_KEY_SALT_LEN, key_buf, key_len);
    if (result != TEE_SUCCESS) {
        SLogError("DeriveTARootKey failed");
        goto done;
    }
    *decrypted_data_len = tmp_sealed_data->encrypted_data_len;
    *mac_data_len = tmp_sealed_data->aad_len;
    result = aes_seal_unseal_data(key_buf, key_len, (uint8_t *)&(tmp_sealed_data->nonce), SEAL_DATA_NONCE_LEN,
        TEE_MODE_DECRYPT, (uint8_t *)&(tmp_sealed_data->payload_data), tmp_sealed_data->encrypted_data_len,
        decrypted_data, decrypted_data_len, (uint8_t *)&(tmp_sealed_data->tag),
        (uint32_t *)&(tmp_sealed_data->tag_len));
    if (result != TEE_SUCCESS) {
        SLogError("AES unseal data failed\n");
        goto done;
    }

    uint32_t temp_mac_len = *mac_data_len;
    if (temp_mac_len < tmp_sealed_data->aad_len) {
        result = TEE_ERROR_WRITE_DATA;
        goto done;
    }
    if (mac_data != NULL) {
        uint32_t encrypted_data_len = tmp_sealed_data->encrypted_data_len;
        if (*mac_data_len  >= tmp_sealed_data->aad_len) {
            memcpy(mac_data, &(tmp_sealed_data->payload_data[encrypted_data_len]), tmp_sealed_data->aad_len);
        }
        *mac_data_len = tmp_sealed_data->aad_len;
    }

done:
    explicit_bzero(key_buf, SEAL_KEY_LEN);
    TEE_Free(key_buf);
    return result;
}
