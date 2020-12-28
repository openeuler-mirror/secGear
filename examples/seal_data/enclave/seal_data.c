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
#include "seal_data_t.h"
#include "status.h"
#include "secgear_dataseal.h"


uint8_t seal_data[] = "Data to encrypt";
uint8_t additional_text[] = "add mac text";

uint8_t *malloc_with_check(uint32_t size)
{
    if (size == 0) {
        return NULL;
    }
    uint8_t *ptr = malloc(size);
    return ptr;
}

int seal_data_test_func(char *buf, uint32_t buf_len)
{
    if (buf_len == 0 || buf == NULL) 
        return CC_ERROR_BAD_PARAMETERS;
    
    cc_enclave_result_t ret;
    uint32_t data_len = strlen((const char *)seal_data);
    uint32_t add_len = strlen((const char *)additional_text);
    /******** prepare to seal data *********/
    uint32_t sealed_data_len = cc_enclave_get_sealed_data_size(data_len, add_len);
    if (sealed_data_len == UINT32_MAX)
        return CC_ERROR_OUT_OF_MEMORY;
    
    cc_enclave_sealed_data_t *sealed_data = (cc_enclave_sealed_data_t *)malloc_with_check(sealed_data_len);
    if (sealed_data == NULL) 
        return CC_ERROR_OUT_OF_MEMORY;

    ret = cc_enclave_seal_data(seal_data, data_len, sealed_data, sealed_data_len, additional_text, add_len);
    if (ret != CC_SUCCESS) 
        goto error3;

    /******** prepare to unseal data ***********/
    uint32_t encrypt_add_len = cc_enclave_get_add_text_size(sealed_data);
    uint32_t encrypt_data_len = cc_enclave_get_encrypted_text_size(sealed_data);

    uint8_t *decrypted_seal_data = malloc_with_check(encrypt_data_len);
    if (decrypted_seal_data == NULL) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto error3;
    }
    uint8_t *demac_data = malloc_with_check(encrypt_add_len);
    if (demac_data == NULL) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto error2;
    }

    ret = cc_enclave_unseal_data(sealed_data,
        decrypted_seal_data, &encrypt_data_len, demac_data, &encrypt_add_len);
    if (ret != CC_SUCCESS) {
        goto error1;
    }
    if(strcmp((const char *)demac_data, (const char *)additional_text) != 0 || encrypt_data_len > buf_len) {
        ret = CC_ERROR_GENERIC;
        goto error1;
    }
    strncpy(buf, (const char *)decrypted_seal_data, encrypt_data_len);
error1:
    free(demac_data);
error2:
    free(decrypted_seal_data);
error3:
    free(sealed_data);

    return ret;
}
