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
#include "secgear_dataseal.h"
#include "dataseal_internal.h"
#include "error_conversion.h"
/*
 * cc_enclave_get_sealed_data_size use to calculate the size of
 * sealed data by the input parameters
 *
 * param add_len 	[IN] additional text length
 * param seal_data_len	[IN] plain text length to be sealed
 *
 * retval UINT32_MAX	means function fails
 * retvel others	means function success
 */
uint32_t cc_enclave_get_sealed_data_size(const uint32_t add_len, const uint32_t seal_data_len)
{
    uint32_t data_body_len;
    uint32_t struct_len = sizeof(cc_enclave_sealed_data_t);
    data_body_len = get_sealed_data_size_ex(add_len, seal_data_len);
    if (UINT32_MAX <= data_body_len || UINT32_MAX - struct_len <= data_body_len) {
        return UINT32_MAX;
    }
    return (uint32_t)(struct_len + data_body_len);
}

/*
 * cc_enclave_get_encrypted_text_size used to get the size of
 * encrypted data from the sealed_data
 *
 * param sealed_data    [IN] the sealed data
 *
 * retval UINT32_MAX    means function fails
 * retvel others        means function success
 */
uint32_t cc_enclave_get_encrypted_text_size(const cc_enclave_sealed_data_t *sealed_data)
{
    if (sealed_data == NULL) {
        return UINT32_MAX;
    }
    return get_encrypted_text_size_ex(sealed_data->data_body);
}

/*
 * cc_enclave_get_add_text_size used to get the size of
 * additional text from the sealed_data
 *
 * param sealed_data    [IN] the sealed data
 *
 * retval UINT32_MAX    means function fails
 * retvel others        means function success
 */
uint32_t cc_enclave_get_add_text_size(const cc_enclave_sealed_data_t *sealed_data)
{
    if (sealed_data == NULL) {
        return UINT32_MAX;
    }
    return get_add_text_size_ex(sealed_data->data_body);
}

/*
 * cc_enclave_seal_data seal the plain text and storage to sealed_data
 * buffer with the additional text
 *
 * param seal_data	[IN] pointer to the plain text buffer
 * param seal_data_len	[IN] plain text length to be sealed
 * param sealed_data	[OUT] handler of the sealed data
 * param sealed_data_len	[IN] size of the sealed_data buffer
 * param additional_text	[IN] pointer to the additional text buffer
 * param additional_text_len	[IN] size of additional text buffer
 */
cc_enclave_result_t cc_enclave_seal_data(uint8_t *seal_data, uint32_t seal_data_len,
    cc_enclave_sealed_data_t *sealed_data, uint32_t sealed_data_len, uint8_t *additional_text,
    uint32_t additional_text_len)
{
    cc_enclave_result_t ret;
    uint32_t ret_ex;
    uint32_t real_sealed_data_len;
    /* check parameters */
    if (seal_data == NULL || seal_data_len == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (sealed_data == NULL || sealed_data_len == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (additional_text == NULL && additional_text_len != 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (sealed_data->data_body == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    real_sealed_data_len = cc_enclave_get_sealed_data_size(additional_text_len, seal_data_len);
    if (real_sealed_data_len > sealed_data_len) {
        return CC_ERROR_SHORT_BUFFER;
    }
    memset(sealed_data, 0, real_sealed_data_len);
    ret_ex = SEAL_DATA_FN(seal_data, seal_data_len, sealed_data->data_body,
        real_sealed_data_len - (uint32_t)sizeof(cc_enclave_sealed_data_t), additional_text, additional_text_len);
    ret = conversion_res_status(ret_ex);
    if (ret != CC_SUCCESS) {
        return ret;
    }
    sealed_data->data_body_len = real_sealed_data_len;

    return ret;
}


cc_enclave_result_t cc_enclave_unseal_data(cc_enclave_sealed_data_t *sealed_data, uint8_t *decrypted_data,
    uint32_t *decrypted_data_len, uint8_t *additional_text, uint32_t *additional_text_len)
{
    cc_enclave_result_t ret;
    if (sealed_data == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (decrypted_data == NULL || decrypted_data_len == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    uint32_t real_additional_text_len = cc_enclave_get_add_text_size(sealed_data);
    if ((real_additional_text_len > 0 && additional_text == NULL) || (additional_text_len == NULL)) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    uint32_t real_encrypted_data_len = cc_enclave_get_encrypted_text_size(sealed_data);
    if (*decrypted_data_len < real_encrypted_data_len) {
        return CC_ERROR_SHORT_BUFFER;
    }
    uint32_t real_add_text_len = cc_enclave_get_add_text_size(sealed_data);
    if (*additional_text_len < real_add_text_len) {
        return CC_ERROR_SHORT_BUFFER;
    }
    ret = UNSEAL_DATA_FN(sealed_data->data_body, decrypted_data, decrypted_data_len, additional_text,
        additional_text_len);
    if (ret != CC_SUCCESS) {
        return ret;
    }
    return ret;
}
