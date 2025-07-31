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

/* *
 * The API about data seal
 */

#ifndef __SECGEAR_DATASEAL_API_H
#define __SECGEAR_DATASEAL_API_H
#include <stdio.h>
#include <stdint.h>
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _enclave_sealed_data_t {
    uint32_t data_body_len;
    uint8_t reserved[16];
    uint8_t data_body[];
} cc_enclave_sealed_data_t;

uint32_t cc_enclave_get_sealed_data_size(const uint32_t add_len, const uint32_t seal_data_len);
uint32_t cc_enclave_get_encrypted_text_size(const cc_enclave_sealed_data_t *sealed_data);
uint32_t cc_enclave_get_add_text_size(const cc_enclave_sealed_data_t *sealed_data);

cc_enclave_result_t cc_enclave_seal_data(uint8_t *seal_data, uint32_t seal_data_len,
    cc_enclave_sealed_data_t *sealed_data, uint32_t sealed_data_len, uint8_t *additional_text,
    uint32_t additional_text_len);

cc_enclave_result_t cc_enclave_unseal_data(cc_enclave_sealed_data_t *sealed_data, uint8_t *decrypted_data,
    uint32_t *decrypted_data_len, uint8_t *additional_text, uint32_t *additional_text_len);

#ifdef __cplusplus
}
#endif
#endif
