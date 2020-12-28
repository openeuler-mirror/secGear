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

#ifndef _SGX_SEAL_H_
#define _SGX_SEAL_H_
#include "sgx_tseal.h"
#include "sgx_utils.h"
#include "string.h"

#define SEAL_DATA_FN(in, inl, out, outl, aad, aadl) \
        internel_sgx_seal_data(in, inl, out, outl, aad, aadl)
#define UNSEAL_DATA_FN(in, out, outl, aad, aadl) \
        internel_sgx_unseal_data(in, out, outl, aad, aadl)

uint32_t get_sealed_data_size_ex(uint32_t seal_data_len, uint32_t aad_len);
uint32_t get_encrypted_text_size_ex(const void *sealed_data);
uint32_t get_add_text_size_ex(const void *sealed_data);       

sgx_status_t internel_sgx_seal_data(uint8_t *seal_data, uint32_t seal_data_len, void *sealed_data,
                                    uint32_t sealed_data_len, uint8_t *mac_data, uint32_t mac_data_len);
sgx_status_t internel_sgx_unseal_data(void *sealed_data, uint8_t *decrypted_data, uint32_t *decrypted_data_len,
                                      uint8_t *mac_data, uint32_t *mac_data_len);

#endif
