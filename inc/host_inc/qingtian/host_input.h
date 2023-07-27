/*
 * Copyright (c) IPADS@SJTU 2021. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef QINGTIAN_OCALL_H
#define QINGTIAN_OCALL_H

#include <stdio.h>
#include <string.h>
#include "status.h"
#include "enclave.h"

#ifdef  __cplusplus
extern "C" {
#endif

void set_ocall_table(const void *table);

cc_enclave_result_t handle_ocall_function(
    const uint8_t *input_buffer,
    size_t input_buffer_size,
    uint8_t **output_buffer,
    size_t *output_bytes_written);

#ifdef  __cplusplus
}
#endif

#endif
