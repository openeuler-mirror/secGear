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

#ifndef QINGTIAN_INPUT_H
#define QINGTIAN_INPUT_H

#include <enclave.h>

typedef cc_enclave_result_t (*cc_ecall_func_t)(
    const uint8_t *input_buffer,
    size_t input_buffer_size,
    uint8_t *output_buffer,
    size_t  output_buffer_size,
    size_t *output_bytes_written);

typedef struct _ecall_table {
    const cc_ecall_func_t *ecalls;
    size_t num;
} enclave_table_t;

cc_enclave_result_t handle_ecall_function(
    const uint8_t *input_buffer,
    size_t input_buffer_size,
    uint8_t **output_buffer,
    size_t *output_bytes_written);

#endif
