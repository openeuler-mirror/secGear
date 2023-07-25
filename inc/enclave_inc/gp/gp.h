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

#ifndef GP_H
#define GP_H

#include <tee_ext_api.h>
#include <tee_log.h>
#include <secgear_log.h>
#include <enclave.h>


#define CC_BUFFER_ALIGNMENT  (2 * sizeof(void*))
#define TA_TEMPLATE_VERSION "SECGEAR_001"
#define OE_UINT32_MAX (0xffffffffu)
#define COUNT(ARR) (sizeof(ARR) / sizeof((ARR)[0]))
enum
{
    SECGEAR_ECALL_FUNCTION = 0,
};

typedef cc_enclave_result_t (*cc_ecall_func_t)(
    const uint8_t *input_buffer,
    size_t input_buffer_size,
    uint8_t *output_buffer,
    size_t  output_buffer_size,
    size_t *output_bytes_written);

typedef struct _ecall_table
{
    const cc_ecall_func_t *ecalls;
    size_t num;
} enclave_table_t;


//extern const enclave_table_t ecalls_table[];
//extern const size_t ecalls_table_size;
bool cc_is_within_enclave(const void *ptr, size_t sz);
#endif
