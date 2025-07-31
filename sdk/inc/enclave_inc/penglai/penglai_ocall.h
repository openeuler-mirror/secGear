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

#ifndef PENGLAI_OCALL_H
#define PENGLAI_OCALL_H

#include <stdio.h>
#include <string.h>
#include "status.h"
#include "enclave.h"

#define OCALL_USER_DEFINED	4

/* New struct used to hint the in | out buf size. */
typedef struct _untrusted_mem_info_t
{
    uint8_t fid;
    size_t in_buf_size;
    size_t out_buf_size;
} untrusted_mem_info_t;

cc_enclave_result_t cc_ocall_enclave(
        size_t func_id,
        const void *in_buf,
        size_t in_buf_size,
        void *out_buf,
        size_t out_buf_size);
#endif
