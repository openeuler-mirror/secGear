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

#include "penglai_ocall.h"
#include "penglai.h"
#include "ocall.h"
#include "print.h"

extern unsigned long EAPP_OCALL(unsigned long ocall_func_id, unsigned long ocall_buf_size);

cc_enclave_result_t cc_ocall_enclave(
    size_t func_id,
    const void *in_buf,
    size_t in_buf_size,
    void *out_buf,
    size_t out_buf_size)
{
    untrusted_mem_info_t mem_info;
    uint8_t* in_buf_ptr = (uint8_t*)DEFAULT_UNTRUSTED_PTR +
                    size_to_aligned_size(sizeof(untrusted_mem_info_t));
    uint8_t* out_buf_ptr = in_buf_ptr + in_buf_size;
    unsigned long ocall_buf_size = size_to_aligned_size(sizeof(untrusted_mem_info_t)) +
                    in_buf_size + out_buf_size;

    if(ocall_buf_size > DEFAULT_UNTRUSTED_SIZE){
        eapp_print("[ERROR]: the size of parameters is too \
            big to transfer through untrusted memory\n");
        return CC_FAIL;
    }

    mem_info.fid = func_id;
    mem_info.in_buf_size = in_buf_size;
    mem_info.out_buf_size = out_buf_size;

    memcpy((uint8_t*)DEFAULT_UNTRUSTED_PTR, &mem_info, sizeof(untrusted_mem_info_t));
    memcpy(in_buf_ptr, in_buf, in_buf_size);
    memcpy(out_buf_ptr, out_buf, out_buf_size);

    EAPP_OCALL(OCALL_USER_DEFINED, ocall_buf_size);

    memcpy(out_buf, out_buf_ptr, out_buf_size);

    return CC_SUCCESS;
}
