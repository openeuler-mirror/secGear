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

#ifndef __SHARED_MEMORY_DEFS_H__
#define __SHARED_MEMORY_DEFS_H__

#include <stdint.h>
#include <tee_client_type.h>
#include "secgear_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t retval_size;
    size_t shared_buf_size;
    size_t shared_buf_len_size;
    size_t is_control_buf_size;
} gp_register_shared_memory_size_t;

typedef struct {
    size_t retval_size;
    size_t shared_buf_size;
} gp_unregister_shared_memory_size_t;

enum {
    fid_register_shared_memory = 0;
    fid_unregister_shared_memory = 1;
}

typedef struct {
    TEEC_SharedMemory_shared_mem;
    bool is_control_buf;
    bool is_registed;
    void *enclave; // refer to cc_enclave_t
    pthread_t register_tid;
    list_node_t node;
} gp_shared_memory_t;

#define GP_SHARED_MEMORY_ENTRY(ptr) \
    ((gp_shared_memory_t *)((char *)ptr - sizeof(gp_shared_memory_t)))

#define TEEC_SHARED_MEMORY_ENTRY(ptr) \
    (TEEC_SharedMemory *)((char *)ptr - sizeof(gp_shared_memory_t)))

#ifdef __cplusplus
}
#endif

#endif