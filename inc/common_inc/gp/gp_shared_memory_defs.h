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

#ifndef SHARED_MEMORY_DEFS_H
#define SHARED_MEMORY_DEFS_H

#include <stdint.h>
#include <pthread.h>
#include "secgear_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t retval_size; // Size of variable retval
    size_t shared_buf_size; // Size of variable shared_buf
    size_t shared_buf_len_size; // Size of variable shared_buf_len
    size_t is_control_buf_size; // Size of variable is_control_buf
} gp_register_shared_memory_size_t;

typedef struct {
    size_t retval_size; // Size of variable retval
    size_t shared_buf_size; // Size of variable shared_buf
} gp_unregister_shared_memory_size_t;

enum {
    fid_register_shared_memory = 0,
    fid_unregister_shared_memory = 1,
};

#define GP_SHARED_MEMORY_SIZE            64

typedef struct {
    char shared_mem[GP_SHARED_MEMORY_SIZE]; // refer to TEEC_SharedMemory
    bool is_control_buf; // whether it is a control area; otherwise, it is the data area used by the user
    bool is_registered; // the shared memory can be used only after being registered
    void *enclave; // refer to cc_enclave_t
    pthread_t register_tid;
    list_node_t node;
} gp_shared_memory_t;

#define GP_SHARED_MEMORY_ENTRY(ptr) \
    ((gp_shared_memory_t *)((char *)(ptr) - sizeof(gp_shared_memory_t)))

#ifdef __cplusplus
}
#endif

#endif
