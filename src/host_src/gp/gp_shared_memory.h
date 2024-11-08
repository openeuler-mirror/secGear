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

#ifndef __GP_SHARED_MEMORY_H__
#define __GP_SHARED_MEMORY_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "enclave.h"
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Summary: Allocates size bytes and returns a pointer to the allocated memory.
 * Parameters:
 *     context: enclave
 *     size: buffer length
 *     is_control_buf: whether it is a control area buffer
 * Return: A pointer to the allocated memory. On error, return NULL.
 */
void *gp_malloc_shared_memory(cc_enclave_t *context, size_t size, bool is_control_buf, int try_cnt);

/*
 * Summary: Frees the memory space pointed to by ptr, which must have been returned by gp_malloc_shared_memory.
 * Parameters:
 *     context: enclave
 *     ptr: buffer address
 * Return: CC_SUCCESS, success; others failed.
 */
cc_enclave_result_t gp_free_shared_memory(cc_enclave_t *context, void *ptr);

/*
 * Summary: Register a pointer to enclave, which must have been returned by gp_malloc_shared_memory.
 * Parameters:
 *     enclave: enclave
 *     ptr: buffer address
 * Return: CC_SUCCESS, success; others failed.
 */
cc_enclave_result_t gp_register_shared_memory(cc_enclave_t *enclave, void *ptr);

/*
 * Summary: Unregister a pointer from enclave, which must have been returned by gp_malloc_shared_memory.
 * Parameters:
 *     enclave: enclave
 *     ptr: buffer address
 * Return: CC_SUCCESS, success; others failed.
 */
cc_enclave_result_t gp_unregister_shared_memory(cc_enclave_t *enclave, void *ptr);
cc_enclave_result_t gp_release_all_shared_memory(cc_enclave_t *enclave);
#ifdef __cplusplus
}
#endif
#endif
