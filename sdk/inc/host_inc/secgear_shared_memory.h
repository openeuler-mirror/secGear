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

#ifndef __SECGEAR_SHARED_MEMORY_H__
#define __SECGEAR_SHARED_MEMORY_H__

#include <stdint.h>
#include "status.h"
#include "enclave.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Summary: Allocate size bytes and returns a pointer to the allocated memory.
 * Parameters:
 *      enclave: enclave
 *      size: buffer length
 * Return: A pointer to the allocated memory On error, return NULL.
 */
CC_API_SPEC void *cc_malloc_shared_memory(cc_enclave_t *enclave, size_t size);

/*
 * Summary: Frees the memory space pointed to by ptr, which must have been returned by cc_malloc_shared_memory.
 * Parameters:
 *     enclave: enclave
 *     ptr: buffer address
 * Return: CC_SUCCESS, success; others failed.
 */
CC_API_SPEC cc_enclave_result_t cc_free_shared_memory(cc_enclave_t *enclave, void *ptr);


#ifdef __cplusplus
}
#endif

#endif
