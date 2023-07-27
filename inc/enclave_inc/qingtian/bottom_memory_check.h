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

#ifndef _QINGTIAN_MEMORY_CHECK_
#define _QINGTIAN_MEMORY_CHECK_

#include <stdbool.h>
#include <stddef.h>

#define MEMORY_CHECK_IN_FN(buffer, size) qingtian_memory_in_enclave(buffer, size)
#define MEMORY_CHECK_OUT_FN(buffer, size) qingtian_memory_out_enclave(buffer, size)

bool qingtian_memory_in_enclave(const void *buffer, size_t size);
bool qingtian_memory_out_enclave(const void *buffer, size_t size);


#endif
