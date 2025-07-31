/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef _ITRUSTEE_MEMORY_CHECK_
#define _ITRUSTEE_MEMORY_CHECK_
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#define MEMORY_CHECK_IN_FN(buffer, size) itrustee_memory_in_enclave(buffer, size)
#define MEMORY_CHECK_OUT_FN(buffer, size) itrustee_memory_out_enclave(buffer, size)

bool itrustee_memory_in_enclave(const void *buffer, uint32_t size);
bool itrustee_memory_out_enclave(const void *buffer, uint32_t size);


#endif
