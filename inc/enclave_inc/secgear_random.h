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

#ifndef __SECGEAR_GENERATE_API_H
#define __SECGEAR_GENERATE_API_H

#include <stdio.h>
#include <stdint.h>
#include "status.h"
#ifdef __cplusplus
extern "C" {
#endif
cc_enclave_result_t  cc_enclave_generate_random(void * buffer, size_t size);

#ifdef __cplusplus
}
#endif
#endif
