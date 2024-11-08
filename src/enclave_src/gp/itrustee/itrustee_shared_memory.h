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

#ifndef __ITRUSTEE_SHARED_MEMORY_H__
#define __ITRUSTEE_SHARED_MEMORY_H__

#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

cc_enclave_result_t register_shared_memory_by_session(uint8_t *in_buf, uint8_t *registered_buf, void **sessionContext);
void open_session_unregister_shared_memory(void *sessionContext);

#ifdef __cplusplus
}
#endif
#endif
