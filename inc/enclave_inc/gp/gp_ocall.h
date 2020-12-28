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

#ifndef GP_OCALL_H
#define GP_OCALL_H

#include <stdio.h>
#include <string.h>
#include "tee_agent.h"
#include "status.h"
#include "enclave.h"

#ifndef TEE_SECE_AGENT_ID 
#define TEE_SECE_AGENT_ID   0x53656345
#endif
cc_enclave_result_t cc_ocall_enclave(
        size_t func_id,
        const void *in_buf,
        size_t in_buf_size,
        void *out_buf,
        size_t out_buf_size);
#endif
