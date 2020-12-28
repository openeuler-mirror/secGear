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

// To do: itrustee support.

#ifndef _REGISTER_AGENT_H_
#define _REGISTER_AGENT_H_


TEEC_Result TEEC_EXT_RegisterAgent(uint32_t agentId, int *devFd, void **buffer);

TEEC_Result TEEC_EXT_WaitEvent(uint32_t agentId, int devFd);

TEEC_Result TEEC_EXT_SendEventResponse(uint32_t agentId, int devFd);

TEEC_Result TEEC_EXT_UnregisterAgent(uint32_t agentId, int devFd, void **buffer);

#endif
