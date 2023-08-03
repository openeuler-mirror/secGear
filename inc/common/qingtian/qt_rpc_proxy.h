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

#ifndef QINGTIAN_RPC_PROXY_H
#define QINGTIAN_RPC_PROXY_H

#include <stdint.h>
#include <stddef.h>
#include "status.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define QT_VSOCK_MAX_DATA_LEN (1024 * 1024)

typedef cc_enclave_result_t (*qt_handle_request_msg_t)(uint8_t *input, size_t input_len, uint8_t **output, size_t *output_len);

int qt_rpc_proxy_init(int cid, qt_handle_request_msg_t handle_func);
void qt_rpc_proxy_destroy(void);

uint64_t qt_rpc_proxy_call(uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len);

#ifdef  __cplusplus
}
#endif
#endif
