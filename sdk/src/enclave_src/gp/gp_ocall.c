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

#include "gp_ocall.h"
#include "tee_log.h"

#define MAX_LEN 4096

static int GetBuffer(
    uint32_t agent_id,
    void *buffer,
    const void *in_buf,
    void *out_buf,
    cc_enclave_ocall_function_args_t args)
{
    const int rc = -1;
    uint32_t ret;
    uint32_t length = -1;
    ret = tee_get_agent_buffer(agent_id, &buffer, &length);
    if (ret != TEE_SUCCESS || length > MAX_LEN) {
        SLogError("Failed to get buffer for agent %d\n", agent_id);
        return ret;
    }
    if (sizeof(args) > length) {
        SLogError("The parameter too long\n");
        return rc;
    } else {
        memcpy(buffer, &args, sizeof(args));
    }
    if (args.input_buffer_size > length - sizeof(args)) {
        SLogError("The parameter too long\n");
        return rc;
    } else {
        memcpy(buffer + sizeof(args), in_buf, args.input_buffer_size);
    }
    if (out_buf != NULL) {
        if (args.output_buffer_size > length - sizeof(args) - args.input_buffer_size) {
            SLogError("The parameter too long\n");
            return rc;
        } else {
            memcpy(buffer + sizeof(args) + args.input_buffer_size, out_buf, args.output_buffer_size);
        }
    }
    ret = tee_send_agent_cmd(agent_id);
    if (ret != TEE_SUCCESS) {
        SLogError("Failed to send cmd to agent 0x%x\n", agent_id);
        return rc;
    }
    return 0;
}
static int GetOutBuffer(
    uint32_t agent_id,
    void *buf,
    void *out_buf,
    size_t out_buf_size,
    cc_enclave_ocall_function_args_t args)
{
    int rc = -1;
    uint32_t ret;
    uint32_t length = -1;
    ret = tee_get_agent_buffer(agent_id, &buf, &length);
    if (ret != TEE_SUCCESS || length > MAX_LEN) {
        SLogError("Failed to get buffer for agent %d\n", agent_id);
        return rc;
    }
    if (out_buf != NULL) { 
        if (out_buf_size <= length - sizeof(args) - args.input_buffer_size ) {
            memcpy(out_buf, buf + sizeof(args) + args.input_buffer_size, out_buf_size);
	} else {
            SLogError("Failed copy buff to out buffer\n");
            return rc;
	}
    }
    return 0;
}
cc_enclave_result_t cc_ocall_enclave(
    size_t func_id,
    const void *in_buf,
    size_t in_buf_size,
    void *out_buf,
    size_t out_buf_size)
{
    void *buffer = NULL;
    int rc;
    uint32_t ret;
    cc_enclave_ocall_function_args_t args;
    uint32_t agent_id = TEE_SECE_AGENT_ID;

    if (!in_buf || in_buf_size == 0) {
        SLogError("input buffer is NULL\n");
        return CC_ERROR_BAD_PARAMETERS;
    }

    args.function_id = func_id;
    args.input_buffer_size = in_buf_size;
    args.output_buffer_size = out_buf_size;

    if (sizeof(args) >=  MAX_LEN) {
        SLogError("input buffer is overflow\n");
        return CC_ERROR_OVERFLOW;
    }
    ret = tee_agent_lock(agent_id);
    if (ret != TEE_SUCCESS) {
        SLogError("Failed to lock agent 0x%x\n", agent_id);
        return CC_ERROR_GENERIC;
    }
    rc = GetBuffer(agent_id, buffer, in_buf, out_buf, args);
    if (rc != 0) {
            goto unlock;
    }
    rc = GetOutBuffer(agent_id, buffer, out_buf, out_buf_size, args);
    if (rc != 0) {
            goto unlock;
    }
    tee_agent_unlock(agent_id);
    SLogTrace("ocall success\n");
    return CC_SUCCESS;
unlock:
    tee_agent_unlock(agent_id);
    return CC_ERROR_GENERIC;
}
