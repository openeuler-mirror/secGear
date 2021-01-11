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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_mem_mgmt_api.h"
#include "gp.h"
#include "caller.h"

#define PARAMNUM 4
#define POS_IN 0
#define POS_OUT 1
#define POS_IN_OUT 2

extern const cc_ecall_func_t cc_ecall_tables[];
extern const size_t ecall_table_size;
bool cc_is_within_enclave(const void *ptr, size_t sz)
{
    TEE_Result result;

    if (sz >= OE_UINT32_MAX)
        return false;
    if (sz == 0)
        sz = 1;

    result = TEE_CheckMemoryAccessRights(
        TEE_MEMORY_ACCESS_WRITE, (void*)ptr, (uint32_t)sz);
    return result == TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
    SLogTrace("----- TA_CreateEntryPoint ----- ");
    SLogTrace("TA version: %s ", TA_TEMPLATE_VERSION);
    set_caller_ca_owner();
    return TEE_SUCCESS;
}

/**
 *  Function TA_OpenSessionEntryPoint
 *  Description:
 *    The Framework calls the function TA_OpenSessionEntryPoint
 *    when a client requests to open a session with the Trusted Application.
 *    The open session request may result in a new Trusted Application instance
 *    being created.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[PARAMNUM], void **sessionContext)
{
    (void)paramTypes;  /* -Wunused-parameter */
    (void)params;  /* -Wunused-parameter */
    (void)sessionContext;  /* -Wunused-parameter */
    TEE_Result ret = TEE_SUCCESS;
    SLogTrace("---- TA_OpenSessionEntryPoint -------- ");

    return ret;
}

/**
 *  Function TA_CloseSessionEntryPoint
 *  Description:
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;  /* -Wunused-parameter */
    SLogTrace("---- TA_CloseSessionEntryPoint ----- ");
}

/**
 *  Function TA_DestroyEntryPoint
 *  Description:
 *    The function TA_DestroyEntryPoint is the Trusted Application's destructor,
 *    which the Framework calls when the instance is being destroyed.
 */
void TA_DestroyEntryPoint(void)
{
    SLogTrace("---- TA_DestroyEntryPoint ---- ");
}

static cc_enclave_result_t get_params_buffer(TEE_Param params[PARAMNUM],
                                               void **input_buffer,
                                               void **output_buffer)
{
    void *tmp_input_buffer = NULL;
    void *tmp_output_buffer = NULL;
    cc_enclave_result_t ret = CC_FAIL;
    if (params[POS_IN].memref.buffer) {
        tmp_input_buffer = malloc(params[POS_IN].memref.size);
        if (!tmp_input_buffer) {
            ret = CC_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        memcpy(tmp_input_buffer,
               params[POS_IN].memref.buffer,
               params[POS_IN].memref.size);
    }
    *input_buffer = tmp_input_buffer;

    if (params[POS_OUT].memref.buffer) {
        tmp_output_buffer = malloc(params[POS_OUT].memref.size);
        if (!tmp_output_buffer) {
            ret = CC_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        memcpy(tmp_output_buffer,
               params[POS_OUT].memref.buffer,
               params[POS_OUT].memref.size);
    }
    *output_buffer = tmp_output_buffer;

    return CC_SUCCESS;
done:
    if(tmp_input_buffer)
        free(tmp_input_buffer);
    if(tmp_output_buffer)
        free(tmp_output_buffer);
    *input_buffer = NULL;
    *output_buffer = NULL;
    return ret;
}
static TEE_Result handle_ecall_function(uint32_t param_types, TEE_Param params[PARAMNUM])
{
    cc_enclave_result_t res = CC_SUCCESS;
    uint32_t pt_input;
    uint32_t pt_output;
    uint32_t pt_args;

    void *tmp_input_buffer = NULL;
    size_t tmp_input_buffer_size;

    void *tmp_output_buffer = NULL;
    size_t tmp_output_buffer_size;

    size_t output_bytes_written = 0;

    cc_enclave_call_function_args_t *args_ptr = NULL;

    cc_ecall_func_t func;
    enclave_table_t ecall_table;

    pt_input = TEE_PARAM_TYPE_GET(param_types, POS_IN);
    pt_output = TEE_PARAM_TYPE_GET(param_types, POS_OUT);
    pt_args = TEE_PARAM_TYPE_GET(param_types, POS_IN_OUT);

    if (pt_input != TEE_PARAM_TYPE_NONE && pt_input != TEE_PARAM_TYPE_MEMREF_INPUT) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (pt_output != TEE_PARAM_TYPE_NONE && pt_output != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (pt_args != TEE_PARAM_TYPE_MEMREF_INOUT) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    args_ptr = (cc_enclave_call_function_args_t *)params[POS_IN_OUT].memref.buffer;

    ecall_table.ecalls = cc_ecall_tables;
    ecall_table.num = ecall_table_size;

    if (args_ptr->function_id >= ecall_table.num)
        return TEE_ERROR_ITEM_NOT_FOUND;

    func = ecall_table.ecalls[args_ptr->function_id];
    if (func == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    tmp_input_buffer_size = params[POS_IN].memref.size;
    tmp_output_buffer_size = params[POS_OUT].memref.size;
    res = get_params_buffer(params, &tmp_input_buffer, &tmp_output_buffer);
    if (res != CC_SUCCESS)
        goto done;
    /* call the ecall function */
    res = func(tmp_input_buffer,
               tmp_input_buffer_size,
               tmp_output_buffer,
               tmp_output_buffer_size,
               &output_bytes_written);
    if (res != CC_SUCCESS) {
        goto done;
    }
    if (params[POS_OUT].memref.buffer != NULL && params[POS_OUT].memref.size != 0) {
        if (output_bytes_written <= params[POS_OUT].memref.size) {
            memcpy(params[POS_OUT].memref.buffer, tmp_output_buffer, output_bytes_written);
        } else {
            SLogError("copy length too long!\n");
            res = CC_FAIL;
            goto done;
        }
    }
    args_ptr->output_bytes_written  = output_bytes_written;
    args_ptr->result = CC_SUCCESS;
done:
    if (tmp_output_buffer) {
        free(tmp_output_buffer);
    }

    if (tmp_input_buffer) {
        free(tmp_input_buffer);
    }

    tmp_input_buffer = NULL;
    tmp_output_buffer = NULL;

    return res == CC_SUCCESS ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
                                      uint32_t cmd_id,
                                      uint32_t paramTypes,
                                      TEE_Param params[PARAMNUM])
{
    (void)session_context; /* -Wunused-parameter */
    TEE_Result ret;

    switch (cmd_id) {
        case SECGEAR_ECALL_FUNCTION:
            {
                ret = handle_ecall_function(paramTypes, params);
                break;
            }
        default:
            {
                ret = TEE_FAIL;
                goto done;
            }
    }
done:
    return ret;
}

