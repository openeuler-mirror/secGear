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
 
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
 
#include "enclave.h"
#include "enclave_internal.h"
#include "enclave_log.h"
#include "sgx_enclave.h"
#include "sgx_uswitchless.h"
#include "sgx_edger8r.h"
#include "sgx_urts.h"
 
extern list_ops_management g_list_ops;
 
typedef struct _sgx_context {
    sgx_enclave_id_t edi;
} sgx_context_t;
 
 
cc_enclave_result_t conversion_res_status(uint32_t enclave_res, enclave_type_version_t type_version)
{
    if (type_version == SGX_ENCLAVE_TYPE_0) {
        switch (enclave_res) {
            case SGX_SUCCESS:
                return CC_SUCCESS;
            case SGX_ERROR_INVALID_PARAMETER:
                return CC_ERROR_BAD_PARAMETERS;
            case SGX_ERROR_OUT_OF_MEMORY:
                return CC_ERROR_OUT_OF_MEMORY;
            case SGX_ERROR_FILE_BAD_STATUS:
                return CC_ERROR_BAD_STATE;
            case SGX_ERROR_FEATURE_NOT_SUPPORTED:
                return CC_ERROR_NOT_SUPPORTED;
            case SGX_ERROR_ENCLAVE_LOST:
                return CC_ERROR_ENCLAVE_LOST;
            case SGX_ERROR_BUSY:
                return CC_ERROR_BUSY;
            case SGX_ERROR_UNDEFINED_SYMBOL:
                return CC_ERROR_INVALID_ENCLAVE;
            case SGX_ERROR_INVALID_SIGNATURE:
                return CC_ERROR_SIGNATURE_INVALID;
            case SGX_ERROR_OCALL_NOT_ALLOWED:
                return CC_ERROR_OCALL_NOT_ALLOWED;
            case SGX_ERROR_INVALID_FUNCTION:
                return CC_ERROR_INVALID_CMD;
            case SGX_ERROR_OUT_OF_TCS:
                return CC_ERROR_OUT_OF_TCS;
            case SGX_ERROR_ENCLAVE_CRASHED:
                return CC_ERROR_ENCLAVE_DEAD;
            case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
                return CC_ERROR_SERVICE_INVALID_PRIVILEGE;
            default:
                return CC_ERROR_UNEXPECTED;
        }
    } else {
        print_error_term("The input type is not supported\n");
        return CC_FAIL;
    }
}

cc_enclave_result_t _sgx_create_with_features(cc_enclave_t *enclave, const enclave_features_t *features,
                                              sgx_context_t *l_context)
{
    cc_enclave_result_t res;
    sgx_status_t sgx_res;
    sgx_uswitchless_config_t l_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
    const void *enclave_ex_p[32] = { 0 };

    cesgx_plc_config_t *l_plc = NULL;
    cesgx_switch_config_t *l_switch = NULL;
    if (features->setting_type & _CESGX_SWITCHLESS_FEATURES) {
        res = CC_ERROR_BAD_PARAMETERS;
        l_switch = (cesgx_switch_config_t *)features->feature_desc;
        /* check host and worker configuration */
        SECGEAR_CHECK_SIZE(l_switch->host_worker);
        SECGEAR_CHECK_SIZE(l_switch->enclave_worker);

        l_config.num_tworkers = l_switch->enclave_worker;
        l_config.num_uworkers = l_switch->host_worker;

        enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void *)&l_config;
        sgx_res = sgx_create_enclave_ex(enclave->path, (uint32_t)(enclave->flags & SECGEAR_DEBUG_FLAG), NULL,
            NULL, &(l_context->edi), NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    } else if (features->setting_type & _CESGX_PROTECTED_CODE_LOADER_FEATURES) {
        /* For the Sealing Enclave and the IP Enclave to be able to seal and unseal the
        decryption key, both enclaves must be signed with the same Intel SGX ISV
        signing key and have the same ProdID. */
        res = CC_ERROR_BAD_PARAMETERS;
        l_plc = (cesgx_plc_config_t *)features->feature_desc;
        SECGEAR_CHECK_SIZE(l_plc->len);
        SECGEAR_CHECK_CHAR(l_plc->path);
        sgx_res = sgx_create_encrypted_enclave(enclave->path, (uint32_t)(enclave->flags & SECGEAR_DEBUG_FLAG), NULL,
                                                  NULL, &(l_context->edi), NULL, (uint8_t *)l_plc->path);
    } else {
        res = CC_ERROR_BAD_STATE;
        print_error_goto("The set feature is currently not supported\n");
    }
    if (sgx_res != SGX_SUCCESS) {
        res = conversion_res_status(sgx_res, enclave->type);
        print_error_goto("Failed to create sgx enclave %s\n",cc_enclave_res2_str(res));
    }
    res = CC_SUCCESS;
done:
    return res;
}

cc_enclave_result_t _sgx_create(cc_enclave_t *enclave, const enclave_features_t *features,
                                  const uint32_t features_count)
{
    cc_enclave_result_t res = CC_ERROR_UNEXPECTED;
    sgx_context_t *l_context = NULL;
    sgx_status_t sgx_res = SGX_ERROR_UNEXPECTED;
 
    l_context = (sgx_context_t *)malloc(sizeof(sgx_context_t));
    if (l_context == NULL) {
        res = CC_ERROR_OUT_OF_MEMORY;
        print_error_goto("Memory out\n");
    }
    switch (features_count) {
        case 0:
            sgx_res = sgx_create_enclave(enclave->path, (uint32_t)(enclave->flags & SECGEAR_DEBUG_FLAG), NULL,
                    NULL, &(l_context->edi), NULL);
            if (sgx_res != SGX_SUCCESS) {
                res = conversion_res_status(sgx_res, enclave->type);
                print_error_goto("Failed to create sgx enclave\n");
            }
            break;
        case 1:
            res = _sgx_create_with_features(enclave, features, l_context);
            if (res != CC_SUCCESS) {
                goto done;
            }
            break;
        default:
            res = CC_ERROR_BAD_STATE;
            print_error_goto("SGX currently does not support setting features\n");
    }
    enclave->private_data = (void *)l_context;
    return CC_SUCCESS;
done:
    if (l_context) {
        free(l_context);
    }
    l_context = NULL;
    return res;
}
 
cc_enclave_result_t _sgx_destroy(cc_enclave_t *context)
{
    sgx_context_t *tmp = NULL;
    cc_enclave_result_t res = CC_FAIL;
    sgx_status_t sgx_res;
 
    if (!context || !context->private_data) {
        print_error_goto("The parameter error\n");
    }
 
    tmp = (sgx_context_t*)context->private_data;
    sgx_res = sgx_destroy_enclave(tmp->edi);
    if (sgx_res != SGX_SUCCESS) {
        res = conversion_res_status(sgx_res, context->type);
        print_error_goto("Failed to destroy sgx enclave \n");
    }

    free(tmp);
    context->private_data = NULL;
    return CC_SUCCESS;
done:
    if (tmp) {
        free(tmp);
        context->private_data = NULL;
    }
    return res;
}
 
cc_enclave_result_t cc_enclave_sgx_call_function(
    cc_enclave_t *enclave,
    uint32_t function_id,
    const void *input_buffer,
    size_t input_buffer_size,
    void *output_buffer,
    size_t output_buffer_size,
    void *ms,
    const void *ocall_table)
{
    (void)input_buffer;
    (void)input_buffer_size;
    (void)output_buffer;
    (void)output_buffer_size;
    sgx_status_t status;
    cc_enclave_result_t cc_status;
    status = sgx_ecall(((sgx_context_t *)(enclave->private_data))->edi, (int)function_id, ocall_table, ms);
    cc_status = conversion_res_status(status, enclave->type);
    return cc_status;
}
 
const struct cc_enclave_ops sgx_ops = {
    .cc_create_enclave = _sgx_create,
    .cc_destroy_enclave = _sgx_destroy,
    .cc_ecall_enclave = cc_enclave_sgx_call_function,
};

struct cc_enclave_ops_desc sgx_ops_name = {
    .name = "sgx",
    .ops = &sgx_ops,
    .type_version = SGX_ENCLAVE_TYPE_0,
    .count = 0,
};
 
struct list_ops_desc sgx_ops_node = {
    .ops_desc = &sgx_ops_name,
    .next = NULL,
};
 
#define OPS_NAME sgx_ops_name
#define OPS_NODE sgx_ops_node
#define OPS_STRU sgx_ops
 
cc_enclave_result_t cc_tee_registered(cc_enclave_t *context, void *handle)
{
    size_t len = strlen(OPS_NAME.name);
    if (OPS_NAME.type_version != context->type || OPS_NODE.ops_desc != &OPS_NAME ||
        len >= MAX_ENGINE_NAME_LEN || OPS_NAME.ops != &OPS_STRU) {
        print_error_goto("The struct cc_enclave_ops_desc initialization error\n");
    }
    OPS_NAME.handle = handle;
    context->list_ops_node = &OPS_NODE;
    add_ops_list(&OPS_NODE);
    return  CC_SUCCESS;
done:
    return CC_ERROR_BAD_PARAMETERS;
}
 
cc_enclave_result_t cc_tee_unregistered(cc_enclave_t *context, enclave_type_version_t type_version)
{
    if (context == NULL || context->list_ops_node != &OPS_NODE || type_version != OPS_NAME.type_version) {
        print_error_goto("Engine parameter error \n");
    }
    remove_ops_list(&OPS_NODE);
    return  CC_SUCCESS;
done:
    return CC_FAIL;
}
