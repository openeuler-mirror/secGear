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

#ifndef FINAL_SECGEAR_GP_ENCLAVE_H
#define FINAL_SECGEAR_GP_ENCLAVE_H

#include "tee_client_api.h"

enum
{
    SECGEAR_ECALL_FUNCTION = 0,
};

typedef struct _gp_context{
    TEEC_UUID uuid;
    TEEC_Context ctx;
    TEEC_Session session;
} gp_context_t;

typedef struct _thread_param {
    uint32_t agent_id;
    uint64_t num;
    cc_ocall_func_t *ocalls;
} thread_param_t;

#define GP_CHECK_MUTEX_RES_UNLOCK(RES)                                  \
    do{                                                                 \
        int32_t _res = (RES);                                           \
        if (_res != 0) {                                                \
            pthread_mutex_unlock(&g_mtx_flag);                          \
            print_error_goto("Mutex acquisition or release error \n");  \
        }                                                               \
    } while(0)

extern list_ops_management  g_list_ops;

#endif //FINAL_SECGEAR_GP_ENCLAVE_H
