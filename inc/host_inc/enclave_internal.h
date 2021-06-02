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

#ifndef FINAL_SECGEAR_ENCLAVE_INTERNAL_H
#define FINAL_SECGEAR_ENCLAVE_INTERNAL_H

#include <pthread.h>
#include "enclave.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define MAX_ENCLAVE 5
#define MAX_ENCLAVE_TYPE 3
#define MAX_ENGINE_NAME_LEN 10

typedef enum _enclave_state {
    ENCLAVE_UNINITIALION,
    ENCLAVE_INITIALIZING,
    ENCLAVE_INITIALIZED,
} enclave_state_t;

/*the ops function structure is used to ecall, create, and destroy specific enclave*/
struct cc_enclave_ops {
    cc_enclave_result_t (*cc_create_enclave)(
                    cc_enclave_t *enclave, 
                    const enclave_features_t *features,
                    const uint32_t features_count);

    cc_enclave_result_t (*cc_destroy_enclave)(cc_enclave_t *enclave);

    cc_enclave_result_t (*cc_ecall_enclave)(
		    cc_enclave_t *enclave, 
		    uint32_t function_id, 
		    const void *input_buffer,
		    size_t input_buffer_size, 
		    void *output_buffer, 
		    size_t output_buffer_size, 
		    void *ms, 
		    const void *ocall_table);
};

struct cc_enclave_ops_desc {
    /*enclave engine name*/
    const char name[MAX_ENGINE_NAME_LEN];
    /*enclave engine handle*/
    void *handle;
    /*reference counting: if 0, close engine engine*/
    uint32_t count;
    const enclave_type_version_t type_version;
    const struct cc_enclave_ops *ops;
};

struct list_ops_desc {
    struct cc_enclave_ops_desc *ops_desc;
    struct list_ops_desc *next;
};

typedef struct _enclave_state_manage {
    uint32_t enclave_count;
} enclave_state_manage_t;

typedef struct _list_ops_management {
    /*count is the number of list_ops_desc maintained by the current list*/
    uint32_t count;
    /*for agent thread*/
    bool pthread_flag;
    /*lock: used to protect the contents of the list*/
    pthread_mutex_t mutex_work;
    struct list_ops_desc *list_head;
    /*all enclave state maintenance*/
    enclave_state_manage_t enclaveState;
} list_ops_management;

/*enclave engine register, unregister function*/
typedef cc_enclave_result_t (*p_tee_registered)(cc_enclave_t *context, void *handle);
typedef cc_enclave_result_t (*p_tee_unregistered)(cc_enclave_t *context, enclave_type_version_t type);


/*creating enclave, first check in the list whether this engine has been added */
uint32_t look_tee_in_list(enclave_type_version_t type, cc_enclave_t *);

enclave_type_version_t match_tee_type_version(enclave_type_t type, uint32_t version);

/*open enclave engine shared lib and return handle*/
cc_enclave_result_t find_engine_open(enclave_type_version_t type, void ** handle);

/*look up enclave engine register, unregister function and return */
cc_enclave_result_t find_engine_registered(void *handle, p_tee_registered *p_func, p_tee_unregistered *p_unfunc);


////////////////////////////////////////////////////////////////////////////////////////////
/*each engine needs to implement registered, and the unregistered function declaration*/
CC_API_SPEC cc_enclave_result_t cc_tee_registered(cc_enclave_t *context, void *handle);
CC_API_SPEC cc_enclave_result_t cc_tee_unregistered(cc_enclave_t *context, enclave_type_version_t type_version);
CC_API_SPEC void add_ops_list(struct list_ops_desc *node);
CC_API_SPEC void remove_ops_list(const struct list_ops_desc *node);

uint32_t check_node_exists_add(const struct list_ops_desc *node);
//////////////////////////////////////////////////////////////////////////////////////////////

cc_enclave_result_t conversion_res_status(uint32_t enclave_res, enclave_type_version_t type_version);

# ifdef  __cplusplus
}
# endif

#endif //FINAL_SECGEAR_ENCLAVE_INTERNAL_H
