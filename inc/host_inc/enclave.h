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

#ifndef FINAL_SECGEAR_ENCLAVE_H
#define FINAL_SECGEAR_ENCLAVE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#include "status.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define CC_API_SPEC __attribute__((visibility("default")))

/*only supports sgx debugging*/
#define SECGEAR_DEBUG_FLAG 0x00000001u

#define SECGEAR_RESERVED_FLAG \
    (~(SECGEAR_DEBUG_FLAG))

/*the enclave types supported by cloud enclave*/
typedef enum _enclave_type {
    SGX_ENCLAVE_TYPE = 0,
    GP_ENCLAVE_TYPE,
    AUTO_ENCLAVE_TYPE,
    ENCLAVE_TYPE_MAX
} enclave_type_t;

/*the enclave types and version supported by cloud enclave*/
typedef enum _enclave_type_version {
    SGX_ENCLAVE_TYPE_0 = 0,
    SGX_ENCLAVE_TYPE_MAX,
    GP_ENCLAVE_TYPE_0,
    GP_ENCLAVE_TYPE_MAX,
    ENCLAVE_TYPE_VERSION_MAX
} enclave_type_version_t;

/*cloud enclave supported features: currently supported sgx switchless plc*/
typedef struct _enclave_features {
    uint32_t setting_type;
    void *feature_desc;
} enclave_features_t;

/*pre-declaration for enclave context structure*/
struct list_ops_desc;

typedef struct _enclave {
    enclave_type_version_t type;
    char *path;
    uint32_t flags;
    pthread_rwlock_t rwlock;
    bool used_flag;
    void *private_data;
    /*enclave engine context manage, only one pointer*/
    struct  list_ops_desc *list_ops_node;
} cc_enclave_t;

/*The compilation options are hidden by default, 
 * and these two function interfaces are exported t
 * hrough this attribute
 * */
CC_API_SPEC cc_enclave_result_t cc_enclave_create(
                const char *path, 
                enclave_type_t type,
                uint32_t version, 
                uint32_t flags, 
                const enclave_features_t *features, 
                const uint32_t features_count,
                cc_enclave_t  *enclave);

CC_API_SPEC cc_enclave_result_t cc_enclave_destroy(cc_enclave_t *context);

/*automatic file generation required: aligned bytes*/
#define ALIGNMENT_SIZE (2 * sizeof(void*))

static inline size_t size_to_aligned_size(size_t size)
{
    return (size + ALIGNMENT_SIZE - 1) / ALIGNMENT_SIZE * ALIGNMENT_SIZE;
}
#define OE_UNUSED(P) (void)(P)

#define SIZE_ADD_POINT_IN(pointer, size)           \
    do {                                           \
        pointer = in_buf_size;                     \
        in_buf_size += size;                       \
    } while(0)

#define SIZE_ADD_POINT_OUT(pointer, size)          \
    do {                                           \
        pointer = out_buf_size;                    \
        out_buf_size += size;                      \
    } while(0)

#define SET_PARAM_IN_1(pointer, type, params, size)        \
    pointer = in_buf + in_buf_offset;                      \
    type params = *(type *)pointer;                        \
    in_buf_offset += size

#define SET_PARAM_IN_2(pointer, type, params, size)        \
    pointer = in_buf + in_buf_offset;                      \
    type *params = (type *)pointer;                        \
    in_buf_offset += size

#define SET_PARAM_OUT(pointer, type, params, size)         \
    pointer = out_buf + out_buf_offset;                    \
    type *params = (type *)pointer;                        \
    out_buf_offset += size

#define SET_PARAM_OUT_2(pointer, type, params, size)        \
    pointer = out_buf + out_buf_offset;                     \
    params = (type *)pointer;                               \
    if (out_buf != NULL && size != 0) {                     \
        memcpy(pointer, params ## _in_p, size);             \
    }                                                       \
    out_buf_offset += size

#define COUNT(ARR) (sizeof(ARR) / sizeof((ARR)[0]))

typedef cc_enclave_result_t (*cc_ocall_func_t)(
    const uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t  output_buffer_size);

typedef struct _call_cc_enclave_function_args {
    uint64_t function_id;
    const void *input_buffer;
    size_t input_buffer_size;
    void *output_buffer;
    size_t output_buffer_size;
    size_t output_bytes_written;
    cc_enclave_result_t result;
} cc_enclave_call_function_args_t;

typedef struct _ocall_cc_enclave_function_args {
    uint64_t function_id;
    size_t input_buffer_size;
    size_t output_buffer_size;
} cc_enclave_ocall_function_args_t;

cc_enclave_result_t oe_call_enclave_function_by_table_id(
        cc_enclave_t *enclave,
        uint64_t function_id,
        const void *input_buffer,
        size_t input_buffer_size,
        void *output_buffer,
        size_t output_buffer_size,
        size_t *output_bytes_written);

cc_enclave_result_t cc_enclave_call_function(
        cc_enclave_t *enclave,
        uint32_t function_id,
        const void *input_buffer,
        size_t input_buffer_size,
        void *output_buffer,
        size_t output_buffer_size,
        void *ms,
        const void *ocall_table);

typedef struct _ocall_table {
    uint64_t num;
    cc_ocall_func_t ocalls[];
} ocall_enclave_table_t;

# ifdef  __cplusplus
}
# endif
#endif //FINAL_SECGEAR_ENCLAVE_H
