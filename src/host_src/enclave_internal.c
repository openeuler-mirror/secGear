/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <sys/utsname.h>

#include "status.h"
#include "enclave_internal.h"
#include "enclave_log.h"

/* list：maintain enclave information */
CC_API_SPEC list_ops_management  g_list_ops = {
    .count = 0,
    .pthread_flag = false,
    .mutex_work = PTHREAD_MUTEX_INITIALIZER,
    .list_head = NULL,
    .enclaveState = {
        .enclave_count = 0,
        }
};

int print_log(cc_enclave_level_t level, const char *fmt, ...)
{
    va_list args;
    int ret;
    va_start(args, fmt);
    if (level == SECGEAR_LOG_LEVEL_NOTICE) {
        ret = vfprintf(stdout, fmt, args);
    } else {
        ret = vfprintf(stderr, fmt, args);
    }
    va_end(args);
    return ret;
}

char *cc_enclave_res2_str(cc_enclave_result_t res)
{
    switch (res) {
        case CC_SUCCESS:
            return "CC_SUCCESS";
        case CC_FAIL:
            return "CC_FAIL";
        case CC_ERROR_INVALID_TYPE:
            return "CC_ERROR_INVALID_TYPE";
        case CC_ERROR_INVALID_HANDLE:
            return "CC_ERROR_INVALID_HANDLE";
        case CC_ERROR_BAD_PARAMETERS:
            return "CC_ERROR_BAD_PARAMETERS";
        case CC_ERROR_OUT_OF_MEMORY:
            return "CC_ERROR_OUT_OF_MEMORY";
        default:
            return "UNKNOWN_RESULT_STATUS";
    }
}
/* return 1 means find */
static int32_t check_handle_opened(enclave_type_version_t type, void **handle)
{
    int32_t res = 0;
    struct list_ops_desc *p = g_list_ops.list_head;
    while (p != NULL) {
        if (p->ops_desc->type_version == type) {
            res = 1;
            *handle = p->ops_desc->handle;
            break;
        }
        p = p->next;
    }
    return res;
}

/* open enclave engine, success return handle */
cc_enclave_result_t find_engine_open(enclave_type_version_t type, void **handle)
{
    cc_enclave_result_t res = CC_ERROR_INVALID_TYPE;
    /* avoid repeated open */
    if (check_handle_opened(type, handle)) {
        res = CC_SUCCESS;
        goto done;
    }
    *handle = NULL;
    switch (type) {
        case SGX_ENCLAVE_TYPE_0:
            *handle = dlopen("/lib64/libsgx_0.so", RTLD_LAZY);
            break;
        case GP_ENCLAVE_TYPE_0:
            *handle = dlopen("/lib64/libgp_0.so", RTLD_LAZY);
            break;
        default:
            print_error_goto("Input type and version are not supported\n");
    }
    if (!*handle) {
        res = CC_ERROR_INVALID_HANDLE;
        print_error_goto("The dlopen failure: reason is %s\n", dlerror());
    } else {
        res = CC_SUCCESS;
    }
done:
    return res;
}

cc_enclave_result_t find_engine_registered(void *handle, p_tee_registered *p_func, p_tee_unregistered *p_unfun)
{
    cc_enclave_result_t res;
    dlerror();
    if (p_func != NULL) {
        *p_func = dlsym(handle, "cc_tee_registered");
    }
    if (dlerror() != NULL) {
        res = CC_ERROR_NO_FIND_REGFUNC;
        print_error_goto("cc_tee_registered function not found\n");
    }
    if (p_unfun != NULL) {
        *p_unfun = dlsym(handle, "cc_tee_unregistered");
    }
    if (dlerror() != NULL) {
        res = CC_ERROR_NO_FIND_UNREGFUNC;
        print_error_goto("cc_tee_unregistered function not found \n");
    }
    res = CC_SUCCESS;
done:
    return res;
}

static uint32_t check_processor()
{
    struct utsname buffer;
    if (uname(&buffer) != 0) {
        return ENCLAVE_TYPE_MAX;
    }
    const char *arch_name[] = {"x86_64", "aarch64"};
    const enclave_type_t type_name[] = {SGX_ENCLAVE_TYPE, GP_ENCLAVE_TYPE};
    for (size_t i = 0; i < sizeof(arch_name) / sizeof(char*); ++i) {
        if (!strcmp(arch_name[i], buffer.machine)) {
            return type_name[i];
        }
    }
    return ENCLAVE_TYPE_MAX;
}

enclave_type_version_t type_check_gp(uint32_t version)
{
    switch (version) {
        case 0:
            return GP_ENCLAVE_TYPE_0;
        default:
            print_error_term("This enclave version is not support\n");
            return ENCLAVE_TYPE_VERSION_MAX;
    }
}

enclave_type_version_t type_check_sgx(uint32_t version)
{
    switch (version) {
        case 0:
            return SGX_ENCLAVE_TYPE_0;
        default:
            print_error_term("This enclave version is not support\n");
            return ENCLAVE_TYPE_VERSION_MAX;
    }
}

/* Match enclave engine: lib<sgx/gp>_<version>.so */
enclave_type_version_t match_tee_type_version(enclave_type_t type, uint32_t version)
{
    type = (type == AUTO_ENCLAVE_TYPE) ? check_processor() : type;
    switch (type) {
        case SGX_ENCLAVE_TYPE:
            return type_check_sgx(version);
        case GP_ENCLAVE_TYPE:
            return type_check_gp(version);
        default:
            print_error_term("Detection platform type error: only support aarch64 and x86_64\n");
            return ENCLAVE_TYPE_VERSION_MAX;
    }
}

/* find return 1， otherwise 0
 * Lock: prevent it from being intercepted by other insertion
 * operations when searching, not in this function, but in the calling function */
uint32_t look_tee_in_list(enclave_type_version_t type, cc_enclave_t **context)
{
    uint32_t res = 0;
    struct list_ops_desc *p = g_list_ops.list_head;
    while (p != NULL) {
        if (p->ops_desc->type_version == type) {
            res = 1;
            /* this enclave ref +1 */
            ++(p->ops_desc->count);
            /* Assign the found node to the context */
            (*context)->list_ops_node = p;
            break;
        }
        p = p->next;
    }
    return res;
}

/* check and insert node to list */
void add_ops_list(struct list_ops_desc *node)
{
    struct list_ops_desc *temp = NULL;
    /* if it already exists, just add 1 to the reference count */
    if (check_node_exists_add(node)) {
        /* create multiple contexts for an engine. The existing ones in
         * this list can be reused without inserting multiple same nodes.
         * Because the function interface in this node can be reused */
        print_debug("This node has been inserted into the global list \n");
    } else {
        temp = g_list_ops.list_head;
        g_list_ops.list_head = node;
        node->next = temp;
        /* corresponding to this node reference +1 */
        ++node->ops_desc->count;
        /* the number of global list maintenance engines +1 */
        ++g_list_ops.count;
    }
}

static void remove_ops(struct list_ops_desc *fp, const struct list_ops_desc *p)
{
    if (fp == NULL) {
        g_list_ops.list_head = p->next;
    } else {
        fp->next = p->next;
    }
    g_list_ops.count--;
}

void remove_ops_list(const struct list_ops_desc *node)
{
    struct list_ops_desc *fp = NULL;
    struct list_ops_desc *p = g_list_ops.list_head;
    while (p != NULL) {
        if (!strcmp(p->ops_desc->name, node->ops_desc->name) &&
            p->ops_desc->type_version == node->ops_desc->type_version) {
            /* reference count becomes 0 delete this node */
            if (!--(p->ops_desc->count)) {
                /* found the head node */
                remove_ops(fp, p);
            }
            break;
        }
        fp = p;
        p = p->next;
    }
}

/*
 * return 1 means exist;
 * otherwise return 0
 */
uint32_t check_node_exists_add(const struct list_ops_desc *node)
{
    uint32_t res = 0;
    struct list_ops_desc *p = g_list_ops.list_head;
    while (p != NULL) {
        if (!strcmp(p->ops_desc->name, node->ops_desc->name) &&
            p->ops_desc->type_version == node->ops_desc->type_version) {
            res = 1;
            ++p->ops_desc->count;
            break;
        }
        p = p->next;
    }
    return res;
}
