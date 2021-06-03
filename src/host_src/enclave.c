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

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>

#include "enclave.h"
#include "enclave_log.h"
#include "enclave_internal.h"

extern list_ops_management  g_list_ops;

static void check_dlopen_engine(p_tee_unregistered unregistered_func, cc_enclave_t *l_context)
{
    pthread_mutex_lock(&(g_list_ops.mutex_work));
    /* unregistered is only responsible for removing from the linked list */
    (*unregistered_func)(l_context, l_context->type);
    if (l_context->list_ops_node->ops_desc->count == 0) {
        dlclose(l_context->list_ops_node->ops_desc->handle);
    }
    pthread_mutex_unlock(&(g_list_ops.mutex_work));
}

static void error_handle(cc_enclave_t *enclave, void *handle, p_tee_registered registered_func,
                         p_tee_unregistered unregistered_func, char* path, bool check)
{
    cc_enclave_result_t tmp_res;
    if (check == true) {
        /* release the enclave number of resources */
        pthread_mutex_lock(&(g_list_ops.mutex_work));
        --g_list_ops.enclaveState.enclave_count;
        pthread_mutex_unlock(&(g_list_ops.mutex_work));
    }
    /* in list find engine: handle is null and l_context is not null */
    if (enclave != NULL && enclave->list_ops_node && !handle) {
        tmp_res = find_engine_registered(enclave->list_ops_node->ops_desc->handle, NULL, &unregistered_func);
        if (tmp_res != CC_SUCCESS) {
            print_error_term("Can not find unregistered in the failed exit phase\n");
        } else {
            check_dlopen_engine(unregistered_func, enclave);
        }
    }
    /* handle is not null, means dlopen is ok */
    if (handle) {
        /* check if registered invoke success */
        if (enclave != NULL && registered_func && unregistered_func && enclave->list_ops_node) {
            check_dlopen_engine(unregistered_func, enclave);
        } else {
            /* means registered func invoke fail OR find_engine_registered fail */
            dlclose(handle);
        }
    }
    if (path) {
        free(path);
    }

    if (enclave) {
        explicit_bzero(enclave, sizeof(cc_enclave_t));
    }
}

/* Lock to check the number of enclave
 * return CC_SUCCESS means success
 * return CC_ERROR_UNEXPECTED means lock mutex fail
 * return CC_FAIL means fail */
static cc_enclave_result_t check_enclave_count()
{
    cc_enclave_result_t res;
    int32_t ires = pthread_mutex_lock(&(g_list_ops.mutex_work));
    if (ires != 0) {
        res = CC_ERROR_UNEXPECTED;
        print_error_goto("Lock mutex failure\n");
    }
    ++g_list_ops.enclaveState.enclave_count;
    if (g_list_ops.enclaveState.enclave_count > MAX_ENCLAVE) {
        res = CC_ERROR_ENCLAVE_MAXIMUM;
        pthread_mutex_unlock(&(g_list_ops.mutex_work));
        print_error_goto("The number of enclaves exceed the maximum\n");
    }
    ires = pthread_mutex_unlock(&(g_list_ops.mutex_work));
    SECGEAR_CHECK_MUTEX_RES_CC(ires, res);
    res = CC_SUCCESS;
done:
    return res;
}

/*
 *  flags & SECGEAR_RESERVED_FLAG to check the flags,  if return true, means that 
 *  uses the currently unsupported bit. the simulation feature and the debug mode only supports sgx
 */
static bool check_flag(cc_enclave_result_t *res, const char *path, uint32_t flags, const enclave_features_t *features,
    const uint32_t features_count, cc_enclave_t *enclave)
{
    if (enclave == NULL || (enclave != NULL && enclave->used_flag == true)) {
        *res = CC_ERROR_INVALID_ENCLAVE_ID;
        return false;
    }
    if (!path) {
        *res = CC_ERROR_INVALID_PATH;
        return false;
    }
    if ((features_count > 0 && features == NULL) || (features_count == 0 &&  features != NULL)) {
        *res = CC_ERROR_BAD_PARAMETERS;
        return false;
    }
    if (flags & SECGEAR_RESERVED_FLAG) {
        *res = CC_ERROR_NOT_SUPPORTED;
        return false;
    }
    return true;
}

/* choose specific engine type */
static bool chose_engine_type(cc_enclave_result_t *res, enclave_type_t type, uint32_t version, enclave_type_version_t *type_version)
{
    *type_version = match_tee_type_version(type, version);
    if (*type_version == ENCLAVE_TYPE_VERSION_MAX) {
        *res = CC_ERROR_BAD_PARAMETERS;
        print_error_term("Type and version parameter error\n");
        return false;
    }
    return true;
}

/* check and transform enclave paths */
static bool check_transform_path(cc_enclave_result_t *res, const char *path, char **l_path)
{
    char real_p[PATH_MAX];
    /* check file exists and get absolute pathname */
    if (realpath(path, real_p) == NULL) {
        *res = CC_ERROR_INVALID_PATH;
        print_error_term("Path %s error %s\n", path, strerror(errno));
        return false;
    }

    /* check file permission */
    if (access(real_p, R_OK) != 0) {
        *res = CC_ERROR_ACCESS_DENIED;
        print_error_term("Path %s error %s\n", path, strerror(errno));
        return false;
    }
    size_t len = strlen(real_p) + 1;
    *l_path = (char *) malloc(len);
    if (*l_path == NULL) {
        *res = CC_ERROR_OUT_OF_MEMORY;
        print_error_term("Memory out\n");
        return false;
    }
    strncpy(*l_path, real_p, len);
    return true;
}

/* The enclave variable is the output context when successfully created */
cc_enclave_result_t cc_enclave_create(const char *path, enclave_type_t type, uint32_t version, uint32_t flags,
    const enclave_features_t *features, const uint32_t features_count, cc_enclave_t *enclave)
{
    int32_t  ires   = 0;
    uint32_t uires  = 0;
    bool check  = true;
    void *handle     = NULL;
    char *l_path     = NULL;

    cc_enclave_result_t res;
    enclave_type_version_t type_version;

    p_tee_registered   registered_func  = NULL;
    p_tee_unregistered unregistered_func = NULL;

    res = check_enclave_count();
    if (res == CC_ERROR_UNEXPECTED) {
        check = false;
    }
    SECGEAR_CHECK_RES(res);

    if (!check_flag(&res, path, flags, features, features_count, enclave)) {
        print_error_term("%s\n", cc_enclave_res2_str(res));
        return res;
    }

    memset(enclave, 0, sizeof(cc_enclave_t));
    if (!check_transform_path(&res, path, &l_path) || !chose_engine_type(&res, type, version, &type_version)) {
        goto done;
    }

    /* to do: gp support enter enclave debugging */
    if (((GP_ENCLAVE_TYPE_0 <= type_version) && (type_version < GP_ENCLAVE_TYPE_MAX)) && (flags & SECGEAR_DEBUG_FLAG)) {
        print_warning("This enclave scheme does not support enter enclave debugging\n");
    }    
    
    /* initialize the context */

    pthread_rwlock_init(&(enclave->rwlock), NULL);
    enclave->path  = l_path;
    enclave->flags = flags;
    enclave->type  = type_version;
    enclave->used_flag = true;

    /* if an enclave is created multiple times, first find it in the global list,
     * maybe the information about this engine has been filled in the list 
     */
    ires = pthread_mutex_lock(&(g_list_ops.mutex_work));
    SECGEAR_CHECK_MUTEX_RES_CC(ires, res);
    if (g_list_ops.count > 0) {
        uires = look_tee_in_list(type_version, enclave);
    }
    ires = pthread_mutex_unlock(&(g_list_ops.mutex_work));
    SECGEAR_CHECK_MUTEX_RES_CC(ires, res);
    
    /* if it is not loaded into the global linked list, 
     * means that this engine is called for the first time 
     * or this engine has been closed, it needs to be reloaded
     */
    if (!uires) {
        /* lock to call the registration function of engine */
        ires = pthread_mutex_lock(&(g_list_ops.mutex_work));
        SECGEAR_CHECK_MUTEX_RES_CC(ires, res);

        res = find_engine_open(type_version, &handle);
        SECGEAR_CHECK_RES_UNLOCK(res);

        res = find_engine_registered(handle, &registered_func, &unregistered_func);
        SECGEAR_CHECK_RES_UNLOCK(res);

        res = (*registered_func)(enclave, handle);
        SECGEAR_CHECK_RES_UNLOCK(res);

        ires = pthread_mutex_unlock(&(g_list_ops.mutex_work));
        SECGEAR_CHECK_MUTEX_RES_CC(ires, res);
    }

    /* call the registered function of each engine */
    if (enclave->list_ops_node != NULL && enclave->list_ops_node->ops_desc->ops->cc_create_enclave != NULL) {
        /* failure of this function will not bring out additional memory that needs to be managed */
        res = enclave->list_ops_node->ops_desc->ops->cc_create_enclave(enclave, features, features_count);
        SECGEAR_CHECK_RES(res);
    } else {
        print_error_goto("Enclave type version %d no valid ops function", type_version);
    }

    return CC_SUCCESS;
done:
    error_handle(enclave, handle, registered_func, unregistered_func, l_path, check);
    return res;
}

cc_enclave_result_t cc_enclave_destroy(cc_enclave_t *context)
{
    int32_t ires = 0;
    cc_enclave_result_t res = CC_FAIL;
    p_tee_unregistered unregistered_funcc;

    /* check context and enclave engine context */
    if (!context || !context->list_ops_node || !context->list_ops_node->ops_desc ||
        !context->list_ops_node->ops_desc->ops || context->used_flag == false) {
        print_error_term("Function context parameter error\n");
        return CC_ERROR_BAD_PARAMETERS;
    }

    ires = pthread_rwlock_wrlock(&(context->rwlock));
    if (ires) {
        return CC_ERROR_BUSY;
    }
    if (context->list_ops_node->ops_desc->ops->cc_destroy_enclave != NULL) {
        res = context->list_ops_node->ops_desc->ops->cc_destroy_enclave(context);
        SECGEAR_CHECK_RES(res);
    } else {
        print_error_goto("Enclave context no valid ops function\n");
    }

    /* look up enclave engine unregistered */
    res = find_engine_registered(context->list_ops_node->ops_desc->handle, NULL, &unregistered_funcc);
    SECGEAR_CHECK_RES(res);

    /* lock call unregistered func */
    ires = pthread_mutex_lock(&(g_list_ops.mutex_work));
    SECGEAR_CHECK_MUTEX_RES_CC(ires, res);
    /* call enclave engine free node */
    res = (*unregistered_funcc)(context, context->list_ops_node->ops_desc->type_version);
    SECGEAR_CHECK_RES_UNLOCK(res);
    if (context->list_ops_node->ops_desc->count == 0) {
        ires = dlclose(context->list_ops_node->ops_desc->handle);
        if (ires != 0) {
            res = CC_FAIL;
            pthread_mutex_unlock(&(g_list_ops.mutex_work));
            print_error_goto("Close engine failure\n");
        }
        context->list_ops_node = NULL;
    }
    /* free enclave number resources */
    g_list_ops.enclaveState.enclave_count--;
    ires = pthread_mutex_unlock(&(g_list_ops.mutex_work));
    SECGEAR_CHECK_MUTEX_RES_CC(ires, res);

    res = CC_SUCCESS;
done:
    if (context && context->path) {
        free(context->path);
    }
    if (context) {
        pthread_rwlock_unlock(&context->rwlock);
        pthread_rwlock_destroy(&context->rwlock);
        explicit_bzero(context, sizeof(cc_enclave_t));
    }
    return res;
}
