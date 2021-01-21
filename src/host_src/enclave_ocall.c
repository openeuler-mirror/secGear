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
#include <dlfcn.h>
#include "enclave.h"
#include "enclave_internal.h"
#include "enclave_log.h"

extern list_ops_management g_list_ops;

static int find_symbol(const char *name, void **function)
{
    void *handle = NULL;
    
    /* Currently, this function can only be called 
       under intel sgx. in this case, only be one sgx node.
       note: the ocall is intermediate process, and resources
       will not be released. */
    if (g_list_ops.list_head == NULL) {
        return 1;
    }

    handle = g_list_ops.list_head->ops_desc->handle;

    *function = dlsym(handle, name);
    if (*function == NULL) {
        return 1;
    }

    return 0;
}

CC_API_SPEC void sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
    void (*p_sgx_oc_cpuidex)(int cpuinfo[4], int leaf, int subleaf) = NULL;
    if (find_symbol(__FUNCTION__, (void **) &p_sgx_oc_cpuidex) == 0) {
        return p_sgx_oc_cpuidex(cpuinfo, leaf, subleaf);
    } else {
        print_error_term("can not find symbol %s \n", __FUNCTION__);
    }
}       
    
CC_API_SPEC int sgx_thread_wait_untrusted_event_ocall(const void *self)
{
    int (*p_sgx_thread_wait_untrusted_event_ocall)(const void *self) = NULL;
    if (find_symbol(__FUNCTION__, (void **) &p_sgx_thread_wait_untrusted_event_ocall) == 0) {
        return p_sgx_thread_wait_untrusted_event_ocall(self);
    } else {
        print_error_term("can not find symbol %s \n", __FUNCTION__);
        return 1;
    }
}      

 
CC_API_SPEC int sgx_thread_set_untrusted_event_ocall(const void *waiter)
{
    int (*p_sgx_thread_set_untrusted_event_ocall)(const void *waiter) = NULL;
    if (find_symbol(__FUNCTION__, (void **) &p_sgx_thread_set_untrusted_event_ocall) == 0) {
        return p_sgx_thread_set_untrusted_event_ocall(waiter);
    } else {
        print_error_term("can not find symbol %s \n", __FUNCTION__);
        return 1;
    }
}      

CC_API_SPEC int sgx_thread_setwait_untrusted_events_ocall(const void *waiter, const void *self)
{
    int (*p_sgx_thread_setwait_untrusted_events_ocall)(const void *waiter, const void *self) = NULL;
    if (find_symbol(__FUNCTION__, (void **) &p_sgx_thread_setwait_untrusted_events_ocall) == 0) {
        return p_sgx_thread_setwait_untrusted_events_ocall(waiter, self);
    } else {
        print_error_term("can not find symbol %s \n", __FUNCTION__);
        return 1;
    }
} 
      
CC_API_SPEC int sgx_thread_set_multiple_untrusted_events_ocall(const void **waiter, size_t total)
{
    int (*p_sgx_thread_set_multiple_untrusted_events_ocall)(const void **waiter, size_t total) = NULL;
    if (find_symbol(__FUNCTION__, (void **) &p_sgx_thread_set_multiple_untrusted_events_ocall) == 0) {
        return p_sgx_thread_set_multiple_untrusted_events_ocall(waiter, total);
    } else {
        print_error_term("can not find symbol %s \n", __FUNCTION__);
        return 1;
    }
}

CC_API_SPEC int pthread_wait_timeout_ocall(unsigned long long waiter, unsigned long long timeout)
{
    int (*p_pthread_wait_timeout_ocall)(unsigned long long waiter, unsigned long long timeout) = NULL;
    if (find_symbol(__FUNCTION__, (void **) &p_pthread_wait_timeout_ocall) == 0) {
        return p_pthread_wait_timeout_ocall(waiter, timeout);
    } else {
        print_error_term("can not find symbol %s \n", __FUNCTION__);
        return 1;
    }
}

CC_API_SPEC int pthread_create_ocall(unsigned long long self)
{
    int (*p_pthread_create_ocall)(unsigned long long self) = NULL;
    if (find_symbol(__FUNCTION__, (void **) &p_pthread_create_ocall) == 0) {
        return p_pthread_create_ocall(self);
    } else {
        print_error_term("can not find symbol %s \n", __FUNCTION__);
        return 1;
    }
}

CC_API_SPEC int pthread_wakeup_ocall(unsigned long long waiter)
{
    int (*p_pthread_wakeup_ocall)(unsigned long long waiter) = NULL;
    if (find_symbol(__FUNCTION__, (void **) &p_pthread_wakeup_ocall) == 0) {
        return p_pthread_wakeup_ocall(waiter);
    } else {
        print_error_term("can not find symbol %s \n", __FUNCTION__);
        return 1;
    }
}
