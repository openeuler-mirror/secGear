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

#ifndef __GP_USWITCHLESS_H__
#define __GP_USWITCHLESS_H__

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include "enclave.h"
#include "switchless_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Summary: Check the validity of the configuration
 * Parameters:
 *      cfg: configuration information of the task pool
 * Return:
 *      true: valid
 *      false: invalid
 */
bool uswitchless_is_valid_config(sl_task_pool_config_t *cfg);

/*
 * Summary: Adjusting default configurations
 * Parameters:
 *      cfg: configuration information of the task pool
 * Return: NA
 */
void uswitchless_adjust_config(sl_task_pool_config_t *cfg);

/*
 * Summary: initializing the switchless invoking task pool
 * Parameters:
 *      pool_buf: address of the task pool
 *      pool_cfg: configuration information of the task pool
 * Return: NA
 */
sl_task_pool_t *uswitchless_create_task_pool(void *pool_buf, sl_task_pool_config_t *pool_cfg);

/*
 * Summary: obtains the index of an idle task area from specified enclave
 * Parameters:
 *      enclave: enclave
 * Return:
 *      -1: no idle task area
 *      other: index of an idle task area
 */
int uswitchless_get_idle_task_index(cc_enclave_t *enclave);

/*
 * Summary: Releasing an idle task area
 * Parameters:
 *      enclave: enclave
 *      task_index: index of an idle task area
 * Return: NA
 */
void uswitchless_put_idle_task_by_index(cc_enclave_t *enclave, int task_index);

/*
 * Summary: submitting a switchless ecall task
 * Parameters:
 *      enclave: enclave
 *      task_index: index of an task area
 * Return: NA
 */
void uswitchless_submit_task(cc_enclave_t *enclave, int task_index);

/*
 * Summary: submitting a task
 * Parameters:
 *      enclave: enclave
 *      task_index: index of an task area
 *      ret_val: address that accepts the return value
 *      ret_val_size: size of the return value
 * Return: CC_SUCCESS, success; others failed.
 */
cc_enclave_result_t uswitchless_get_task_result(cc_enclave_t *enclave,
                                                int task_index,
                                                void *ret_val,
                                                size_t ret_val_size);

/*
 * Summary: whether the switchless features is enabled
 * Parameters:
 *      enclave: enclave
 * Return:
 *      true: enalbe
 *      false: disabled
 */
bool uswitchless_is_switchless_enabled(cc_enclave_t *enclave);

/*
 * Summary: whether the number of switchless ecall parameters is valid
 * Parameters:
 *      enclave: enclave
 *      argc: number of parameters
 * Return:
 *      true: the number of parameters is valid
 *      false: invalid number of parameters
 */
bool uswitchless_is_valid_param_num(cc_enclave_t *enclave, uint32_t argc);

/*
 * Summary: fill a task
 * Parameters:
 *      enclave: enclave
 *      task_index: index of an task area
 *      func_id: switchless function index
 *      argc: number of parameters
 *      args: parameter buffer
 * Return: NA
 */
void uswitchless_fill_task(cc_enclave_t *enclave, int task_index, uint32_t func_id, uint32_t argc, void *args);

#ifdef __cplusplus
}
#endif
#endif 
