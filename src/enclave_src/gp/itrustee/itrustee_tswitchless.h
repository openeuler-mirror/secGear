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

#ifndef __ITRUSTEE_TSWITCHLESS_H__
#define __ITRUSTEE_TSWITCHLESS_H__

#include <pthread.h>
#include "switchless_defs.h"
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Summary: Switchless initalization on the TA side
 * Parameters:
 *     pool_buf: address of the task pool buffer
 *     pool: task pool management data structure
 *     tids: thread id for tworkers
 * Return: CC_SUCCESS, success; others failed.
 */
cc_enclave_result_t tswitchless_init(void *pool_buf, sl_task_pool_t **pool, pthread_t **tids);

/*
 * Summary: Switchless deinitalization on the TA side
 * Parameters:
 *     pool: task pool management data structure
 *     tids: thread id for tworkers
 * Return: CC_SUCCESS, success; others failed.
 */
void tswitchless_fini(sl_task_pool_t *pool, pthread_t *tids);

#ifdef __cplusplus
}
#endif
#endif
