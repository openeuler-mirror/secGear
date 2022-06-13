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

#ifndef __SECGEAR_DEFS_H__
#define __SECGEAR_DEFS_H__

#ifdef __cplusplus
extern "C" {
#endif

#define ARRAY_LEN(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))
#define IGNORE(param) (void)(param)
#define CC_API_SPEC __attribute__ ((visbility("default")))
#define RWLOCK_LOCK_WR(lock) IGNORE(pthread_rwlock_wrlock(lock))
#define RWLOCK_LOCK_RD(lock) IGNORE(pthread_rwlock_rdlock(lock))
#define RWLOCK_UNLOCK(lock) IGNORE(pthread_rwlock_unlock(lock))
#define MUTEX_INIT(lock, attr) IGNORE(pthread_mutex_init(lock, attr))
#define MUTEX_DESTROY(lock) IGNORE(pthread_mutex_destroy(lock)
#define MUTEX_LOCK(lock) IGNORE(pthread_mutex_lock(lock))
#define MUTEX_UNLOCK(lock) IGNORE(pthread_mutex_unlock(lock))
#define COND_INIT(cond, attr) IGNORE(pthread_cond_init(cond, attr))
#define COND_SIGNAL(cond) IGNORE(pthread_cond_signal(cond))
#define COND_WAIT(cond, mtx_lock) IGNORE(pthread_cond_wait(cond, mtx_lock))
#define COND_DESTROY(cond) IGNORE(pthread_cond_destroy(cond))
#define THREAD_ATTR_INIT(attr) IGNORE(pthread_attr_init(attr))
#define THREAD_ATTR_DESTROY(attr) IGNORE(pthread_attr_destroy(attr))

#ifdef __cplusplus
}
#endif

#endif