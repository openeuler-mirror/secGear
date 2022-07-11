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

#define CC_ARRAY_LEN(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))

#define CC_IGNORE(param) (void)(param)

#define CC_API_SPEC __attribute__((visibility("default")))

#define CC_RWLOCK_LOCK_WR(lock) CC_IGNORE(pthread_rwlock_wrlock(lock))
#define CC_RWLOCK_LOCK_RD(lock) CC_IGNORE(pthread_rwlock_rdlock(lock))
#define CC_RWLOCK_UNLOCK(lock) CC_IGNORE(pthread_rwlock_unlock(lock))
#define CC_MUTEX_INIT(lock, attr) CC_IGNORE(pthread_mutex_init(lock, attr))
#define CC_MUTEX_DESTROY(lock) CC_IGNORE(pthread_mutex_destroy(lock))
#define CC_MUTEX_LOCK(lock) CC_IGNORE(pthread_mutex_lock(lock))
#define CC_MUTEX_UNLOCK(lock) CC_IGNORE(pthread_mutex_unlock(lock))
#define CC_COND_INIT(cond, attr) CC_IGNORE(pthread_cond_init(cond, attr))
#define CC_COND_SIGNAL(cond) CC_IGNORE(pthread_cond_signal(cond))
#define CC_COND_WAIT(cond, mtx_lock) CC_IGNORE(pthread_cond_wait(cond, mtx_lock))
#define CC_COND_DESTROY(cond) CC_IGNORE(pthread_cond_destroy(cond))
#define CC_THREAD_ATTR_INIT(attr) CC_IGNORE(pthread_attr_init(attr))
#define CC_THREAD_ATTR_DESTROY(attr) CC_IGNORE(pthread_attr_destroy(attr))

#ifdef __cplusplus
}
#endif

#endif
