/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * CloudEnclave is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "mapping_cache.h"
#include "persistent_object_manager.h"
#include "secgear_log.h"

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define TEE_ERROR_UNKOWN 0x8000100CULL  // occurs when the subthread of TA access the persistent object
#define WORKER_THREAD_OWNER -2  // indicates one thread has won the loading ownership
#define DEFAULT_WAIT_TIME 100   // us

char SECURE_STORE_DIR[128] = "sec_storage_data/";

bool is_init = false;

int read_data(uint8_t *addr, int page_id)
{
    if (page_id < 0) {
        return 0;
    }

    char path[256];
    (void)snprintf(path, sizeof(path), "%s%d", SECURE_STORE_DIR, page_id);
    return read_po(path, addr, MAX_SECURE_FILE_SIZE);
}

int write_data(uint8_t *write_buffer, int page_id)
{
    if (page_id < 0) {
        return 0;
    }

    char path[256];
    (void)snprintf(path, sizeof(path), "%s%d", SECURE_STORE_DIR, page_id);
    return write_po(path, write_buffer, MAX_SECURE_FILE_SIZE);
}

int mapping_cache_data_manager_init(MappingCacheDataManager *mgr)
{
    for (int i = 0; i < MAX_CACHE_SLOT_NUM; i++) {
        pthread_rwlock_init(&mgr->cache[i].lock, NULL);
        mgr->cache[i].page_id = -1;
        mgr->cache[i].dirty = false;
        memset(mgr->cache[i].buffer, 0, MAX_SECURE_FILE_SIZE);
    }
    return 0;
}

void mapping_cache_data_manager_deinit(MappingCacheDataManager *mgr)
{
    for (int i = 0; i < MAX_CACHE_SLOT_NUM; i++) {
        pthread_rwlock_destroy(&mgr->cache[i].lock);
    }
}

int mapping_cache_data_manager_load(MappingCacheDataManager *mgr, int slot_id, int page_id)
{
    if (mgr->cache[slot_id].page_id == page_id) {
        return SM_ERR_NO_ERROR;
    }

    pthread_rwlock_wrlock(&mgr->cache[slot_id].lock);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    __atomic_store_n(&mgr->cache[slot_id].page_id, mgr->cache[slot_id].page_id - 1, __ATOMIC_RELEASE);
    pthread_rwlock_unlock(&mgr->cache[slot_id].lock);

    __atomic_thread_fence(__ATOMIC_ACQUIRE);

    // only this thread is allowed to perform read_data(), others must wait.
    if (mgr->cache[slot_id].page_id == WORKER_THREAD_OWNER || gettid() == getpid() + 1) {
        if (gettid() != getpid() + 1) {
            return SM_ERR_SWL_NO_SUPPORT;
        }

        uint32_t read_ret = read_data(mgr->cache[slot_id].buffer, page_id);
        if (read_ret == TEE_ERROR_UNKOWN) {
            return SM_ERR_SWL_NO_SUPPORT;
        }

        __atomic_store_n(&mgr->cache[slot_id].page_id, page_id, __ATOMIC_RELEASE);
        mgr->cache[slot_id].dirty = false;
    } else {
        while (mgr->cache[slot_id].page_id  < 0) {
            // wait for the loading to finish
            usleep(DEFAULT_WAIT_TIME);
            __atomic_thread_fence(__ATOMIC_ACQUIRE);
        }
    }

    return SM_ERR_NO_ERROR;
}

int mapping_cache_data_manager_put(MappingCacheDataManager *mgr, uint64_t id, uint8_t *plain, size_t len)
{
    int page_id = id / MAX_SECURE_FILE_SIZE;
    int slot_id = page_id;

    int ret = mapping_cache_data_manager_load(mgr, slot_id, page_id);
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }

    pthread_rwlock_rdlock(&mgr->cache[slot_id].lock);
    mgr->cache[slot_id].dirty = true;
    SMHdr *wp = (SMHdr *)(mgr->cache[slot_id].buffer + (id % MAX_SECURE_FILE_SIZE));
    wp->len = len;
    memcpy((uint8_t *)wp + sizeof(SMHdr), plain, len);
    pthread_rwlock_unlock(&mgr->cache[slot_id].lock);

    return SM_ERR_NO_ERROR;
}

int mapping_cache_data_manager_get(MappingCacheDataManager *mgr, uint64_t id, uint8_t *out_data, size_t *len)
{
    *len = 0;
    int page_id = id / MAX_SECURE_FILE_SIZE;
    int slot_id = page_id;

    int ret = mapping_cache_data_manager_load(mgr, slot_id, page_id);
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }

    pthread_rwlock_rdlock(&mgr->cache[slot_id].lock);
    SMHdr *wp = (SMHdr *)(mgr->cache[slot_id].buffer + (id % MAX_SECURE_FILE_SIZE));
    *len = wp->len;
    memcpy(out_data, (uint8_t *)wp + sizeof(SMHdr), wp->len);
    pthread_rwlock_unlock(&mgr->cache[slot_id].lock);

    return SM_ERR_NO_ERROR;
}

int mapping_cache_data_manager_flush(MappingCacheDataManager *mgr)
{
    int res = 0;
    int cnt = 0;
    for (int i = 0; i < MAX_CACHE_SLOT_NUM; i++) {
        pthread_rwlock_rdlock(&mgr->cache[i].lock);
        if (mgr->cache[i].page_id >= 0 && mgr->cache[i].dirty) {
            res += write_data(mgr->cache[i].buffer, mgr->cache[i].page_id);
            mgr->cache[i].dirty = false;
            cnt++;
        }
        pthread_rwlock_unlock(&mgr->cache[i].lock);
    }
    PrintInfo(PRINT_STRACE, "Secure Mapping: Flush buffers done, total %d\n", cnt);
    return res;
}

int mapping_cache_data_manager_flush_range(MappingCacheDataManager *mgr, int left, int right)
{
    int res = 0;
    int cnt = 0;
    for (int i = left; i < right; i++) {
        pthread_rwlock_rdlock(&mgr->cache[i].lock);
        if (mgr->cache[i].page_id >= 0 && mgr->cache[i].dirty) {
            res += write_data(mgr->cache[i].buffer, mgr->cache[i].page_id);
            mgr->cache[i].dirty = false;
            cnt++;
        }
        pthread_rwlock_unlock(&mgr->cache[i].lock);
    }
    PrintInfo(PRINT_STRACE, "Secure Mapping: Flush buffer done, total %d ([%d, %d)])\n", cnt, left, right);
    return res;
}

int id_manager_init(IDManager *mgr)
{
    pthread_spin_init(&mgr->spinlock, PTHREAD_PROCESS_PRIVATE);
    mgr->first_run = true;
    mgr->SM_off = 0;
    return 0;
}

void id_manager_deinit(IDManager *mgr)
{
    pthread_spin_destroy(&mgr->spinlock);
}

uint32_t id_manager_load(IDManager *mgr)
{
    if (likely(!mgr->first_run)) {
        return 0;
    }

    pthread_spin_lock(&mgr->spinlock);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (!mgr->first_run) {
        pthread_spin_unlock(&mgr->spinlock);
        return 0;
    }

    char path[64];
    (void)snprintf(path, sizeof(path), "%sid", SECURE_STORE_DIR);
    uint32_t ret = read_po(path, (uint8_t *)&mgr->SM_off, sizeof(uint64_t));
    if (ret != TEE_ERROR_UNKOWN) {
        __atomic_store_n(&(mgr->first_run), false, __ATOMIC_RELEASE);
    }
    pthread_spin_unlock(&mgr->spinlock);
    return ret;
}

int id_manager_persist(IDManager *mgr)
{
    if (mgr->first_run) {
        return 0;
    }

    char path[256];
    (void)snprintf(path, sizeof(path), "%sid", SECURE_STORE_DIR);
    return write_po(path, (uint8_t *)&mgr->SM_off, sizeof(uint64_t));
}

int id_manager_get_id(IDManager *mgr, size_t len, uint64_t *id)
{
    *id = INVALID_MAPPING_ID;

    uint32_t ret = id_manager_load(mgr);
    if (ret == TEE_ERROR_UNKOWN) {
        return SM_ERR_SWL_NO_SUPPORT;
    }

    pthread_spin_lock(&mgr->spinlock);
    uint64_t pos_id = mgr->SM_off;
    if (pos_id / MAX_SECURE_FILE_SIZE != (pos_id + len + sizeof(SMHdr)) / MAX_SECURE_FILE_SIZE) {
        pos_id = ((pos_id + len + sizeof(SMHdr)) / MAX_SECURE_FILE_SIZE) * MAX_SECURE_FILE_SIZE;
    }
    mgr->SM_off = pos_id + len + sizeof(SMHdr);
    pthread_spin_unlock(&mgr->spinlock);

    if (pos_id >= MAPPING_CACHE_SIZE) {
        PrintInfo(PRINT_ERROR, "Secure Mapping: Overflow!");
        return SM_ERR_OUT_OF_MEMORY;
    }

    *id = pos_id;
    return SM_ERR_NO_ERROR;
}

int id_manager_check_valid(IDManager *mgr, uint64_t id, bool *res)
{
    uint32_t ret = id_manager_load(mgr);
    if (ret == TEE_ERROR_UNKOWN) {
        return SM_ERR_SWL_NO_SUPPORT;
    }

    pthread_spin_lock(&mgr->spinlock);
    bool cmp = (id >= mgr->SM_off);
    pthread_spin_unlock(&mgr->spinlock);

    if (cmp) {
        PrintInfo(PRINT_ERROR,
                  "Secure Mapping: Invalid id access! id = %ld, SM_off = %ld (may inaccurate)",
                  id, mgr->SM_off);
    }

    *res = (!cmp);
    return SM_ERR_NO_ERROR;
}

int id_manager_flush(IDManager *mgr)
{
    return id_manager_persist(mgr);
}


void mapping_cache_init(MappingCache *map, char *store_path)
{
    if (store_path == NULL) {
        PrintInfo(PRINT_STRACE, "Secure Mapping: Use default storage path %s.", SECURE_STORE_DIR);
    } else {
        memcpy(SECURE_STORE_DIR, store_path, strlen(store_path) + 1);
    }

    id_manager_init(&map->id_manager);
    mapping_cache_data_manager_init(&map->data_manager);
}

void mapping_cache_deinit(MappingCache *map)
{
    id_manager_deinit(&map->id_manager);
    mapping_cache_data_manager_deinit(&map->data_manager);
}

int mapping_cache_put(MappingCache *map, uint8_t *plain, size_t len, uint64_t *key_id)
{
    if (plain == NULL || len == 0 || key_id == NULL || len >= MAX_SECURE_FILE_SIZE) {
        PrintInfo(PRINT_ERROR, "Secure Mapping: Put param invalid!");
        return SM_ERR_INVALID_PARAMETER_VALUE;
    }

    if (!is_init) {
        mapping_cache_init(map, NULL);
        is_init = true;
    }

    *key_id = INVALID_MAPPING_ID;
    uint64_t pos_id;
    int error = id_manager_get_id(&map->id_manager, len, &pos_id);
    if (error != SM_ERR_NO_ERROR) {
        return error;
    }
    *key_id = pos_id;

    error = mapping_cache_data_manager_put(&map->data_manager, pos_id, plain, len);
    return error;
}

int mapping_cache_replace(MappingCache *map, uint8_t *plain, size_t len, uint64_t key_id)
{
    if (!is_init) {
        mapping_cache_init(map, NULL);
        is_init = true;
    }

    return mapping_cache_data_manager_put(&map->data_manager, key_id, plain, len);
}

int mapping_cache_get(MappingCache *map, uint64_t id, uint8_t *out_data, size_t *len)
{
    if (out_data == NULL || len == NULL) {
        PrintInfo(PRINT_ERROR, "Secure Mapping: Get param invalid!");
        return SM_ERR_INVALID_PARAMETER_VALUE;
    }

    if (!is_init) {
        mapping_cache_init(map, NULL);
        is_init = true;
    }

    *len = 0;
    bool res;
    int error = id_manager_check_valid(&map->id_manager, id, &res);
    if (error != SM_ERR_NO_ERROR) {
        return error;
    }

    if (!res) {
        return SM_ERR_INVALID_PARAMETER_VALUE;
    }

    error = mapping_cache_data_manager_get(&map->data_manager, id, out_data, len);
    return error;
}

int mapping_cache_flush(MappingCache *map)
{
    if (!is_init) {
        return;
    }

    int res = id_manager_flush(&map->id_manager);
    res += mapping_cache_data_manager_flush(&map->data_manager);
    return res;
}
