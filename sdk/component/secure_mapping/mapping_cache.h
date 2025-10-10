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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

extern char SECURE_STORE_DIR[128];

#define MAX_SECURE_FILE_SIZE (4 * 1024 * 1024)
#define MAPPING_CACHE_SIZE (MAX_CACHE_SLOT_NUM * MAX_SECURE_FILE_SIZE)
#define INVALID_MAPPING_ID UINT64_MAX
#define MAX_CACHE_SLOT_NUM 128

enum SM_ERROR_LS {
    SM_ERR_NO_ERROR = 0,
    SM_ERR_INVALID_PARAMETER_VALUE = 1,
    SM_ERR_OUT_OF_MEMORY = 5,
    SM_ERR_NO_KEY = 7,
    SM_ERR_SWL_NO_SUPPORT = 63,
};

typedef struct SMHdr {
    size_t len;
} SMHdr;

typedef struct MappingCacheSlot {
    pthread_rwlock_t lock;
    int page_id;
    bool dirty;
    uint8_t buffer[MAX_SECURE_FILE_SIZE];
} MappingCacheSlot;

typedef struct MappingCacheDataManager {
    MappingCacheSlot cache[MAX_CACHE_SLOT_NUM];
} MappingCacheDataManager;

typedef struct IDManager {
    pthread_spinlock_t spinlock;
    bool first_run;
    uint64_t SM_off;
} IDManager;

typedef struct MappingCache {
    IDManager id_manager;
    MappingCacheDataManager data_manager;
} MappingCache;

extern MappingCache mapping_cache;

void mapping_cache_init(MappingCache *map, char *store_path);
void mapping_cache_deinit(MappingCache *map);
int mapping_cache_flush(MappingCache *map);
int mapping_cache_get(MappingCache *map, uint64_t id, uint8_t *out_data, size_t *len);
int mapping_cache_replace(MappingCache *map, uint8_t *plain, size_t len, uint64_t key_id);
int mapping_cache_put(MappingCache *map, uint8_t *plain, size_t len, uint64_t *key_id);
