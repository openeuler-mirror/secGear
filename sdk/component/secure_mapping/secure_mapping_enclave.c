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

#include "secure_mapping_enclave.h"
#include "mapping_cache.h"
MappingCache mapping_cache;

/* hooks */
extern int cipher2plain(uint32_t session_id, const char *cipher, size_t clen,
                        unsigned char *plain, size_t *plen);
extern int plain2cipher(uint32_t session_id, const char *plain, size_t plen,
                        unsigned char *cipher, size_t *clen);
extern int c2i_post_process(uint32_t session_id, const uint8_t *in_data, size_t in_size,
                            uint64_t mapping_id, uint64_t *id_res);
extern int i2c_pre_process(uint32_t session_id, uint64_t *mapping_id,
                           uint8_t *out_data, size_t *out_size);

int cc_sm_flush_data(uint32_t session_id)
{
    return mapping_cache_flush(&mapping_cache);
}

int cc_sm_transition_c2i(uint32_t session_id, const uint8_t *in_data, size_t in_size,
                         uint64_t mapping_id, uint64_t *id_res)
{
    unsigned char plain[MAX_CIPHER_SIZE] = {0};
    size_t plain_len = 0;
    uint64_t mid = 0;

    int ret = cipher2plain(session_id, (const char *)in_data, in_size, plain, &plain_len);
    if (ret != SM_ERR_NO_ERROR) {
        return SM_ERR_NO_KEY;
    }

    if (mapping_id != INVALID_MAPPING_ID) {
        ret = mapping_cache_replace(&mapping_cache, plain, plain_len, mapping_id);
    } else {
        ret = mapping_cache_put(&mapping_cache, plain, plain_len, &mid);
    }
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }

    ret = c2i_post_process(session_id, in_data, in_size, mapping_id, &mid);
    *id_res = mid;
    return ret;
}

int cc_sm_transition_i2c(uint32_t session_id, uint64_t *mapping_id,
                         uint8_t *out_data, size_t *out_size)
{
    unsigned char plain[MAX_CIPHER_SIZE] = {0};
    size_t plain_len = 0;
    uint64_t mid = *mapping_id;

    int ret = i2c_pre_process(session_id, &mid, out_data, out_size);
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }

    ret = mapping_cache_get(&mapping_cache, mid, (uint8_t *)plain, &plain_len);
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }

    ret = plain2cipher(session_id, (const char *)plain, plain_len, out_data, out_size);
    if (ret != SM_ERR_NO_ERROR) {
        return ret;
    }
    return ret;
}
