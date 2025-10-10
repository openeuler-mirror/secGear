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

#ifndef SECURE_MAPPING_ENCLAVE_H
#define SECURE_MAPPING_ENCLAVE_H

#ifndef MAX_CIPHER_SIZE
#define MAX_CIPHER_SIZE 256
#endif

/* tee APIs */
int cc_sm_flush_data(uint32_t session_id);
int cc_sm_transition_c2i(uint32_t session_id, const uint8_t *in_data, size_t in_size,
                         uint64_t key_id, uint64_t *id_res);
int cc_sm_transition_i2c(uint32_t session_id, uint64_t *mapping_id,
                         uint8_t *out_data, size_t *out_size);

#endif
