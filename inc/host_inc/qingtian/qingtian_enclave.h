/*
 * Copyright (c) IPADS@SJTU 2021. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef FINAL_SECGEAR_QINGTIAN_ENCALVE_H
#define FINAL_SECGEAR_QINGTIAN_ENCALVE_H

#include "enclave.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define QINGTIAN_STARTUP_FEATURES 0x00000001u

typedef struct _qingtian_startup {
    uint32_t enclave_cid;
    uint32_t cpus;
    uint32_t mem_mb;
    const char *ip;
    uint16_t port;
    int query_retry;
} qingtian_startup_t;

typedef struct _qingtian_private_data {
    uint32_t enclave_id;
    qingtian_startup_t startup;
} qingtian_private_data_t;

#ifdef  __cplusplus
}
#endif

#endif // FINAL_SECGEAR_QINGTIAN_ENCALVE_H
