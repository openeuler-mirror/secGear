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

#ifndef FINAL_SECGEAR_SGX_ENCALVE_H
#define FINAL_SECGEAR_SGX_ENCALVE_H

#define _CESGX_SWITCHLESS_FEATURES 0x00000001u
#define _CESGX_PROTECTED_CODE_LOADER_FEATURES 0x00000002u

/* This header file is placed in inc/sgx to allow users to 
 * invoke features supported by specific enclave, such as 
 * plc swichless, which are only meaningful for sgx. 
 */


typedef struct _sgx_plc_config {
    uint32_t len;
    char *path;
} cesgx_plc_config_t;

typedef struct _sgx_switch_config {
    uint32_t host_worker;
    uint32_t enclave_worker;
} cesgx_switch_config_t;

#endif //FINAL_SECGEAR_SGX_ENCALVE_H
