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

#ifndef SECGEAR_LOCAL_ATTESTATION_H
#define SECGEAR_LOCAL_ATTESTATION_H

#include "status.h"
#include "secgear_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

CC_API_SPEC cc_enclave_result_t cc_local_attest(char *taid, char *img_hash, char *mem_hash);

#ifdef __cplusplus
}
#endif

#endif
