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

#ifndef SECGEAR_REPORT_STRUCT_H
#define SECGEAR_REPORT_STRUCT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cc_ra_buf {
    uint32_t len;
    uint8_t *buf;
} cc_ra_buf_t;

typedef enum {
    CC_RA_SCENARIO_NO_AS,
    // CC_RA_SCENARIO_AS_NO_DAA,
    // CC_RA_SCENARIO_AS_WITH_DAA
} cc_ra_scenario_t;

typedef enum {
    CC_RA_VERIFY_TYPE_LOOSE,
    CC_RA_VERIFY_TYPE_STRICT,
    CC_RA_VERIFY_TYPE_MAX
} cc_ra_verify_type_t;

#ifdef __cplusplus
}
#endif

#endif
