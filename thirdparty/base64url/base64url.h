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

#ifndef SECGEAR_BASE64URL_H
#define SECGEAR_BASE64URL_H

#include <stddef.h>
#include "status.h"
#include "secgear_defs.h"
#include "sg_report_st.h"

#ifdef __cplusplus
extern "C" {
#endif
// warning, caller need free return ptr
char* kpsecl_base64urlencode(const uint8_t *source, size_t source_len, size_t *dest_len);

// warning, caller need free return ptr
uint8_t* kpsecl_base64urldecode(const char *source, size_t source_len, size_t *dest_len);

#ifdef __cplusplus
}
#endif

#endif
