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

#ifndef FINAL_SECGEAR_PENGLAI_ENCALVE_H
#define FINAL_SECGEAR_PENGLAI_ENCALVE_H

/* New struct used to hint the in | out buf size. */
typedef struct _untrusted_mem_info_t
{
    uint8_t fid;
    size_t in_buf_size;
    size_t out_buf_size;
} untrusted_mem_info_t;

#endif // FINAL_SECGEAR_PENGLAI_ENCALVE_H
