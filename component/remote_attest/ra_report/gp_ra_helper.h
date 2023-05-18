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

#ifndef SECGEAR_RA_HELPER_H
#define SECGEAR_RA_HELPER_H

#include <stdint.h>
#include <stdbool.h>
#include "status.h"
#include "sg_report_st.h"

#define MAX_NONCE_BUF_LEN 512
typedef struct {
    uint8_t *uuid;
    uint32_t nonce_len;
    uint8_t nonce[MAX_NONCE_BUF_LEN];
    bool with_tcb;
} gp_get_ra_report_input_t;

cc_enclave_result_t gen_provision_no_as_in_buff(cc_ra_buf_t **in);
cc_enclave_result_t gen_ra_report_in_buff(gp_get_ra_report_input_t *param, cc_ra_buf_t **json_buf);
void print_ra_report(cc_ra_buf_t *report);
void free_cc_ra_buf(cc_ra_buf_t *ra_buf);
#endif

