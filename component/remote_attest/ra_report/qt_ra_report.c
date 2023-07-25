/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include <stdio.h>
#include "enclave.h"
#include "qt_ra_report.h"
#include "sg_ra_report_u.h"

cc_enclave_result_t qt_get_attestation_doc(cc_get_ra_report_input_t *in, cc_ra_buf_t *report)
{
    int retval = 0;
    uint32_t doc_cose_len = 0;
    int rc = CC_FAIL;
    cc_enclave_t *context = NULL;

    /* doc_cose_len is too long for cboren report, need to reduce it. */
    if (!in || !report ) {
        printf("[Error] Invalid Remote attestation inputs.\n");
        return rc;
    }

    context = (cc_enclave_t *)in->taid;
    if (context == NULL || report->buf == NULL || report->len < QINGTIAN_REPORT_MAX_LENGTH) {
        printf("[Error] Remote attestation input is suspiciously wrong.\n");
        return rc;
    }

    printf("Invoking Qingtian enclave attestation ecall...\n");

    rc = qt_enclave_att_report(context, &retval, in->nonce, in->nonce_len, report->buf, report->len, &doc_cose_len);
    if (rc != CC_SUCCESS || retval != CC_SUCCESS) {
        printf("Invoke qiantian attestation ecall failed, rc = 0x%08X, retval = 0x%08X.\n", rc, retval);
    }

    printf("Qiantian attestation ecall Done.\n");
    report->len = doc_cose_len; // Report real length of CBOR encoded qingtian attestation doc.
    return rc; 
}

static uni_ra_agent_t g_qt_agent = {
    .tee_type = CC_TEE_TYPE_QT,
    .prepare_ra_env = NULL,
    .get_ra_report = qt_get_ra_report,
};

static __attribute__((constructor)) void gp_register_ra_agent(void)
{
    cc_register_ra_agent(&g_qt_agent);
}