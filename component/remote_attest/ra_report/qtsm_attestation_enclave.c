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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qtsm_lib.h>
#include "status.h"
#include "qingtian_enclave_init.h"

extern __attribute__((weak)) int qtsm_get_attestation(const int fd,
    const uint8_t *user_data, const uint32_t user_data_len,
    const uint8_t *nonce_data, const uint32_t nonce_data_len,
    const uint8_t *pubkey_data, const uint32_t pubkey_len,
    uint8_t *att_doc_data, uint32_t *att_doc_data_len);

int qt_enclave_att_report(uint8_t *nonce, uint32_t nonce_len, uint8_t *report, uint32_t report_len, uint32_t *real_len)
{
    int qtsm_dev_fd = 0;
    uint32_t doc_cose_len = (uint32_t)sizeof(attestation_document);
    uint8_t *doc_cose = NULL;
    uint8_t *user_data = NULL; // Provided by Enclave
    uint8_t *pubkey_data = NULL; // Provided by Enclave
    uint32_t user_data_len = 0;
    uint32_t pubkey_len = 0;
    int rc = -1;

    if (!nonce || !report || !real_len) {
        printf("[Error] Remote attestation input is suspiciously wrong.\n");
        return rc;
    }

    printf("Trying to get Qingtian enclave attestation doc...\n");
    /* Open QTSM device for interactions */
    qtsm_dev_fd = qt_get_qtsm_fd();
    if (qtsm_dev_fd <= 0 || qtsm_get_attestation == NULL) {
        rc = CC_FAIL;
        goto exit;
    }

    /* retrieve attestation report, currently pubkey and user_data are both NULL */
    doc_cose = (uint8_t *)calloc(1, doc_cose_len);
    if (!doc_cose) {
        rc = CC_FAIL;
        goto exit;
    }
    
    printf("Calling qtsm_get_attestation ... ");
    rc = qtsm_get_attestation(qtsm_dev_fd,
                              user_data, user_data_len,
                              nonce, nonce_len,
                              pubkey_data, pubkey_len,
                              doc_cose, &doc_cose_len);
    printf("Done.\n");

exit:
    if (rc == NO_ERROR) {
        memcpy(report, doc_cose, doc_cose_len);
        *real_len = doc_cose_len;
        rc = CC_SUCCESS;
    } else {
        /* Report failure */
        memset(report, 0, report_len);
        *real_len = 0;
        rc = CC_FAIL;
    }

    if (doc_cose) {
        free(doc_cose);
        doc_cose = NULL;
    }
    printf("Measurement complete.\n");
    return rc;
}