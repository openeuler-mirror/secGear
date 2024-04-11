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
#include <linux/limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "enclave.h"
#include "qingtian_enclave.h"
// #include "qt_ra_report.h"
#include "sg_ra_report.h"

#include "qt_ra_report_verify.h"
#include "qingtian_verify_report_u.h"

#define MAX_BUFFER_SIZE 5120

int main(int argc, char *argv[])
{
    int rc = 0;
    char *path = PATH;
    cc_enclave_t *context = NULL;
    cc_enclave_result_t res = CC_FAIL;

    uint8_t exp_nonce[8] = {'1','1','2','2','3','3','4','4'};
    cc_get_ra_report_input_t in;

    uint8_t _out_buf[MAX_BUFFER_SIZE] = {0};
    cc_ra_buf_t out = {MAX_BUFFER_SIZE, (uint8_t*)&_out_buf};
    // Image pcr values, recorded when enclave image file is generated
    char *pcr0_value = "622177f13a6ec40756d37862dba63e4f48d3934dbdc044a81b7"
	               "6b5fc416dd2e6eabfdb0ab22cb8b61dd6d75d87f49eb5"; 
    pcr_raw pcr0 = {0, {0}};
    
    // For demo only, first argument is treated as Qingtian Root Path
    if (argc > 1) {
        g_qt_root_cert = qt_read_root_cert(argv[1]);
        if (!g_qt_root_cert) {
            printf("[Error] No Qingtian root cert is provided, "
                   "unable to do validation.\n");
        }
    }

    context = (cc_enclave_t *)malloc(sizeof(cc_enclave_t));
    if (!context) {
        return CC_ERROR_OUT_OF_MEMORY;
    }
    
    printf("Create secgear enclave\n");

    char real_p[PATH_MAX];
    /* check if file exists */
    if (realpath(path, real_p) == NULL) {
        if (getcwd(real_p, sizeof(real_p)) == NULL) {
            printf("Cannot find enclave image file");
            return -1;
        }
    }
    
    enclave_features_t features[2];
    features[0].setting_type = QINGTIAN_STARTUP_FEATURES;
    
    cc_startup_t pra;
    pra.cpus = 2;
    pra.enclave_cid = 5;
    pra.mem_mb = 512;
    // pra.ip = "127.0.0.1";
    // pra.port = 8082;
    pra.query_retry = 10;
    features[0].feature_desc = &pra;

    // Create qingtian enclave
    res = cc_enclave_create(real_p, QINGTIAN_ENCLAVE_TYPE, 0, 
                            SECGEAR_DEBUG_FLAG, &features[0], 1, context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        return res;
    }

    // Get qingtian enclave quote
    in.taid = (uint8_t *)context;
    in.nonce_len = 8;
    memcpy(in.nonce, exp_nonce, 8);
    in.with_tcb = false;
    in.req_key = false;

    rc = cc_get_ra_report(&in, &out);
    if (rc != CC_SUCCESS) {
        printf("Get Qiantian attestation report error.\n");
        goto end;
    }
    // image pcr_0, same as qt make-img outputs
    pcr0.index = 0;
    memcpy(pcr0.data, pcr0_value, QTSM_PCR_MAX_LENGTH);

    cc_ra_buf_t nonce = {8, exp_nonce}; // same as input for qingtian quote
    printf("COBR report lenth is %u-byte, start validation.\n", out.len);
    res = qt_verify_report(&out, &nonce, CC_RA_VERIFY_TYPE_LOOSE, (char*)&pcr0);
    if (res != CC_SUCCESS) {
        printf("[ERROR] Verify report failed. res is %d\n", res);
        goto end;
    }

    printf("Report verify succeeded.\n");
end:
    printf("Destroying enclave.\n");
    /* End */
    res = cc_enclave_destroy(context);
    if(res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    }

    free(context);

    if (g_qt_root_cert) {
        free_qt_root_cert(g_qt_root_cert);
    }

    return res;
}
