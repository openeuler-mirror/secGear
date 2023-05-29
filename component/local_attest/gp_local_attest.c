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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "tee_ra_api.h"
#include "tee_crypto_api.h"
#include "base64url.h"
#include "cJSON.h"
#include "secgear_log.h"
#include "status.h"
#include "sg_report_st.h"
#include "local_attest_agent.h"
#include "gp_report_helper.h"

#define CC_HASH_LEN 64
typedef struct {
    char *taid;
    char *img_hash;
    char *mem_hash;
} gp_basevalue_t;

#define HEX_ONE_CHAR_BITS 4
#define HEX_BYTE_MAX 0xf

static void hex2str(const uint8_t *source, int source_len, char *dest)
{
    char *hexEncode = "0123456789abcdef";
    int i = 0, j =  0;
    for (i = 0; i < source_len; i++) {
        dest[j++] = hexEncode[(source[i] >> HEX_ONE_CHAR_BITS) & HEX_BYTE_MAX];
        dest[j++] = hexEncode[(source[i]) & HEX_BYTE_MAX];
    }
}

static cc_enclave_result_t gp_compare_hash(gp_basevalue_t *basevalue, char *ta_img, char *ta_mem)
{
    size_t imglen = 0;
    size_t memlen = 0;
    uint8_t *decodedimg = kpsecl_base64urldecode(ta_img, strlen(ta_img), &imglen);
    uint8_t *decodedmem = kpsecl_base64urldecode(ta_mem, strlen(ta_mem), &memlen);

    char heximg[CC_HASH_LEN + 1] = {0};
    char hexmem[CC_HASH_LEN + 1] = {0};
    hex2str(decodedimg, imglen, heximg);
    hex2str(decodedmem, memlen, hexmem);
    free(decodedimg);
    free(decodedmem);

    PrintInfo(PRINT_STRACE, "heximg:%s, hexmem:%s", heximg, hexmem);
    PrintInfo(PRINT_STRACE, "img_hash:%s, mem_hash:%s", basevalue->img_hash, basevalue->mem_hash);

    if (memcmp(heximg, basevalue->img_hash, strlen(basevalue->img_hash)) != 0 ||
        memcmp(hexmem, basevalue->mem_hash, strlen(basevalue->mem_hash)) != 0) {
        PrintInfo(PRINT_ERROR, "verify local report hash failed!\n");
        return CC_ERROR_LOCAL_REPORT_HASH_MISMATCH;
    }
    return CC_SUCCESS;
}

static cc_enclave_result_t gp_verify_local_report(gp_basevalue_t *basevalue, uint8_t *nonce, size_t nonce_len,
    cc_ra_buf_t *report)
{
    char *b64_nonce = NULL;
    size_t b64_nonce_len = 0;
    cc_enclave_result_t ret = CC_ERROR_LOCAL_REPORT_INVALID;

    cJSON *cj_report = cJSON_ParseWithLength((char *)report->buf, report->len);
    if (cj_report == NULL) {
        PrintInfo(PRINT_ERROR, "report to json failed\n");
        return ret;
    }
    cJSON *cj_payload = cJSON_GetObjectItemCaseSensitive(cj_report, "payload");
    if (cj_payload == NULL) {
        PrintInfo(PRINT_ERROR, "report payload failed!\n");
        goto end;
    }
    b64_nonce = kpsecl_base64urlencode(nonce, nonce_len, &b64_nonce_len);
    cJSON *cj_b64_nonce = cJSON_GetObjectItemCaseSensitive(cj_payload, "nonce");
    if (cj_b64_nonce == NULL || strcmp(cj_b64_nonce->valuestring, b64_nonce)) {
        PrintInfo(PRINT_ERROR, "check nonce value failed!\n");
        free(b64_nonce);
        goto end;
    }
    free(b64_nonce);

    cJSON *cj_uuid = cJSON_GetObjectItemCaseSensitive(cj_payload, "uuid");
    if (cj_uuid == NULL || strcmp(cj_uuid->valuestring, basevalue->taid)) {
        PrintInfo(PRINT_ERROR, "check uuid failed!\n");
        goto end;
    }
    cJSON *cj_ta_img = cJSON_GetObjectItemCaseSensitive(cj_payload, "ta_img");
    if (cj_ta_img == NULL) {
        PrintInfo(PRINT_ERROR, "check ta_img failed!\n");
        goto end;
    }
    cJSON *cj_ta_mem = cJSON_GetObjectItemCaseSensitive(cj_payload, "ta_mem");
    if (cj_ta_mem == NULL) {
        PrintInfo(PRINT_ERROR, "check ta_mem failed!\n");
        goto end;
    }

    ret = gp_compare_hash(basevalue, cj_ta_img->valuestring, cj_ta_mem->valuestring);
end:
    cJSON_Delete(cj_report);

    return ret;
}

#define LOCAL_REPORT_OUT_LEN 0x3000
#define LOCAL_REPORT_NONCE_LEN 32
cc_enclave_result_t agent_local_attest(char *taid, char *img_hash, char *mem_hash)
{
    cc_get_ra_report_input_t ra_input = {0};
    ra_input.taid = (uint8_t *)taid;
    ra_input.with_tcb = false;

    TEE_GenerateRandom(ra_input.nonce, LOCAL_REPORT_NONCE_LEN);
    ra_input.nonce_len = LOCAL_REPORT_NONCE_LEN + 1;

    cc_ra_buf_t *in = NULL;
    cc_enclave_result_t ret = gen_ra_report_in_buff(&ra_input, &in);
    if (ret != CC_SUCCESS) {
        PrintInfo(PRINT_ERROR, "gen ra report in buff error! ret:%x\n", ret);
        return -1;
    }

    uint8_t data[LOCAL_REPORT_OUT_LEN] = {0};
    cc_ra_buf_t report = {LOCAL_REPORT_OUT_LEN, data};

    TEE_Result gp_ret = ra_local_report((struct ra_buffer_data *)in, (struct ra_buffer_data *)&report);
    free_cc_ra_buf(in);
    if (gp_ret != CC_SUCCESS) {
        PrintInfo(PRINT_ERROR, "get ra report failed, ret:%x\n", gp_ret);
        return CC_ERROR_RA_GET_REPORT;
    }

    gp_basevalue_t basevalue = {
        .taid = taid,
        .img_hash = img_hash,
        .mem_hash = mem_hash,
    };
    return gp_verify_local_report(&basevalue, ra_input.nonce, ra_input.nonce_len, &report);
}
