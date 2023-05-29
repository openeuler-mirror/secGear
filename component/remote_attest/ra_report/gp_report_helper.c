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
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "base64url.h"
#include "gp_report_helper.h"

void free_cc_ra_buf(cc_ra_buf_t *ra_buf)
{
    if (ra_buf == NULL) {
        return;
    }
    if (ra_buf->buf != NULL) {
        free(ra_buf->buf);
    }

    free(ra_buf);
    return;
}

/* caller need to free (cc_ra_buf_t **in) */
cc_enclave_result_t gen_provision_no_as_in_buff(cc_ra_buf_t **in)
{
    if (in == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    cc_enclave_result_t ret = CC_SUCCESS;
    cJSON *in_json = cJSON_CreateObject();
    cJSON_AddStringToObject(in_json, "handler", "provisioning-input");

    cJSON *in_payload = cJSON_CreateObject();
    cJSON_AddStringToObject(in_payload, "version", "TEE.RA.1.0");
    cJSON_AddStringToObject(in_payload, "scenario", "sce_no_as");
    cJSON_AddStringToObject(in_payload, "hash_alg", "HS256");

    cJSON_AddItemToObject(in_json, "payload", in_payload);

    char *in_buf = cJSON_PrintUnformatted(in_json);
    uint32_t in_buf_len = strlen(in_buf) + 1;

    cc_ra_buf_t *tmp_ra_buf = calloc(1, sizeof(cc_ra_buf_t));
    if (tmp_ra_buf == NULL) {
        ret = CC_ERROR_RA_MEMORY;
        goto end;
    }
    tmp_ra_buf->buf = calloc(1, in_buf_len);
    if (tmp_ra_buf->buf == NULL) {
        ret = CC_ERROR_RA_MEMORY;
        free(tmp_ra_buf);
        goto end;
    }
    (void)memcpy(tmp_ra_buf->buf, in_buf, in_buf_len);
    tmp_ra_buf->len = in_buf_len;

    *in = tmp_ra_buf;
end:
    cJSON_free(in_buf);
    cJSON_Delete(in_json);
    return ret;
}

/* caller need to free (cc_ra_buf_t **in) */
cc_enclave_result_t gen_ra_report_in_buff(cc_get_ra_report_input_t *param, cc_ra_buf_t **json_buf)
{
    if (param == NULL || param->taid == NULL || json_buf == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    cc_enclave_result_t ret = CC_SUCCESS;
    cJSON *in_json = cJSON_CreateObject();
    cJSON_AddStringToObject(in_json, "handler", "report-input");

    size_t b64_nonce_len = 0;
    char *b64_nonce = kpsecl_base64urlencode(param->nonce, param->nonce_len, &b64_nonce_len);

    cJSON *in_payload = cJSON_CreateObject();
    cJSON_AddStringToObject(in_payload, "version", "TEE.RA.1.0");
    cJSON_AddStringToObject(in_payload, "nonce", b64_nonce);
    free(b64_nonce);
    cJSON_AddStringToObject(in_payload, "uuid", (char *)param->taid);
    cJSON_AddStringToObject(in_payload, "hash_alg", "HS256");
    cJSON_AddBoolToObject(in_payload, "with_tcb", param->with_tcb);
    if (param->req_key) {
        cJSON_AddBoolToObject(in_payload, "request_key", param->req_key);
    }

    cJSON_AddItemToObject(in_json, "payload", in_payload);

    char *in_buf = cJSON_PrintUnformatted(in_json);
    uint32_t in_buf_len = strlen(in_buf) + 1;

    cc_ra_buf_t *tmp_ra_buf = calloc(1, sizeof(cc_ra_buf_t));
    if (tmp_ra_buf == NULL) {
        ret = CC_ERROR_RA_MEMORY;
        goto end;
    }
    tmp_ra_buf->buf = calloc(1, in_buf_len);
    if (tmp_ra_buf->buf == NULL) {
        ret = CC_ERROR_RA_MEMORY;
        free(tmp_ra_buf);
        goto end;
    }
    (void)memcpy(tmp_ra_buf->buf, in_buf, in_buf_len);
    tmp_ra_buf->len = in_buf_len;

    *json_buf = (cc_ra_buf_t *)tmp_ra_buf;
end:
    cJSON_free(in_buf);
    cJSON_Delete(in_json);
    return ret;
}

