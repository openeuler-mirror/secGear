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

/*
 * Parse Qingtian Attestation Document encoded in CBOR format, adpated from Huawei Cloud Qingtian qtsm.
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <cbor.h>

#include "qt_attestation_api.h"

typedef enum sig_algo sig_params;

static int check_parse_moduleid(const struct cbor_pair cur_map_pair,
                                attestation_document *cur_doc)
{
    if (cur_doc == NULL) {
        return INTERNAL_ERROR;
    }

    if (cbor_typeof(cur_map_pair.key) != CBOR_TYPE_STRING || cbor_typeof(cur_map_pair.value) != CBOR_TYPE_STRING) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_string_is_indefinite(cur_map_pair.key) || cbor_string_is_indefinite(cur_map_pair.value)) {
        return CBOR_DATA_INDEFINITE;
    }

    if (cbor_string_handle(cur_map_pair.key) == NULL || cbor_string_length(cur_map_pair.key) != strlen("module_id") ||
        strncmp((char*)cbor_string_handle(cur_map_pair.key), "module_id", strlen("module_id")) != 0 ||
        cbor_string_length(cur_map_pair.value) <= 0 ||
        cbor_string_length(cur_map_pair.value) >= QTSM_MODULE_ID_MAX_SIZE) {
        return CBOR_CONTENT_ERROR;
    }

    memcpy(cur_doc->doc.module_id, cbor_string_handle(cur_map_pair.value),
        cbor_string_length(cur_map_pair.value));

    return NO_ERROR;
}

static int check_parse_digest(const struct cbor_pair cur_map_pair,
                              const sig_params *condition,
                              attestation_document *cur_doc)
{
    unsigned char *val_str = NULL;

    if (condition == NULL || cur_doc == NULL) {
        return INTERNAL_ERROR;
    }

    if (cbor_typeof(cur_map_pair.key) != CBOR_TYPE_STRING || cbor_typeof(cur_map_pair.value) != CBOR_TYPE_STRING) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_string_is_indefinite(cur_map_pair.key) || cbor_string_is_indefinite(cur_map_pair.value)) {
        return CBOR_DATA_INDEFINITE;
    }

    if (cbor_string_handle(cur_map_pair.key) == NULL || cbor_string_length(cur_map_pair.key) != strlen("digest") ||
        strncmp((char*)cbor_string_handle(cur_map_pair.key), "digest", strlen("digest")) != 0 ||
        cbor_string_length(cur_map_pair.value) <= 0) {
        return CBOR_CONTENT_ERROR;
    }

    val_str = cbor_string_handle(cur_map_pair.value);
    if (val_str == NULL) {
        return CBOR_CONTENT_ERROR;
    }

    switch (*condition) {
        case ECDSA256:
            if (cbor_string_length(cur_map_pair.value) == strlen("SHA256") &&
                strncmp((char*)val_str, "SHA256", strlen("SHA256")) == 0) {
                cur_doc->doc.digest = QTSM_SHA256;
                break;
            }
            return CBOR_CONTENT_ERROR;
        case ECDSA384:
            if (cbor_string_length(cur_map_pair.value) == strlen("SHA384") &&
                strncmp((char*)val_str, "SHA384", strlen("SHA384")) == 0) {
                cur_doc->doc.digest = QTSM_SHA384;
                break;
            }
            return CBOR_CONTENT_ERROR;
        case ECDSA512:
            if (cbor_string_length(cur_map_pair.value) == strlen("SHA512") &&
                strncmp((char*)val_str, "SHA512", strlen("SHA512")) == 0) {
                cur_doc->doc.digest = QTSM_SHA512;
                break;
            }
            return CBOR_CONTENT_ERROR;
        default:
            return CBOR_CONTENT_ERROR;
    }
    return NO_ERROR;
}

static int check_parse_timestamp(const struct cbor_pair cur_map_pair,
                                 attestation_document *cur_doc)
{
    if (cur_doc == NULL) {
        return INTERNAL_ERROR;
    }

    if (cbor_typeof(cur_map_pair.key) != CBOR_TYPE_STRING || cbor_typeof(cur_map_pair.value) != CBOR_TYPE_UINT) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_string_is_indefinite(cur_map_pair.key) || cbor_int_get_width(cur_map_pair.value) != CBOR_INT_64) {
        return CBOR_DATA_INDEFINITE;
    }

    if (cbor_string_handle(cur_map_pair.key) == NULL || cbor_string_length(cur_map_pair.key) != strlen("timestamp") ||
        strncmp((char*)cbor_string_handle(cur_map_pair.key), "timestamp", strlen("timestamp")) != 0 ||
        cbor_get_uint64(cur_map_pair.value) <= 0) {
        return CBOR_CONTENT_ERROR;
    }

    cur_doc->doc.timestamp = cbor_get_uint64(cur_map_pair.value);

    return NO_ERROR;
}

static int check_parse_cur_pcr(const struct cbor_pair cur_map_pair,
                               attestation_document *cur_doc, 
                               size_t idx)
{
    uint16_t cur_idx = 0;
    size_t byte_len = 0;

    if (cur_doc == NULL || idx >= cur_doc->doc.pcrs.pcrs_num) {
        return INTERNAL_ERROR;
    }

    if (cbor_typeof(cur_map_pair.key) != CBOR_TYPE_UINT || cbor_typeof(cur_map_pair.value) != CBOR_TYPE_BYTESTRING) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_bytestring_is_indefinite(cur_map_pair.value)) {
        return CBOR_DATA_INDEFINITE;
    }

    cur_idx = cbor_get_uint16(cur_map_pair.key);
    if (cur_idx >= QTSM_MAX_PCR_COUNT) {
        return CBOR_CONTENT_ERROR;
    }

    byte_len = cbor_bytestring_length(cur_map_pair.value);

    switch (cur_doc->doc.digest) {
        case QTSM_SHA256:
            if (byte_len != SHA256_LEN) {
                return CBOR_CONTENT_ERROR;
            }
            break;
        case QTSM_SHA384:
            if (byte_len != SHA384_LEN) {
                return CBOR_CONTENT_ERROR;
            }
            break;
        case QTSM_SHA512:
            if (byte_len != SHA512_LEN) {
                return CBOR_CONTENT_ERROR;
            }
            break;
        default:
            return CBOR_CONTENT_ERROR;
    }

    cur_doc->doc.pcrs.pcrs[idx].index = cur_idx;
    memcpy(cur_doc->doc.pcrs.pcrs[idx].data,
        cbor_bytestring_handle(cur_map_pair.value), byte_len);

    return NO_ERROR;
}

static int check_parse_pcrs(const struct cbor_pair cur_map_pair,
                            attestation_document *cur_doc)
{
    size_t map_size = 0;
    size_t idx = 0;
    int rc = NO_ERROR;

    if (cur_doc == NULL) {
        return INTERNAL_ERROR;
    }

    if (cbor_typeof(cur_map_pair.key) != CBOR_TYPE_STRING || cbor_typeof(cur_map_pair.value) != CBOR_TYPE_MAP) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_string_is_indefinite(cur_map_pair.key) || cbor_map_is_indefinite(cur_map_pair.value)) {
        return CBOR_DATA_INDEFINITE;
    }

    map_size = cbor_map_size(cur_map_pair.value);

    if (cbor_string_handle(cur_map_pair.key) == NULL || cbor_string_length(cur_map_pair.key) != strlen("pcrs") ||
        strncmp((char*)cbor_string_handle(cur_map_pair.key), "pcrs", strlen("pcrs")) != 0 ||
        map_size > QTSM_MAX_PCR_COUNT) {
        return CBOR_CONTENT_ERROR;
        }

    cur_doc->doc.pcrs.pcrs_num = map_size;

    for (idx = 0; idx < map_size; idx++) {
        rc = check_parse_cur_pcr(cbor_map_handle(cur_map_pair.value)[idx], cur_doc, idx);
        if (rc != NO_ERROR) {
            return CBOR_CONTENT_ERROR;
        }
    }

    return NO_ERROR;
}

static int check_parse_cert(const struct cbor_pair cert_pair,
                            attestation_document *cur_doc)
{
    if (cur_doc == NULL) {
        return INTERNAL_ERROR;
    }
    if (cbor_typeof(cert_pair.key) != CBOR_TYPE_STRING || cbor_typeof(cert_pair.value) != CBOR_TYPE_BYTESTRING) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_string_is_indefinite(cert_pair.key) || cbor_bytestring_is_indefinite(cert_pair.value)) {
        return CBOR_DATA_INDEFINITE;
    }

    if (cbor_string_handle(cert_pair.key) == NULL || cbor_string_length(cert_pair.key) != strlen("certificate") ||
        strncmp((char*)cbor_string_handle(cert_pair.key), "certificate", strlen("certificate")) != 0 ||
        cbor_bytestring_handle(cert_pair.value) == NULL ||
        cbor_bytestring_length(cert_pair.value) > QTSM_CERTIFICATE_MAX_SIZE) {
        return CBOR_CONTENT_ERROR;
    }

    cur_doc->doc.cert_len = cbor_bytestring_length(cert_pair.value);
    memcpy(cur_doc->doc.certificate, cbor_bytestring_handle(cert_pair.value),
        cbor_bytestring_length(cert_pair.value));

    return NO_ERROR;
}

static int check_parse_cabundle(const struct cbor_pair cabundle_pair,
                                attestation_document *cur_doc)
{
    size_t cabundle_array_size = 0;
    unsigned char *cur_str = NULL;
    cbor_item_t *cabundle_item = NULL;
    size_t i = 0;
    int rc = NO_ERROR;

    if (cur_doc == NULL)
        return INTERNAL_ERROR;

    /* Note: the format of ca bundles is different from that of AWS */
    if (cbor_typeof(cabundle_pair.key) != CBOR_TYPE_STRING || cbor_typeof(cabundle_pair.value) != CBOR_TYPE_ARRAY) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_string_is_indefinite(cabundle_pair.key) || cbor_array_is_indefinite(cabundle_pair.value)) {
        return CBOR_DATA_INDEFINITE;
    }

    if (cbor_string_handle(cabundle_pair.key) == NULL || 
        cbor_string_length(cabundle_pair.key) != strlen("cabundle") ||
        strncmp((char*)cbor_string_handle(cabundle_pair.key), "cabundle", strlen("cabundle")) != 0) {
        return CBOR_CONTENT_ERROR;
    }

    cabundle_array_size = cbor_array_size(cabundle_pair.value);
    if (cabundle_array_size > QTSM_CERTIFICATE_MAX_DEPTH) {
        return CBOR_CONTENT_ERROR;
    }

    cur_doc->doc.ca_bundles.ca_bundle_num = cabundle_array_size;
    for (i = 0; i < cabundle_array_size; i++) {
        cabundle_item = cbor_array_handle(cabundle_pair.value)[i];
        if (cabundle_item == NULL) {
            rc = CBOR_CONTENT_ERROR;
            goto error;
        }

        cur_str = cbor_bytestring_handle(cabundle_item);
        if (cur_str == NULL ||
            cbor_bytestring_length(cabundle_item) > QTSM_CERTIFICATE_MAX_SIZE) {
            rc = CBOR_CONTENT_ERROR;
            goto error;
        }

        cur_doc->doc.ca_bundles.cabundles[i].data_len =
            cbor_bytestring_length(cabundle_item);
        memcpy(cur_doc->doc.ca_bundles.cabundles[i].data, cur_str,
            cbor_bytestring_length(cabundle_item));
    }

error:
    if (cabundle_item) {
        cbor_decref(&cabundle_item);
    }
    return rc;
}

/*
 * check_required_fields() - Check if the required fields are present.
 * @cur_item (input) : The cbor-encoded attestation doc.
 * @condition (input) : The signature algorithm and so on.
 * @cur_doc (output) : The actual attestation doc.
 *
 * Context: Validation flow is:
 *         1)module_id : type : string; length : must be non-empty
 *         2)timestamp : type : string; value : sha256, sha384 or sha512
 *         3)digest : must be SHA256 or SHA384 or SHA512
 *         4)pcrs : pcrs.pcrs_num : at least 1 and at most 32
 *                  pcrs.pcrs.index : index can be in this interval [0, 32)
 *         5)certificate : must have length between 1 and 1024
 *         6)ca_bundles : must have length between 1 and 4096
 *         7)user_data_len : must have length between 1 and 512
 *         8)nonce_len : must have length between 1 and 512
 *         9)pubkey_len : must have length between 1 and 1024
 *
 * Returns:
 * * NO_ERROR on success.
 * * Others on failure.
 */
static int check_required_fields(const cbor_item_t *cur_item,
                                 const sig_params *condition,
                                 attestation_document *cur_doc)
{
    uint8_t *temp_data = NULL;
    cbor_item_t *payload_item = NULL;
    struct cbor_load_result result = {0};
    int rc = NO_ERROR;
    int index = 0;

    if (cur_item == NULL || condition == NULL || cur_doc == NULL) {
        return INTERNAL_ERROR;
    }

    if (cbor_typeof(cur_item) != CBOR_TYPE_BYTESTRING) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_bytestring_is_indefinite(cur_item)) {
        return CBOR_DATA_INDEFINITE;
    }

    temp_data = cbor_bytestring_handle(cur_item);
    if (!temp_data) {
        return INTERNAL_ERROR;
    }

    payload_item = cbor_load(temp_data, cbor_bytestring_length(cur_item), &result);
    if (result.error.code != CBOR_ERR_NONE) {
        rc = CBOR_LOAD_ERROR;
        goto error;
    }

    /* make sure map */
    if (cbor_typeof(payload_item) != CBOR_TYPE_MAP) {
        rc = CBOR_TYPE_ERROR;
        goto error;
    }

    /* All field content (moudle_id, timestamp, etc.) can not be null */
    if (cbor_map_size(payload_item) != CBOR_PAYLOAD_MAP_NUM) {
        rc = CBOR_CONTENT_ERROR;
        goto error;
    }
    /* module_id */
    rc = check_parse_moduleid(cbor_map_handle(payload_item)[index++], cur_doc);
    if (rc != NO_ERROR)
        goto error;
    /* timestamp */
    rc = check_parse_timestamp(cbor_map_handle(payload_item)[index++], cur_doc);
    if (rc != NO_ERROR)
        goto error;
    /* digest */
    rc = check_parse_digest(cbor_map_handle(payload_item)[index++],
        condition, cur_doc);
    if (rc != NO_ERROR)
        goto error;
    /* pcrs */
    rc = check_parse_pcrs(cbor_map_handle(payload_item)[index++], cur_doc);
    if (rc != NO_ERROR)
        goto error;
    /* certificate */
    rc = check_parse_cert(cbor_map_handle(payload_item)[index++], cur_doc);
    if (rc != NO_ERROR)
        goto error;
    /* ca bundle */
    rc = check_parse_cabundle(cbor_map_handle(payload_item)[index++], cur_doc);

error:
    if (payload_item)
        cbor_decref(&payload_item);
    return rc;
}

static int parse_protected_header(const cbor_item_t *cur_item,
                                  cbor_item_t **protected_item)
{
    uint8_t *temp_data = NULL;
    struct cbor_load_result result = {0};
    int rc = NO_ERROR;

    if (cbor_typeof(cur_item) != CBOR_TYPE_BYTESTRING) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_bytestring_is_indefinite(cur_item)) {
        return CBOR_DATA_INDEFINITE;
    }

    temp_data = cbor_bytestring_handle(cur_item);
    if (!temp_data) {
        return INTERNAL_ERROR;
    }

    *protected_item = cbor_load(temp_data, cbor_bytestring_length(cur_item), &result);
    if (result.error.code != CBOR_ERR_NONE) {
        rc = CBOR_LOAD_ERROR;
        goto error;
    }

    /* make sure map */
    if (cbor_typeof(*protected_item) != CBOR_TYPE_MAP) {
        rc = CBOR_TYPE_ERROR;
        goto error;
    }

    if (cbor_map_size(*protected_item) != CBOR_PROTECTED_MAP_NUM) {
        rc = CBOR_CONTENT_ERROR;
        goto error;
    }

    rc = NO_ERROR;

error:
    return rc;
}

static int check_parse_protected_header(const cbor_item_t *cur_item,
                                        sig_params *condition)
{
    cbor_item_t *protected_item = NULL;
    struct cbor_pair *cur_map_pair = NULL;
    uint64_t header_label = 0;
    int rc = NO_ERROR;

    if (cur_item == NULL || condition == NULL) {
        return INTERNAL_ERROR;
    }

    rc = parse_protected_header(cur_item, &protected_item);
    if (rc > 0) {
        goto error;
    }

    cur_map_pair = cbor_map_handle(protected_item);
    if (!cur_map_pair) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    if (cbor_typeof(cur_map_pair->key) != CBOR_TYPE_UINT || cbor_typeof(cur_map_pair->value) != CBOR_TYPE_NEGINT) {
        rc = CBOR_TYPE_ERROR;
        goto error;
    }

    /* type: 1 */
    header_label = cbor_get_int(cur_map_pair->key);
    if (header_label != CBOR_LABEL_ALG) {
        rc = CBOR_CONTENT_ERROR;
        goto error;
    }

    /* algo: -35 (ecdsa384) */
    *condition = ~cbor_get_int(cur_map_pair->value);

    /* Note: now only support ecdsa256/ecdsa384/ecdsa512 */
    if (*condition != ECDSA256 && *condition != ECDSA384 && *condition != ECDSA512) {
        rc = CBOR_SIG_ALG_ERROR;
        goto error;
    }

    rc = NO_ERROR;

error:
    if (protected_item) {
        cbor_decref(&protected_item);
    }
    return rc;
}

static int check_parse_unprotected_header(const cbor_item_t *cur_item,
                                          sig_params *condition)
{
    if (cur_item == NULL || condition == NULL) {
        return INTERNAL_ERROR;
    }

    if (cbor_typeof(cur_item) != CBOR_TYPE_MAP) {
        return CBOR_TYPE_ERROR;
    }

    if (cbor_bytestring_is_indefinite(cur_item)) {
        return CBOR_DATA_INDEFINITE;
    }

    /* no item */
    if (cbor_map_size(cur_item) != 0) {
        return CBOR_CONTENT_ERROR;
    }

    return NO_ERROR;
}

/*
 * check_parse_att_doc() - Parse the cbor-en Attestation Document.
 * @cur_item (input): The cbor-en attestation doc.
 * @condition (input): The signature algorithm and so on.
 * @cur_doc (output): The actual attestation doc.
 *
 * Context: Validation flow is:
 *         1)Check if the required fields are present.
 *         2)Verify the certificates chain.
 *
 * Returns:
 * * NO_ERROR on success.
 * * Others on failure.
 */
static int check_parse_att_doc(const cbor_item_t *cur_item,
                               sig_params *condition,
                               attestation_document *cur_doc)
{
    int rc = NO_ERROR;

    if (cur_item == NULL || condition == NULL || cur_doc == NULL) {
        return INTERNAL_ERROR;
    }

    rc = check_required_fields(cur_item, condition, cur_doc);
    if (rc != NO_ERROR) {
        return rc;
    }

    return NO_ERROR;
}

static int check_parse_signature(const cbor_item_t *cur_item,
                                 const sig_params *condition,
                                 attestation_document *cur_doc)
{
    size_t len = 0;
    int rc = NO_ERROR;

    if (cur_item == NULL) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    if (cbor_typeof(cur_item) != CBOR_TYPE_BYTESTRING) {
        rc = CBOR_TYPE_ERROR;
        goto error;
    }

    if (cbor_bytestring_is_indefinite(cur_item)) {
        rc = CBOR_DATA_INDEFINITE;
        goto error;
    }

    len = cbor_bytestring_length(cur_item);
    if ((*condition == ECDSA256 && len != (SHA256_LEN << 1)) ||
        (*condition == ECDSA384 && len != (SHA384_LEN << 1)) ||
        (*condition == ECDSA512 && len != (SHA512_LEN << 1))) {
        rc = CBOR_CONTENT_ERROR;
        goto error;
    }
    
    memcpy(cur_doc->signature, cbor_bytestring_handle(cur_item), len);

error:
    return rc;
}

/*
 * build_signature_message() - Build a Sig_structure
 * @protected_item (input): The protected header encoded in a bstr type.
 * @payload_item (input): The attestation doc encoded in a bstr type.
 * @signature_message (output): The well-defined byte stream.
 * @sig_message_len (output): The length of signature message.
 *
 * Context: The Sig_structure is:
 *          1)context: "Signature1"
 *          2)body_protected: protected header
 *          3)external_add: bstr (defaults to zero,
 *              which is not carried as part of the COSE object)
 *          4)payload: protected payload (attestation doc)
 *
 * Returns:
 * * NO_ERROR on success.
 * * Others on failure.
 */
static int build_signature_message(cbor_item_t *protected_item,
                                   cbor_item_t *payload_item,
                                   unsigned char **signature_message,
                                   size_t *sig_message_len)
{
    cbor_item_t *msg_root = NULL;
    cbor_item_t *context_item = NULL;
    cbor_item_t *external_add_item = NULL;
    size_t buffer_size;
    bool rst;
    int rc = NO_ERROR;
    int index = 0;

    if (protected_item == NULL || payload_item == NULL) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    msg_root = cbor_new_definite_array(CBOR_DOC_ITEM_NUM);
    if (msg_root == NULL) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    context_item = cbor_build_string("Signature1");
    if (context_item == NULL) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    rst = cbor_array_set(msg_root, index++, cbor_move(context_item));
    if (rst != true) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    rst = cbor_array_set(msg_root, index++, protected_item);
    if (rst != true) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    external_add_item = cbor_new_definite_bytestring();
    if (external_add_item == NULL) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    rst = cbor_array_set(msg_root, index++, cbor_move(external_add_item));
    if (rst != true) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    rst = cbor_array_set(msg_root, index++, payload_item);
    if (rst != true) {
        rc = INTERNAL_ERROR;
        goto error;
    }

    *sig_message_len = cbor_serialize_alloc(msg_root, signature_message, &buffer_size);
    if (*sig_message_len == 0) {
        rc = INTERNAL_ERROR;
        goto error;
    }

error:
    if (context_item) {
        cbor_decref(&context_item);
    }
    if (external_add_item) {
        cbor_decref(&external_add_item);
    }
    if (msg_root) {
        cbor_decref(&msg_root);
    }
    return rc;
}

/*
 * parse_cboren_doc() - Parse the cbor-encoded attestation doc.
 * @att_doc (input): The cbor-encoded attestation doc.
 * @cur_doc (output): The cbor-decoded attestation doc.
 * @sig_msg (output): The signature message of cbor-encoded attestation doc.
 * @sig_msg_len (output): The length of the signature message.
 *
 * Context: COSE_Sign1 structure is
 *          protected parameters : Header
 *          unprotected parameters : Header
 *          payload : Attestation Document
 *          signature : Signature
 *
 * Returns:
 * * NO_ERROR on success.
 * * Others on failure.
 */
int parse_cboren_doc(const uint8_t *doc_cose, 
                     const uint32_t doc_len,
                     attestation_document *cur_doc, 
                     unsigned char** sig_msg, 
                     size_t *sig_msg_len)
{
    cbor_item_t *doc_root_item = NULL;
    cbor_item_t *hdr_prot_item = NULL;
    cbor_item_t *hdr_unprot_item = NULL;
    cbor_item_t *payload_item = NULL;
    cbor_item_t **cbor_array_item = NULL;
    cbor_item_t *sign_item = NULL;
    struct cbor_load_result result = {0};
    sig_params condition = 0;
    uint64_t tag_value;
    int rc = NO_ERROR;
    int index = 0;

    if (doc_cose == NULL || doc_len == 0 || sig_msg_len == NULL) {
        return CBOR_INVALID_PARAM;
    }

    doc_root_item = cbor_load(doc_cose, doc_len, &result);
    if (result.error.code != CBOR_ERR_NONE) {
        printf("result.error.code is %d\n", result.error.code);
        rc = CBOR_LOAD_ERROR;
        goto err;
    }

    /* Todo: Tag is array or cose_sign1 (untagged or tagged),
     * both are parsed according to COSE_Sign1 structure.
     */
    tag_value = cbor_tag_value(doc_root_item);
    if (tag_value != CBOR_COSE_SIGN1_TAG && tag_value != CBOR_ARRAY_TAG) {
        return CBOR_TAG_ERROR;
    }
    /* The type, tag etc. */
    if (cbor_typeof(doc_root_item) != CBOR_TYPE_ARRAY || !cbor_array_is_definite(doc_root_item)) {
        rc = CBOR_TYPE_ERROR;
        goto err;
    }

    if (cbor_array_size(doc_root_item) != CBOR_DOC_ITEM_NUM) {
        rc = CBOR_CONTENT_ERROR;
        goto err;
    }
    /* Read the array out, index must not exceed CBOR_DOC_ITEM_NUM */
    cbor_array_item = cbor_array_handle(doc_root_item);
    if (cbor_array_item == NULL) {
        rc = CBOR_CONTENT_ERROR;
        goto err;
    }
    /* The protected parameters */
    hdr_prot_item = cbor_array_item[index++];
    rc = check_parse_protected_header(hdr_prot_item, &condition);
    if (rc != NO_ERROR) {
        goto err;
    }
    /* The unprotected parameters */
    hdr_unprot_item = cbor_array_item[index++];
    rc = check_parse_unprotected_header(hdr_unprot_item, &condition);
    if (rc != NO_ERROR) {
        goto err;
    }
    /* The payload, i.e. doc */
    payload_item = cbor_array_item[index++];
    rc = check_parse_att_doc(payload_item, &condition, cur_doc);
    if (rc != NO_ERROR) {
        goto err;
    }
    /* The signature */
    sign_item = cbor_array_item[index++];
    rc = check_parse_signature(sign_item, &condition, cur_doc);

    /* build signature */
    rc = build_signature_message(hdr_prot_item, payload_item,
            sig_msg, sig_msg_len);

err:
    if (doc_root_item) {
        cbor_decref(&doc_root_item);
    }
    if (sign_item) {
        cbor_decref(&sign_item);
    }
    if (payload_item) {
        cbor_decref(&payload_item);
    }
    if (hdr_unprot_item) {
        cbor_decref(&hdr_unprot_item);
    }
    if (hdr_prot_item) {
        cbor_decref(&hdr_prot_item);
    }
    return rc;
}
