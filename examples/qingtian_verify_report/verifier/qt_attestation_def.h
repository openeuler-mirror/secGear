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
 * QTSM LIB data structure definitions, imported from Huawei Cloud qtsm.
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef _QT_ATTESTATION_DEF_H
#define _QT_ATTESTATION_DEF_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QTSM_PCR_MAX_LENGTH             64
#define QTSM_MAX_PCR_COUNT              32
#define QTSM_MODULE_ID_MAX_SIZE         128
#define QTSM_CERTIFICATE_MAX_SIZE       4096
#define QTSM_CERTIFICATE_MAX_DEPTH      4
#define QTSM_PUBLIC_KEY_MAX_SIZE        1024
#define QTSM_USER_DATA_MAX_SIZE         512
#define QTSM_NONCE_MAX_SIZE             512
#define QTSM_SIGNATURE_MAX_SIZE         128

#define CBOR_DOC_ITEM_NUM               4
#define CBOR_PROTECTED_MAP_NUM          1
#define CBOR_PAYLOAD_MAP_NUM            9

/* Signature */
#define CBOR_LABEL_ALG                  1

#define MAX_QT_VALIDATION_PERIOD 15*60*1000 // 15-min

enum error_code {
    NO_ERROR = 0,
    INVALID_INDEX = 1,
    INVALID_RESPONSE = 2,
    INVALID_ARGUMENT = 3,
    READ_ONLY_INDEX = 4,
    INVALID_OPERATION = 5,
    BUFFER_TOO_SMALL = 6,
    INPUT_TOO_LARGE = 7,
    INTERNAL_ERROR = 8,
    INVALID_QTSM_CERT = 9,
};

enum cbor_errcode {
    CBOR_INVALID_PARAM = 20,
    CBOR_TAG_ERROR = 21,
    COBR_TIMESTAMP_ERROR = 22,
    CBOR_SIG_ALG_ERROR = 23,
    CBOR_LOAD_ERROR = 24,
    CBOR_TYPE_ERROR = 25,
    CBOR_CONTENT_ERROR = 26,
    CBOR_DATA_INDEFINITE = 27,
    CBOR_CERT_ERROR = 28,
    CBOR_CABUNDLES_ERROR = 29,
    CBOR_CERT_VRY_ERROR = 30,
    CBOR_CERT_PUBKEY_ERROR = 31,
    CBOR_SIG_ERROR = 32,
};

enum digest_alg {
    QTSM_SHA256 = 0,
    QTSM_SHA384 = 1,
    QTSM_SHA512 = 2,
};

/* CBOR Tag */
enum cbor_tags {
    CBOR_ARRAY_TAG = 4,
    CBOR_COSE_SIGN1_TAG = 18,
};

/* Ref: rfc8152#setion-8.1 */
enum sig_algo {
    /* ECDSA w/ SHA-256 */
    ECDSA256 = -7,
    /* ECDSA w/ SHA-384 */
    ECDSA384 = -35,
    /* ECDSA w/ SHA-512 */
    ECDSA512 = -36,
};

enum sha_len {
    SHA256_LEN = 32,
    SHA384_LEN = 48,
    SHA512_LEN = 64,
};

struct pcr_raw {
    uint16_t index;
    uint8_t data[QTSM_PCR_MAX_LENGTH];
};
typedef struct pcr_raw pcr_raw;

struct pcr_raws {
    uint32_t pcrs_num;
    struct pcr_raw pcrs[QTSM_MAX_PCR_COUNT];
};
typedef struct pcr_raws pcr_raws;

struct cabundle_raw {
    uint32_t data_len;
    uint8_t data[QTSM_CERTIFICATE_MAX_SIZE];
};
typedef struct cabundle_raw cabundle_raw;

struct cabundles_raws {
    uint32_t ca_bundle_num;
    struct cabundle_raw cabundles[QTSM_CERTIFICATE_MAX_DEPTH];
};
typedef struct cabundles_raws cabundles_raws;

struct attestation_doc {
    char module_id[QTSM_MODULE_ID_MAX_SIZE];
    uint64_t timestamp;
    enum digest_alg digest;
    struct pcr_raws pcrs;
    uint32_t cert_len;
    uint8_t certificate[QTSM_CERTIFICATE_MAX_SIZE];
    struct cabundles_raws ca_bundles;
    uint32_t user_data_len;
    uint8_t user_data[QTSM_USER_DATA_MAX_SIZE];
    uint32_t nonce_len;
    uint8_t nonce[QTSM_NONCE_MAX_SIZE];
    uint32_t pubkey_len;
    uint8_t pubkey[QTSM_PUBLIC_KEY_MAX_SIZE];
};
typedef struct attestation_doc attestation_doc;

struct attestation_document {
    struct attestation_doc doc;
    uint8_t signature[QTSM_SIGNATURE_MAX_SIZE];
};
typedef struct attestation_document attestation_document;

struct describe_qtsm {
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t version_patch;
    uint32_t module_id_len;
    char module_id[QTSM_MODULE_ID_MAX_SIZE];
    uint16_t max_pcrs;
    uint32_t locked_pcrs_num;
    uint16_t locked_pcrs[QTSM_MAX_PCR_COUNT];
    enum digest_alg digest;
};
typedef struct describe_qtsm describe_qtsm;

#ifdef __cplusplus
}
#endif

#endif
