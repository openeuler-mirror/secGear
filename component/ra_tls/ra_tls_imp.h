/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef RA_TLS_IMP_H_
#define RA_TLS_IMP_H_
#include <stdint.h>
#include <stddef.h>
#if defined(USE_OPENSSL)
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#else
    #error TLS library Must be specified
#endif

#ifdef __cplusplus
extern "C" {
#endif

// todo register oid
#define EVIDENCE_OID    "1.3.6.1.4.1.2011.2.8"
#define TOKEN_OID       "1.3.6.1.4.1.2011.2.10"

#define KEY_SIZE_MAX (3072)
#define DEFAULT_CERT_LIFETIME_YEARS (1)

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t filled;
} ra_tls_buf;

typedef enum key_size_t {
    RSA_2048,
    RSA_3072
} key_size;

typedef enum key_type_t {
    KEY_PUBLIC,
    KEY_PRIVATE
} key_type;

typedef enum hash_type_t {
    SHA_256,
    SHA_512
} hash_type;

typedef enum ra_mode_t {
    BACKGROUND,
    PASSPORT
} ra_mode;

typedef struct {
    ra_tls_buf prv_key;
    ra_tls_buf pub_key;
    char *subject_name;
    char *issuer_name;
    char *not_before; // format:YYYYMMDDHHMMSSZ
    char *not_after;  // format:YYYYMMDDHHMMSSZ
    const char *ext_oid;
    ra_tls_buf ext;
} cert_config;

#define RA_TLS_BUF_INIT {NULL, 0, 0}
int ra_tls_buf_init(ra_tls_buf *buf, int len);
void ra_tls_buf_free(ra_tls_buf *buf);

int get_hash(ra_tls_buf *hash, ra_tls_buf *input, hash_type type);
int generate_key_pair_der(key_size key_len, ra_tls_buf *public_key, ra_tls_buf *private_key);
// generate pem certificate，use evidence filled extension specified by oid
int generate_certificate_with_extension(ra_tls_buf *cert, ra_tls_buf *evidence, ra_tls_buf *public_key,
    ra_tls_buf *private_key, const char *oid);

#if defined(USE_OPENSSL)
/*
    get extension by oid (EVIDENCE_OID or TOKEN_OID) in certificate
    cert_ctx associate with library, it may be a runtime context
*/
int get_extension_from_certificate_context(ra_tls_buf *ext_buf, ra_tls_buf *oid, void *cert_ctx);
int get_public_key_from_certificate_context(ra_tls_buf *key_der, void *cert_ctx);
int get_extension_from_certificate_der(ra_tls_buf *ext_buf, ra_tls_buf *oid, ra_tls_buf *cert_der);
#endif

#ifdef __cplusplus
}
#endif

#endif
