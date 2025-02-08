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

#ifndef RA_TLS_H_
#define RA_TLS_H_

#ifndef __cplusplus
#include <stdbool.h>
#endif
#if defined(USE_OPENSSL)
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#elif defined(USE_MBEDTLS)
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#endif
#include "ra_tls_imp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // attestation agent listen address
    char *aa_addr;
    char *uuid;
    ra_mode mode;
}ra_cfg;

#define CHALLENGE_LEN   64
#define HASH_LEN        32
#define HASH_OFFSET     32
#define PUBLIC_KEY_HASH_PRINT_LEN (4 * HASH_LEN)
#define EXTENSION_EXPIRED_OFFSET_SECONDS (5)

int ra_tls_generate_certificate(ra_tls_buf *cert, ra_tls_buf *private_key, ra_cfg *cfg_ra, key_size size);
// set attestation agent address, addr is ip:port or domain:port
int ra_tls_set_addr(char *addr);
// cert is DER-encoded
bool ra_tls_cert_extension_expired(ra_tls_buf *cert);

#if defined(USE_OPENSSL)
// return 0 failed, 1 ok
int ra_tls_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
#elif defined(USE_MBEDTLS)
// return 0 ok, or failed result
int ra_tls_verify_callback(void *data, mbedtls_509_crt *crt, int depth, uint32_t *flasgs);
#endif

#ifdef __cplusplus
}
#endif

#endif