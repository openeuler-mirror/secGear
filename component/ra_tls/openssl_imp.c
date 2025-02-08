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
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "ra_tls_imp.h"

#define OID_LEN_MAX         64
#define CERT_TIME_STR_LEN   17
#define RSA_PRIVATE_KEY_BITS_2048   2048
#define RSA_PRIVATE_KEY_BITS_3072   3072
#define RSA_PRIVATE_KEY_BUF_2048    2048
#define RSA_PRIVATE_KEY_BUF_3072    3072
#define RSA_PUB_KEY_BUF_2048        512
#define RSA_PUB_KEY_BUF_3072        650

#define ERR_CHECK(CONDITION, RESULT, ERRNO, GOTO_ERR, PREFIX) do { \
    if ((CONDITION)) { \
        RESULT = ERRNO; \
        printf("%s:%d, %s: %s", __FILE__, __LINE__, PREFIX, ERR_reason_error_string(ERR_get_error())); \
        goto GOTO_ERR; \
    } \
} while (0)

const size_t MIN_CERTIFICATE_SIZE = 4096;

int ra_tls_buf_init(ra_tls_buf *buf, int len)
{
    if (buf == NULL || len < 0) {
        return -1;
    }
    if (len == 0) {
        buf->buf = NULL;
        buf->len = 0;
        buf->filled = 0;
        return 0;
    }
    buf->buf = malloc(len);
    if (buf->buf == NULL) {
        return -1;
    }
    memset(buf->buf, 0, len);
    buf->len = len;
    buf->filled = 0;
    return len;
}

void ra_tls_buf_free(ra_tls_buf *buf)
{
    if (buf == NULL) {
        return;
    }
    if (buf->buf) {
        free(buf->buf);
        buf->buf = NULL;
    }
    buf->len = 0;
    buf->filled = 0;
}

static int generate_pkey_rsa(EVP_PKEY *pk, key_size key_len)
{
    int ret = -1;
    int key_bits = 0;
    if (pk == NULL) {
        return ret;
    }
    EVP_PKEY_CTX *ctx = NULL;
    if (key_len == RSA_2048) {
        key_bits = RSA_PRIVATE_KEY_BITS_2048;
    } else if (key_len == RSA_3072) {
        key_bits = RSA_PRIVATE_KEY_BITS_3072;
    } else {
        printf("unknown key length:%d\n", key_len);
        return ret;
    }
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        return ret;
    }
    int res = EVP_PKEY_keygen_init(ctx);
    if (res <= 0) {
        printf("key generate failed (%d)\n", res);
        ret = -1;
        goto done;
    }

    res = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits);
    if (res <= 0) {
        printf("set_rsa_kengen_bits failed (%d)\n", res);
        ret = -1;
        goto done;
    }
    res = EVP_PKEY_keygen(ctx, &pk);
    if (res <= 0) {
        printf("keygen failed (%d)\n", res);
        ret = -1;
        goto done;
    }
    ret = 0;
done:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}

// type = 0, 公钥，=1 私钥
static int read_key(EVP_PKEY *pkey, key_type type, ra_tls_buf *key)
{
    BIO *bio = NULL;
    int ret = -1;
    int res;
    if (pkey == NULL) {
        return ret;
    }
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        printf("bio new failed");
        return ret;
    }
    if (type == KEY_PUBLIC) {
        ret = i2d_PUBKEY_bio(bio, pkey);
    } else if (type == KEY_PRIVATE) {
        ret = i2d_PrivateKey_bio(bio, pkey);
    } else {
        printf("unknown key type\n");
        ret = -1;
    }
    res = BIO_read(bio, key->buf, key->len);
    if (res > 0) {
        ret = 0;
        key->filled = res;
    }
    if (bio) {
        BIO_free(bio);
    }
    bio = NULL;
    return ret;
}

static X509_NAME *create_x509_name(const char *country_name, const char *org, const char *comm_name)
{
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)country_name, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)org, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)comm_name, -1, -1, 0);
    return name;
}

static int set_public_key(X509 *cert, ra_tls_buf *pub_key)
{
    int ret = -1;
    int res = 0;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    pkey = EVP_PKEY_new();
    ERR_CHECK(pkey == NULL, ret, -1, err, "new public key error");
    bio = BIO_new_mem_buf((const void*)pub_key->buf, (int)pub_key->filled);
    ERR_CHECK(bio == NULL, ret, -1, err, "bio new error");
    EVP_PKEY *key = d2i_PUBKEY_bio(bio, &pkey);
    ERR_CHECK(key == NULL, ret, -1, err, "read public key error");
    res = X509_set_pubkey(cert, pkey);
    ERR_CHECK(res == 0, ret, -1, err, "set x509 public key error");
    ret = 0;
err:
    if (bio) {
        BIO_free(bio);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return ret;
}

static int sign_cert(X509 *cert, ra_tls_buf *prv_key)
{
    int ret = -1;
    int res = 0;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    pkey = EVP_PKEY_new();
    ERR_CHECK(pkey == NULL, ret, -1, err, "new private key error");
    bio = BIO_new_mem_buf((const void*)prv_key->buf, (int)prv_key->filled);
    ERR_CHECK(bio == NULL, ret, -1, err, "bio new error");
    EVP_PKEY *key = d2i_PrivateKey_bio(bio, &pkey);
    ERR_CHECK(key == NULL, ret, -1, err, "read private key error");
    res = X509_sign(cert, pkey, EVP_sha256());
    ERR_CHECK(res == 0, ret, -1, err, "sign error");
    ret = 0;
err:
    if (bio) {
        BIO_free(bio);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return ret;
}

static int set_subject(X509 *cert)
{
    int ret = -1;
    int res = 0;
    X509_NAME *name = NULL;
    name = create_x509_name("ZH", "Huawei Corporation", "VirtCCA Enclave");
    ERR_CHECK(name == NULL, ret, -1, err, "create subject name error");
    res = X509_set_subject_name(cert, name);
    ERR_CHECK(res == 0, ret, -1, err, "set x509 subject name error");
    ret = 0;
err:
    if (name) {
        X509_NAME_free(name);
    }
    return ret;
}

static int set_issuer(X509 *cert)
{
    int ret = -1;
    int res = 0;
    X509_NAME *name = NULL;
    name = create_x509_name("ZH", "Huawei Corporation", "VirtCCA Enclave");
    ERR_CHECK(name == NULL, ret, -1, err, "create issuer name error");
    res = X509_set_issuer_name(cert, name);
    ERR_CHECK(res == 0, ret, -1, err, "set x509 issuer name error");
    ret = 0;
err:
    if (name) {
        X509_NAME_free(name);
    }
    return ret;
}

static int set_extension(X509 *cert, cert_config *cfg)
{
    int res = 0;
    int ret = -1;
    X509V3_CTX ctx;
    ASN1_OBJECT *obj = NULL;
    ASN1_OCTET_STRING *data = NULL;
    X509_EXTENSION *ext = NULL;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    // set extension
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    res = X509_add_ext(cert, ext, -1);
    ERR_CHECK(res == 0, ret, -1, err, "x509 add basic constraints error");
    X509_EXTENSION_free(ext);
    ext = NULL;

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    res = X509_add_ext(cert, ext, -1);
    ERR_CHECK(res == 0, ret, -1, err, "x509 add subject key identifier error");
    X509_EXTENSION_free(ext);
    ext = NULL;

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always");
    res = X509_add_ext(cert, ext, -1);
    ERR_CHECK(res == 0, ret, -1, err, "x509 add authority key identifier error");
    X509_EXTENSION_free(ext);
    ext = NULL;

    // add extension evidence
    obj = OBJ_txt2obj(cfg->ext_oid, 1);
    ERR_CHECK(obj == NULL, ret, -1, err, "create asn1 obj error");
    data = ASN1_OCTET_STRING_new();
    ERR_CHECK(data == NULL, ret, -1, err, "create asn1 string error");
    res = ASN1_OCTET_STRING_set(data, cfg->ext.buf, strlen((const char *)cfg->ext.buf));
    ERR_CHECK(res == 0, ret, -1, err, "asn1 set string error");
    ext = X509_EXTENSION_create_by_OBJ(&ext, obj, 0, data);
    ERR_CHECK(ext == NULL, ret, -1, err, "create x509 extension error");
    res = X509_add_ext(cert, ext, -1);
    ERR_CHECK(res == 0, ret, -1, err, "x509 add evidence error");
    ret = 0;
err:
    if (ext) {
        X509_EXTENSION_free(ext);
    }
    if (data) {
        ASN1_OCTET_STRING_free(data);
    }
    if (obj) {
        ASN1_OBJECT_free(obj);
    }
    return ret;
}

static int output_certificate_der(ra_tls_buf *output, X509 *cert)
{
    int ret = -1;
    int res = 0;
    BIO *bio = NULL;
    bio = BIO_new(BIO_s_mem());
    ERR_CHECK(bio == NULL, ret, -1, err, "bio new failed");
    ERR_clear_error();
    res = i2d_X509_bio(bio, cert);
    ERR_CHECK(res == 0, ret, -1, err, "output certificate to bio error");
    res = BIO_read(bio, output->buf, output->len);
    ERR_CHECK(res <= 0, ret, -1, err, "read cert from bio error");
    output->filled = res;
    ret = 0;
    goto end;
err:
    ra_tls_buf_free(output);
end:
    if (bio) {
        BIO_free(bio);
    }
    return ret;
}

static int generate_x509_self_signed_certificate(ra_tls_buf *output_cert, cert_config *cfg)
{
    int res = 0;
    int ret = -1;
    const int x509_ver = 2; // 2 means X509 Version 3
    X509 *x509cert = NULL;
    if (output_cert == NULL || cfg == NULL) {
        return ret;
    }
    ERR_load_crypto_strings();
    OPENSSL_init_crypto(0, NULL);
    // certificate version 3
    x509cert = X509_new();
    res = X509_set_version(x509cert, x509_ver);
    ERR_CHECK(res == 0, ret, -1, err, "set x509 version error");
    ret = set_public_key(x509cert, &(cfg->pub_key));
    ERR_CHECK(res < 0, ret, -1, err, "set x509 public key error");
    res = set_subject(x509cert);
    ERR_CHECK(res < 0, ret, -1, err, "set x509 subject name error");
    res = set_issuer(x509cert);
    ERR_CHECK(res < 0, ret, -1, err, "set x509 issuer name error");

    // set serial number
    res = ASN1_INTEGER_set(X509_get_serialNumber(x509cert), 1);
    ERR_CHECK(res == 0, ret, -1, err, "set x509 serial number error");

    // set date
    res = ASN1_TIME_set_string(X509_getm_notBefore(x509cert), cfg->not_before);
    ERR_CHECK(res == 0, ret, -1, err, "set x509 not before error");
    res = ASN1_TIME_set_string(X509_getm_notAfter(x509cert), cfg->not_after);
    ERR_CHECK(res == 0, ret, -1, err, "set x509 not after error");

    // set extension
    res = set_extension(x509cert, cfg);
    ERR_CHECK(res < 0, ret, -1, err, "set x509 extension error");
    // sign certificate
    res = sign_cert(x509cert, &(cfg->prv_key));
    ERR_CHECK(res < 0, ret, -1, err, "sign error");
    // output certificate
    res = ra_tls_buf_init(output_cert, cfg->pub_key.len + cfg->ext.len + MIN_CERTIFICATE_SIZE);
    ERR_CHECK(res <= 0, ret, -1, err, "init buffer failed");
    res = output_certificate_der(output_cert, x509cert);
    ERR_CHECK(res < 0, ret, -1, err, "output certificate failed");
    ret = 0;
err:
    if (x509cert) {
        X509_free(x509cert);
    }
    return ret;
}

static int openssl_generate_certificate_with_extension(ra_tls_buf *cert, ra_tls_buf *ext,
    ra_tls_buf *public_key, ra_tls_buf *private_key, const char *oid)
{
    int res = 0;
    int ret = -1;
    char not_before[CERT_TIME_STR_LEN] = {0};
    char not_after[CERT_TIME_STR_LEN] = {0};
    // fill config and generate certificate
    if (cert == NULL || ext == NULL || public_key == NULL || private_key == NULL || oid == NULL) {
        return ret;
    }
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    res = strftime(not_before, CERT_TIME_STR_LEN, "%Y%m%d%H%M%SZ", tm);
    if (!res) {
        return ret;
    }
    tm->tm_year += DEFAULT_CERT_LIFETIME_YEARS;
    res = strftime(not_after, CERT_TIME_STR_LEN, "%Y%m%d%H%M%SZ", tm);
    if (!res) {
        return ret;
    }
    cert_config cert_cfg;
    cert_cfg.prv_key = *private_key;
    cert_cfg.pub_key = *public_key;
    cert_cfg.not_before = not_before;
    cert_cfg.not_after = not_after;
    cert_cfg.ext_oid = oid;
    cert_cfg.ext = *ext;
    res = generate_x509_self_signed_certificate(cert, &cert_cfg);
    if (res >= 0) {
        ret = 0;
    }
    return ret;
}

static int init_key_buffer(key_size key_len, ra_tls_buf *public_key, ra_tls_buf *private_key)
{
    int ret = -1;
    int pub_len = 0;
    int prv_len = 0;
    if (key_len == RSA_2048) {
        pub_len = RSA_PUB_KEY_BUF_2048;
        prv_len = RSA_PRIVATE_KEY_BUF_2048;
    } else if (key_len == RSA_3072) {
        pub_len = RSA_PUB_KEY_BUF_3072;
        prv_len = RSA_PRIVATE_KEY_BUF_3072;
    } else {
        printf("unknown key length\n");
        return -1;
    }
    if (ra_tls_buf_init(public_key, pub_len) < 0) {
        ret = -1;
        goto err;
    }
    if (ra_tls_buf_init(private_key, prv_len) < 0) {
        ret = -1;
        goto err;
    }
    ret = 0;
    return ret;
err:
    ra_tls_buf_free(public_key);
    ra_tls_buf_free(private_key);
    return ret;
}

static int get_sha256(ra_tls_buf* hash, ra_tls_buf* input)
{
    int res = 0;
    int ret = -1;
    unsigned int hash_len;
    EVP_MD_CTX *md_ctx;
    if (hash == NULL || input == NULL) {
        return ret;
    }
    md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        goto err;
    }
    EVP_DigestUpdate(md_ctx, input->buf, input->filled);
    ra_tls_buf_init(hash, EVP_MAX_MD_SIZE);
    hash_len = EVP_MAX_MD_SIZE;
    res = EVP_DigestFinal_ex(md_ctx, hash->buf, &hash_len);
    if (res <= 0) {
        ret = -1;
        goto err;
    }
    hash->filled = hash_len;
    ret = 0;
    goto end;
err:
    ra_tls_buf_free(hash);
end:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret;
}

int generate_key_pair_der(key_size key_len, ra_tls_buf *public_key, ra_tls_buf *private_key)
{
    int res;
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    ra_tls_buf pub_key = RA_TLS_BUF_INIT;
    ra_tls_buf prv_key = RA_TLS_BUF_INIT;
    if (public_key == NULL || private_key == NULL) {
        return ret;
    }
    res = init_key_buffer(key_len, &pub_key, &prv_key);
    if (res < 0) {
        return -1;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        printf("EVP_PKEY_new return NULL\n");
        return ret;
    }
    res = generate_pkey_rsa(pkey, key_len);
    if (res < 0) {
        printf("generate rsa key failed\n");
        ret = -1;
        goto err;
    }
    res = read_key(pkey, KEY_PUBLIC, &pub_key);
    if (res < 0) {
        printf("read public key failed\n");
        ret = -1;
        goto err;
    }
    res = read_key(pkey, KEY_PRIVATE, &prv_key);
    if (res < 0) {
        printf("read private key failed\n");
        ret = -1;
        goto err;
    }
    *public_key = pub_key;
    *private_key = prv_key;
    ret = 0;
err:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return ret;
}

int get_hash(ra_tls_buf *hash, ra_tls_buf *input, hash_type type)
{
    switch (type) {
        case SHA_256:
            get_sha256(hash, input);
            break;
        default:
            printf("unknown hash type\n");
            return -1;
    }
    return 0;
}

int generate_certificate_with_extension(ra_tls_buf *cert, ra_tls_buf *extension, ra_tls_buf *public_key,
    ra_tls_buf *private_key, const char *oid)
{
    return openssl_generate_certificate_with_extension(cert, extension, public_key, private_key, oid);
}

static int get_extension_from_X509(ra_tls_buf *ext_buf, ra_tls_buf *oid, X509 *cert)
{
    int extensions_cnt = 0;
    if (cert == NULL || ext_buf == NULL || oid == NULL) {
        return -1;
    }
    const STACK_OF(X509_EXTENSION) *extensions = NULL;
    if (!(extensions = X509_get0_extensions(cert))) {
        printf("get extensions failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
    extensions_cnt = sk_X509_EXTENSION_num(extensions);
    
    ra_tls_buf_init(oid, OID_LEN_MAX + 1);
    for (int i = 0; i < extensions_cnt; i++) {
        X509_EXTENSION *ext;
        ASN1_OBJECT *asn1_obj;
        ASN1_OCTET_STRING *asn1_str;
        ext = sk_X509_EXTENSION_value(extensions, i);
        if (ext == NULL) {
            printf("get extension[%d] failed: %s\n", i, ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (!(asn1_obj = X509_EXTENSION_get_object(ext))) {
            printf("get extensions obj failed: %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (!OBJ_obj2txt((char *)oid->buf, oid->len, asn1_obj, 1)) {
            printf("get extensions oid failed: %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (strcmp((const char *)oid->buf, EVIDENCE_OID) != 0 && strcmp((const char *)oid->buf, TOKEN_OID) != 0) {
            continue;
        }
        if (!(asn1_str = X509_EXTENSION_get_data(ext))) {
            printf("get extensions data failed: %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        ra_tls_buf_init(ext_buf, asn1_str->length + 1);
        memcpy(ext_buf->buf, asn1_str->data, asn1_str->length);
        ext_buf->filled = asn1_str->length;
        ext_buf->buf[ext_buf->filled] = '\0';
#ifdef DEBUG
        printf("oid: %s\n", oid->buf);
        printf("extension:\n%s\n", ext_buf->buf);
#endif
        return 0;
    }
err:
    ra_tls_buf_free(ext_buf);
    ra_tls_buf_free(oid);
    return -1;
}
// for verify
int get_extension_from_certificate_context(ra_tls_buf *ext_buf, ra_tls_buf *oid, void *cert_ctx)
{
    int ret = -1;
    X509 *cert = NULL;
    X509_STORE_CTX *x509_ctx = (X509_STORE_CTX *)cert_ctx;
    if (ext_buf == NULL || oid == NULL) {
        goto end;
    }
    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert == NULL) {
        printf("get certificate failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        goto end;
    }
    if (get_extension_from_X509(ext_buf, oid, cert) < 0) {
        goto end;
    }
    ret = 0;
end:
    return ret;
}

int get_public_key_from_certificate_context(ra_tls_buf* key_der, void* cert_ctx)
{
    int ret = -1;
    X509 *cert = NULL;
    unsigned char *pub_key = NULL;
    int pub_key_len = 0;
    X509_STORE_CTX *x509_ctx = (X509_STORE_CTX*)cert_ctx;
    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert == NULL) {
        printf("get certificate failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    ra_tls_buf_init(key_der, KEY_SIZE_MAX);
    pub_key = key_der->buf;
    pub_key_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &pub_key);
    if (pub_key_len <= 0) {
        printf("get public key failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    key_der->filled = pub_key_len;
    ret = 0;
err:
    return ret;
}

int get_extension_from_certificate_der(ra_tls_buf *ext_buf, ra_tls_buf *oid, ra_tls_buf *cert_der)
{
    int ret = -1;
    BIO *bio_cert = BIO_new_mem_buf(cert_der->buf, cert_der->filled);
    X509 *icert = NULL;
    if (d2i_X509_bio(bio_cert, &icert) == NULL) {
        printf("der read certificate failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    if (get_extension_from_X509(ext_buf, oid, icert) < 0) {
        goto err;
    }
    ret = 0;
err:
    if (bio_cert) {
        BIO_free(bio_cert);
    }
    if (icert) {
        X509_free(icert);
    }
    return ret;
}
