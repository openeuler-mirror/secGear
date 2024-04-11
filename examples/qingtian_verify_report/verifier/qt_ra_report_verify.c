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
#include <linux/limits.h>
#include <stdlib.h>
#include <unistd.h>
#include "qt_ra_report_verify.h"

#define TIME_UNIT               1000
/*
 * #define SECGEAR_CHECK_PCRS 
 * Uncomment the macro to verify image pcr values.
 * NOTE: On some platform, the quote is not generated correctly, which contains no valid nonce and pcrs.
 */

#define SECGEAR_SKIP_ROOT_CERT
/*  
 * Comment the macro to alert if the cert chain is not starting form qingtian root cert.
 * NOTE: On some old platforms, the cert chain does not start from the qingtian root cert.
 */

/* Qingtian root cert can be retrived from 
 * https://qingtian-enclave.obs.myhuaweicloud.com/huawei_qingtian-enclaves_root-G1.zip 
 * NOTE: The cert is UNIQUE and IDENTICAL.
 */
X509 *g_qt_root_cert;

/* Read Qingtian root certificate from f_path. */
X509 *qt_read_root_cert(const char* f_path)
{
    char real_p[PATH_MAX] = {0};

    if (realpath(f_path, real_p) == NULL) {
        if (getcwd(real_p, sizeof(real_p)) == NULL) {
            printf("Cannot find Qingtian root cert.\n");
            goto end;
        }
        if (PATH_MAX - strlen(real_p) <= strlen("/root.pem")) {
            printf("Failed to strcat Qingtian root cert path");
            goto end;
        }
        (void)strcat(real_p, "/root.pem");
    }

    FILE *cert = fopen(real_p, "r");
    if (!cert) {
        return NULL;
    }
    
    if (!PEM_read_X509(cert, &g_qt_root_cert, NULL, NULL))
        return NULL;

    fclose(cert);
end:
    return g_qt_root_cert;
}

void free_qt_root_cert(X509 *cert)
{
    if(cert) {
        X509_free(cert);
    }
}

/* Check if the report is generated within 15 minutes. */
static bool qt_is_timestamp_expired(const uint64_t timestamp) 
{
    struct timeval cur_time = {0, 0};
    int flag = -1;
    int trials = 3;
    uint64_t milliseconds = 0;

    while (flag != 0 && trials > 0) {
        flag = gettimeofday(&cur_time, NULL);
        trials--;
    }

    milliseconds = (uint64_t)(cur_time.tv_sec) * TIME_UNIT + (uint64_t)(cur_time.tv_usec) / TIME_UNIT;
    return ((int64_t)(milliseconds - timestamp) > MAX_QT_VALIDATION_PERIOD);
}

/* Verify embedded cert chain, starting from qingtian root cert. */
static int qt_verify_certchain(cabundles_raws *certificate, 
                               unsigned char* target, 
                               uint32_t target_len, 
                               X509 **target_cert)
{
    int ret = CC_SUCCESS;
    X509 *interm_cert = NULL;
    X509_STORE_CTX *cert_ctx = NULL;
    X509_STORE *cert_store = NULL;
    STACK_OF(X509) *cert_stack = NULL;
    unsigned char *tmp_buf = NULL;
    long tmp_buf_len = 0;
#ifdef DEBUG_DUMP_PEM
    FILE *interms = NULL;
    interms = fopen("./interms.pem", "w+");
#endif  

    cert_ctx = X509_STORE_CTX_new();
    cert_store = X509_STORE_new();
    cert_stack = sk_X509_new_null();

    if (certificate->ca_bundle_num > QTSM_CERTIFICATE_MAX_DEPTH) {
        printf("Certificate chain exceeds the maimum depth, abort!\n");
        return CC_ERROR_INVALID_ATTRIBUTE;
    }

    /* recover cert chain [target, intermN, intermN-1,..., root cert] */
    for (uint32_t i = certificate->ca_bundle_num; i != 0; i--) {
        tmp_buf = certificate->cabundles[i-1].data;
        tmp_buf_len = (long)certificate->cabundles[i-1].data_len;

        interm_cert = d2i_X509(NULL, (const unsigned char **)&tmp_buf, tmp_buf_len);
        if (!interm_cert) {
            printf("read intermediate certificate failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ret = CC_ERROR_CORRUPT_OBJECT;
            goto exit;
        }
#ifdef DEBUG_DUMP_PEM
        PEM_write_X509_AUX(interms, interm_cert);
#endif
        sk_X509_push(cert_stack, interm_cert);
    }

    interm_cert = NULL;

    /* Load trusted qingtian root cert, if exists. */
    if (g_qt_root_cert == NULL) {
        ret = CC_ERROR_INVALID_ATTRIBUTE;
        goto exit;
    }

    if (!X509_STORE_add_cert(cert_store, g_qt_root_cert)) {
        ret = CC_ERROR_CORRUPT_OBJECT;
        goto exit;
    }

    /* load target cert */
    tmp_buf_len = (long)target_len;
    *target_cert = d2i_X509(NULL, (const unsigned char **)&target, tmp_buf_len);
#ifdef DEBUG_DUMP_PEM
    PEM_write_X509_AUX(interms, target_cert);
#endif

    if (!X509_STORE_CTX_init(cert_ctx, cert_store, *target_cert, cert_stack)) {
        ret = CC_FAIL;
        goto exit;
    }
    /* verify with openssl internal cb */
    ret = X509_verify_cert(cert_ctx);
    if (ret <= 0) {
        printf("Verify certificate chain failed at depth %d: %s\n", 
            X509_STORE_CTX_get_error_depth(cert_ctx), 
            X509_verify_cert_error_string(X509_STORE_CTX_get_error(cert_ctx)));
#ifdef SECGEAR_SKIP_ROOT_CERT
        // Skip root cert issue on some old platforms
	    ret = CC_ERROR_RA_REPORT_VERIFY_INVALID_CERTS;
#endif
    }

exit:
#ifdef DEBUG_DUMP_PEM
    fclose(interms);
#endif
    if (cert_ctx) {
        /* cleanup is automatically done in free routine */
        X509_STORE_CTX_free(cert_ctx);
    }

    if (cert_store) {
        X509_STORE_free(cert_store);
    }

    /* free X509 STACK */
    if (cert_stack) {
	    // sk_X509_pop_free automatically frees all elements and stack
        sk_X509_pop_free(cert_stack, X509_free);
    }

    return ret;
}

/* Verify if cbored doc's signature is properly signed. */
static int qt_check_cbored_signature(const unsigned char *sig_msg, 
                                     const size_t sig_msg_len, 
                                     const unsigned char *signature, 
                                     const enum digest_alg alg, 
                                     EVP_PKEY *pubkey)
{
    int ret = CC_SUCCESS, rc = 0;
    BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG *ecsig_val = NULL;
    SHA512_CTX sha_ctx = {0};
    EC_KEY *ec_key = NULL;
    unsigned char t_signature[QTSM_SIGNATURE_MAX_SIZE] = {0};
    int t_signature_len = 0;
    int digest_len = 0;

    switch (alg) {
        case QTSM_SHA256:
            t_signature_len = SHA256_LEN << 1;
            digest_len = SHA256_LEN;
            break;
        case QTSM_SHA384:
            t_signature_len = SHA384_LEN << 1;
            digest_len = SHA384_LEN;
            break;
        case QTSM_SHA512:
            t_signature_len = SHA512_LEN << 1;
            digest_len = SHA512_LEN;
            break;
        default:
            return CC_ERROR_INVALID_ATTRIBUTE;
    }

    r = BN_new();
    if (r == NULL) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    s = BN_new();
    if (s == NULL) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    BN_bin2bn(signature, digest_len, r);
    BN_bin2bn(signature + digest_len, digest_len, s);

    ecsig_val = ECDSA_SIG_new();
    if (ecsig_val == NULL) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    rc = ECDSA_SIG_set0(ecsig_val, r, s);
    if (!rc) {
        ret = CC_ERROR_FILE_CLOSE_FAILED;
        goto exit;
    }

    rc = SHA384_Init(&sha_ctx);
    if (!rc) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    rc = SHA384_Update(&sha_ctx, sig_msg, sig_msg_len);
    if (!rc) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    rc = SHA384_Final(t_signature, &sha_ctx);
    if (!rc) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    ec_key = EVP_PKEY_get0_EC_KEY(pubkey);
    if (!ec_key) {
        ret = CC_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    rc = ECDSA_do_verify(t_signature, t_signature_len, ecsig_val, ec_key);
    if (rc == 1) {
        printf("check signature succeeded!\n");
        ret = CC_SUCCESS;
    } else if (ret < 1) { // 0 and -1
        printf("check signature error!\n");
        ret = CC_ERROR_RA_REPORT_VERIFY_SIGNATURE;
    }

exit:    
    /* r and s are also cleared via BN_clear_free (in ECDSA_SIG_free).*/
    if (ecsig_val) {
        ECDSA_SIG_free(ecsig_val);
    }
    memset(&sha_ctx, 0, sizeof(SHA512_CTX));    
    return ret;
}

static int qt_check_report(attestation_document *adoc, 
                     size_t adoc_length,
                     unsigned char *sig_msg, 
                     size_t sig_msg_len)
{
    int ret = CC_SUCCESS;
    X509 *pem_with_pubkey = NULL;
    EVP_PKEY *pubkey = NULL;
    assert(adoc_length == sizeof(attestation_document));

    /* 1. verify timestamp */
    if (qt_is_timestamp_expired(adoc->doc.timestamp)) {
        printf("[ERROR] time stamp expired.\n");
        ret = CC_ERROR_RA_REPORT_VERIFY_INVALID_TIMESTAMP;
        goto exit;
    }

    /* 2. Verify cert chain from cabundles and extract ecdsa pub key*/
    ret = qt_verify_certchain(&(adoc->doc.ca_bundles), adoc->doc.certificate, adoc->doc.cert_len, &pem_with_pubkey);
    if (ret != CC_SUCCESS) {
        printf("[ERROR] Certificate chain verification failed.\n");
        goto exit;
    }
    pubkey = X509_get0_pubkey(pem_with_pubkey);

    /* 3. Verify signature */
    ret = qt_check_cbored_signature(sig_msg, sig_msg_len, adoc->signature, adoc->doc.digest, pubkey);
    if (ret != CC_SUCCESS) {
        printf("[ERROR] CBOREN doc Signature verification failed.");
        long rc = ERR_get_error();
        if (rc > 0) {
            printf("Openssl: %s", ERR_error_string(rc, NULL));
        }
        printf("\n");
    }
    
exit:
    if (pem_with_pubkey) {
        X509_free(pem_with_pubkey);
    }

    return ret;
}

#ifdef SECGEAR_CHECK_PCRS
/**
 * Check if pcr base values match with those in attestation document.
 * @param[in] pcrs, the expected set of pcr values.
 * @param[in] doc, the attestation doc.
 * @param[in] type, the verification mode.
 * @retval, on success, return 0, otherwise -1;
*/
static int check_basevalue(pcr_raw *pcrs, attestation_document *doc_plain, cc_ra_verify_type_t type)
{
    uint16_t index = 0;
    int rc = -1;

    if (pcrs[0].index == 0) {
        index = pcrs[0].index;
        rc = memcmp(pcrs[0].data, (doc_plain->doc.pcrs.pcrs[index].data), QTSM_PCR_MAX_LENGTH);
        if (rc != 0) {
            goto end;
        }
    } else {
        goto end;
    }

    if (type > CC_RA_VERIFY_TYPE_LOOSE) {
        if (pcrs[1].index == 8) {
            index = pcrs[1].index;
            rc = memcmp(pcrs[1].data, (doc_plain->doc.pcrs.pcrs[index].data), QTSM_PCR_MAX_LENGTH);
        } else {
            rc = -1; // pcr-8 missing in strict mode
        }
    } 

end:    
    if (rc > 0) {
        rc = -1;
    }

    return rc;
}
#endif

/** 
 * If type == 
 * CC_RA_VERIFY_TYPE_LOOSE, we proceed as far as we can, unless a fetal error stops proceeding with the report.
 * CC_RA_VERIFY_TYPE_STRICT, all required fields must be strictly matched.
*/
cc_enclave_result_t qt_verify_report(cc_ra_buf_t *report, cc_ra_buf_t *nonce,
    cc_ra_verify_type_t type, char *basevalue)
{
    int ret = CC_MAXIMUM_ERROR; 
    int rc = 0;
    unsigned char *signature_msg = NULL;
    size_t signature_msg_len = 0;
    attestation_document doc_plain = {0};

    if (g_qt_root_cert == NULL || nonce == NULL || basevalue == NULL) {
        /* Alert no cert. */
        ret = CC_ERROR_INVALID_ATTRIBUTE;
        goto exit;
    }

    /* 1. Parse and format report, which is atomic, no loose or strict policy. */
    rc = parse_cboren_doc((uint8_t*)report->buf, report->len, &doc_plain, &signature_msg, &signature_msg_len);
    if (rc != NO_ERROR) {
        ret = CC_ERROR_RA_REPORT_VERIFY_FORMAT;
        goto exit;
    }
    /* 2. Now we have raw attestation_document in doc_plain, check signature, timestamp and cert chain. */
    ret = qt_check_report(&doc_plain, sizeof(attestation_document), signature_msg, signature_msg_len);
    if (ret != CC_SUCCESS) {
        goto exit;
    }

    (void)type;
#ifdef SECGEAR_CHECK_PCRS 
    // NOTE: On Odin platform, the current quote is not generated correctly, it has no valid nonce and pcrs.
    /* 3. Check if nounce are as expected */
    if (nonce->len > 0 && nonce->len == doc_plain.doc.nonce_len) {
        rc = memcmp(nonce->buf, doc_plain.doc.nonce, nonce->len);
    } else {
        rc = -1;
    }
    /* Report nonce error */
    if (rc != 0) {
        ret = CC_ERROR_RA_REPORT_VERIFY_NONCE;
        goto exit;
    }

    /* 4. Check base valuse,  */
    pcrs = (pcr_raw *)basevalue;
    rc = check_basevalue(pcrs, &doc_plain, type);
    if (rc != 0) {
        ret = CC_ERROR_RA_REPORT_VERIFY_HASH;
    }
#endif
exit:
    if (signature_msg) {
        free(signature_msg);
    }

    return ret;
}
