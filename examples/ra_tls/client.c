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
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#include "ra_tls.h"
#ifdef CLIENT_WITH_CERT
const ra_mode mode = PASSPORT;
#endif
// return socket fd
int connect_with_tcp(const char *dst, const int port)
{
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) {
        printf("create client socket failed\n");
        return -1;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, dst, &addr.sin_addr.s_addr);
    addr.sin_port = htons(port);

    if (connect(client, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        printf("connect failed: %s:%d\n", dst, port);
        return -1;
    } else {
        printf("tcp connected: %s:%d\n", dst, port);
    }

    return client;
}
#ifdef CLIENT_WITH_CERT
int generate_certificate(ra_tls_buf *cert, ra_tls_buf *prv_key)
{
    int res = 0;
    printf("starting generate certificate...\n");
    ra_cfg cfg;
    cfg.aa_addr = "http://server.com:8081/";
    cfg.uuid = "f68fd704-6eb1-4d14-b218-722850eb3ef0";
    cfg.mode = mode;
    if (mode == PASSPORT) {
        printf("mode: Passport\n");
    } else if (mode == BACKGROUND) {
        printf("mode: Background\n");
    }
    printf("attestation agent address: %s\n", cfg.aa_addr);
    printf("uuid: %s\n", cfg.uuid);
    res = ra_tls_generate_certificate(cert, prv_key, &cfg, RSA_3072);
    if (res < 0) {
        printf("generate certificate failed\n");
        return -1;
    }
    return 0;
}

int set_context_with_certificate(SSL_CTX *ssl_ctx, ra_tls_buf *cert, ra_tls_buf *prv_key)
{
    int ret = -1;
    BIO *bio_cert = BIO_new_mem_buf(cert->buf, cert->filled);
    BIO *bio_prv = BIO_new_mem_buf(prv_key->buf, prv_key->filled);
    X509 *icert = NULL;
    if (d2i_X509_bio(bio_cert, &icert) == NULL) {
        printf("der read certificate failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    EVP_PKEY *iprv_key = NULL;
    if (d2i_PrivateKey_bio(bio_prv, &iprv_key) == NULL) {
        printf("pem read private key failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    if (SSL_CTX_use_certificate(ssl_ctx, icert) <= 0) {
        printf("ctx use certificate failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    if (SSL_CTX_use_PrivateKey(ssl_ctx, iprv_key) <= 0) {
        printf("ctx use private key failed: %s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    ret = 0;
err:
    if (bio_cert) {
        BIO_free(bio_cert);
    }
    if (bio_prv) {
        BIO_free(bio_prv);
    }
    if (icert) {
        X509_free(icert);
    }
    if (iprv_key) {
        EVP_PKEY_free(iprv_key);
    }
    return ret;
}
#endif

#define BUF_LEN_MAX 256
int main(int argc, char *argv[])
{
    int res = 0;
    int ret = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const char *dst = "server.com";
    int port = 10001;
    int server_sokcet = -1;
    uint8_t send_buf[BUF_LEN_MAX] = {"Hello Server\n"};
    size_t send_buf_len = strlen(send_buf);
    uint8_t recv_buf[BUF_LEN_MAX] = {0};
    size_t recv_buf_len = strlen(recv_buf);
#ifdef CLIENT_WITH_CERT
    ra_tls_buf cert = RA_TLS_BUF_INIT;
    ra_tls_buf prv_key = RA_TLS_BUF_INIT;

    if (generate_certificate(&cert, &prv_key) < 0) {
        return -1;
    }
    /* when use PASSPORT mode, ra_tls_cert_extension_expired() can check extension is expired or not
       it's benifit to avoid regenerate certificate repeatly
    */
    if (mode == PASSPORT && ra_tls_cert_extension_expired(&cert)) {
        printf("certificate expired and regenarate\n");
        ra_tls_buf_free(&cert);
        ra_tls_buf_free(&prv_key);
        if (generate_certificate(&cert, &prv_key) < 0) {
            return -1;
        }
    }
#endif
    server_sokcet = connect_with_tcp(dst, port);
    if (server_sokcet < 0) {
        printf("connect to[%s:%d] failed, exit\n", dst, port);
        return ret;
    }
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("ctx create failed\n");
        printf("%s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
#ifdef CLIENT_WITH_CERT
    if (set_context_with_certificate(ctx, &cert, &prv_key) < 0) {
        goto err;
    }
#endif
    ra_tls_set_addr("http://server.com:8081/");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ra_tls_verify_callback);

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("ssl create failed\n");
        printf("%s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    res = SSL_set_fd(ssl, server_sokcet);
    res = SSL_connect(ssl);
    if (res <= 0) {
        printf("ssl connect failed: %d\n", res);
        printf("%s\n", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    res = SSL_write(ssl, send_buf, send_buf_len);
    if (res <= 0) {
        printf("ssl write failed:%d\n", res);
        printf("%s\n", ERR_reason_error_string(ERR_get_error()));
        goto end;
    }
    printf("send ok[%d]:%s\n", res, send_buf);
    usleep(1000); // wati 1000ms to receive data
#if 1
    res = SSL_read(ssl, recv_buf, BUF_LEN_MAX);
    if (res <= 0) {
        printf("ssl read failed:%d\n", res);
        goto end;
    }
    recv_buf_len = res;
    printf("read from peer[len = %d]: %s\n", recv_buf_len, recv_buf);
#endif
end:
    SSL_shutdown(ssl);
    ret = 0;
err:
    if (ssl) {
        SSL_free(ssl);
        ssl = NULL;
    }
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
#ifdef CLIENT_WITH_CERT
    ra_tls_buf_free(&cert);
    ra_tls_buf_free(&prv_key);
#endif
    close(server_sokcet);
    server_sokcet = -1;
    return ret;
}