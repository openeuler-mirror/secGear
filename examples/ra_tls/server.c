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

#include <unistd.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "ra_tls.h"

const ra_mode mode = PASSPORT;
// return listen socket
int server_listen(int port)
{
    const int reuse = 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        printf("create socket failed\n");
        goto exit;
    }
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const void*)&reuse, sizeof(reuse)) < 0) {
        printf("set socket failed \n");
        goto exit;
    }
    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("bind failed port = %d\n", port);
        goto exit;
    }
    if (listen(server_socket, 20) < 0) { // default connections max 20
        printf("listen failed, port = %d\n", port);
        goto exit;
    }
    return server_socket;
exit:
    return -1;
}

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


int main(int argc, char *argv[])
{
    int res = 0;
    ra_tls_buf cert = RA_TLS_BUF_INIT;
    ra_tls_buf prv_key = RA_TLS_BUF_INIT;
    int client_socket = -1;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    uint8_t read_buf[256];
    size_t read_len = 0;
    size_t write_len = 0;
    SSL *ssl = NULL;
    SSL_CTX *ssl_ctx = NULL;

    SSL_library_init();
    SSL_load_error_strings();
    int listen_socket = server_listen(10001);
    while (1) {
        printf("wait client tcp connect...\n");
        client_socket = accept(listen_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            printf("accept error\n");
            break;
        }
        (void)fflush(stdout);
        printf("Connected\n");
        if (cert.buf == NULL || mode == BACKGROUND) {
            // generate certificate
            printf("certificate empty and initialize\n");
            if (generate_certificate(&cert, &prv_key) < 0) {
                close(client_socket);
                return -1;
            }
        } else if (ra_tls_cert_extension_expired(&cert)) {
            printf("certificate expired and regenarate\n");
            ra_tls_buf_free(&cert);
            ra_tls_buf_free(&prv_key);
            if (generate_certificate(&cert, &prv_key) < 0) {
                close(client_socket);
                return -1;
            }
        }

        // use certificate to set context
        ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (set_context_with_certificate(ssl_ctx, &cert, &prv_key) < 0) {
            break;
        }
        ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            printf("SSL new failed\n");
            break;
        }
        if (SSL_set_fd(ssl, client_socket) <= 0) {
            printf("set fd failed\n");
            break;
        }
        printf("\nwait client handshake...\n");
        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            printf("ssl accept failed\n");
            SSL_free(ssl);
            ssl = NULL;
            close(client_socket);
            client_socket = -1;
            continue;
        }
        printf("Success\n");
        printf("read ready...\n");
        read_len = SSL_read(ssl, read_buf, sizeof(read_buf) - 1);
        if (read_len <= 0) {
            break;
        }
        read_buf[read_len] = '\0';
        printf("read data[%d]: %s\n", read_len, read_buf);
        printf("write back\n");
        write_len = SSL_write(ssl, read_buf, read_len);
        if (write_len <= 0) {
            break;
        }
        printf("write ok\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
        printf("bye\n");

        close(client_socket);
        client_socket = -1;
    }
    if (ssl) {
        SSL_free(ssl);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    ERR_free_strings();
    EVP_cleanup();

    ra_tls_buf_free(&cert);
    ra_tls_buf_free(&prv_key);
    return 0;
}