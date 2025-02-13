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
err:
    if (ssl) {
        SSL_free(ssl);
        ssl = NULL;
    }
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    close(server_sokcet);
    server_sokcet = -1;
}