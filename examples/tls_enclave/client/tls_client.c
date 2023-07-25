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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"

#define BUF_LEN 1024

int main(int argc, const char *argv[])
{
    struct sockaddr_in client_addr;
    int fd = 0;
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char buf[BUF_LEN] = {0};   
    int ret = -1;
    
    if (argc != 3) {
        printf("usage: %s port ca_file\n", argv[0]);
        return -1;
    }

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = TLS_method();
    if (meth == NULL) {
        return -1;
    }
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, argv[2], NULL) <= 0) {
        goto end;
    }
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(atoi(argv[1]));
    client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        goto end;
    } 
    ret = connect(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    if (ret < 0) {
        goto end;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto end;
    }
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) <= 0) {
        goto end;
    }
    if (SSL_write(ssl, "hello enclave!", sizeof("hello enclave!")) <= 0) {
        goto end;
    }
    printf("send data: %s\n", "hello enclave!");
    if (SSL_read(ssl, buf, BUF_LEN - 1) <= 0) {
        goto end;
    }
    printf("receive data: %s\n", buf);
    ret = 0;

end:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    if (fd > 0) {
        close(fd);
    }
    return ret;
}
