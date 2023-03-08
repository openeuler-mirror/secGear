#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <string.h>
#include "status.h"

#include "usr_msg.h"
#include "secure_channel_client.h"


#define MAXBUF 1024
cc_sec_chl_ctx_t g_ctx = {0};

void *recv_msg_thread(void *arg)
{
    (void)arg;
    cc_sec_chl_ctx_t *ctx = &g_ctx;
    int fd = *(int *)(ctx->conn_kit.conn);
    int len;
    uint8_t buf[MAXBUF] = {0};
    int ret;
    uint8_t plain[MAXBUF] = {0};
    size_t plain_len = MAXBUF;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL); // 收到cancel信号后，state设置为CANCELED状态
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL); // 退出形式为立即退出

    while (1) {
        pthread_testcancel();
        len = read(fd, buf, MAXBUF);
        if (len <= 0) {
            printf("receive no data\n");
            sleep(1);
            continue;
        }
        usr_msg_t *msg = calloc(1, len);
        memcpy(msg, buf, len);
        switch (msg->type) {
            case MSG_TYPE_SEC_CHL_ESTABLISH:
                // step2: 在业务的消息接手函数中，调用安全通道客户端回调函数
                ret = cc_sec_chl_client_callback(ctx, msg->data, msg->len);
                break;
            case MSG_TYPE_TEST:
                // step5: 接收到server enclave中发送过来的数据
                ret = cc_sec_chl_client_decrypt(ctx, msg->data, msg->len, plain, &plain_len);
                if (ret != 0) {
                    printf("client decrypt error\n");
                }
                printf("client recv secret:%s\n", plain);
                break;
            default:
                printf("client recv error msg type\n");
                break;
        }
        free(msg);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int sockfd;
    cc_enclave_result_t ret;
    struct sockaddr_in svr_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("create socket failed\n");
        return -1;
    }
    bzero(&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    svr_addr.sin_port = htons(12306);

    if (connect(sockfd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) != 0) {
        printf("connet to server failed\n");
        close(sockfd);
        return -1;
    }
    printf("connect server success\n");

    // step1: 初始化安全通道客户端，注册消息发送函数
    g_ctx.conn_kit.send = (void *)socket_write_adpt;
    g_ctx.conn_kit.conn = &sockfd;

    pthread_t thread;
    pthread_create(&thread, NULL, recv_msg_thread, NULL);

    ret = cc_sec_chl_client_init(CC_SEC_CHL_ALGO_RSA_ECDH_AES_GCM, &g_ctx);
    if (ret != CC_SUCCESS) {
        printf("secure channel init failed:%u\n", ret);
        goto finish;
    }

    // step2: 安全通道初始化完成后，调用加密接口加密业务数据
    char *client_secret = "This is client secret 666";
    printf("client send secret:%s\n\n", client_secret);

    char *encrypted = NULL;
    size_t encrypt_len = 0;
    ret = cc_sec_chl_client_encrypt(&g_ctx, (void *)client_secret, strlen(client_secret),
        encrypted, &encrypt_len);
    if (ret == CC_ERROR_SEC_CHL_LEN_NOT_ENOUGH) {
        encrypted = (char *)calloc(1, encrypt_len);
        if (encrypted == NULL) {
            goto finish;
        }
    }
    ret = cc_sec_chl_client_encrypt(&g_ctx, (void *)client_secret, strlen(client_secret), encrypted, &encrypt_len);
    if (ret != CC_SUCCESS) {
        printf("client encrypt secret failed:%u\n", ret);
        free(encrypted);
        encrypted = NULL;
        goto finish;
    }

    // step3: 加密后，用户结合自己业务发送到服务端enclave中，调用解密接口解密
    size_t msg_len = sizeof(usr_msg_t) + encrypt_len;
    usr_msg_t *msg = calloc(1, msg_len);
    msg->type = MSG_TYPE_TEST;
    msg->session = g_ctx.session_id;
    msg->len = encrypt_len;
    memcpy(msg->data, encrypted, encrypt_len);

    int result = write(sockfd, (void *)msg, msg_len);
    if (result < 0) {
        printf("send msg error\n");
    }
    free(msg);
    free(encrypted);

    sleep(2); // 等收到enclave加密消息后，再结束安全通道

  finish:
    cc_sec_chl_client_fini(&g_ctx);
    pthread_cancel(thread);
    close(sockfd);
    return 0;
}


