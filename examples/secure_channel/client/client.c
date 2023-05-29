#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <string.h>
#include "status.h"

#include "usr_msg.h"
#include "secure_channel_client.h"


#define MAXBUF 12800
cc_sec_chl_ctx_t g_ctx = {0};

int socket_write_and_read(void *conn, void *buf, size_t count)
{
    int ret = socket_write_adpt(conn, buf, count);
    if (ret < 0) {
        return ret;
    }
    // 发送完消息后，就等待响应消息，并调用cc_sec_chl_client_callback处理
    int len;
    int fd = *(int *)conn;
    uint8_t recv_buf[MAXBUF] = {0};
    uint8_t sc_msg[MAXBUF] = {0};
    usr_msg_t *usr_msg = NULL;
    while(1) {
        len = read(fd, recv_buf, MAXBUF);
        if (len <= 0) {
            printf("receive no data\n");
            sleep(1);
            continue;
        } else {
            usr_msg = (usr_msg_t *)recv_buf;
            memcpy(sc_msg, usr_msg->data, usr_msg->len);
            break;
        }
    }

    return cc_sec_chl_client_callback(&g_ctx, sc_msg, usr_msg->len);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int sockfd;
    cc_enclave_result_t ret;
    struct sockaddr_in svr_addr;

    char *ta_basevalue_file = "../basevalue.txt";
    char basevalue_real_path[PATH_MAX] = {0};
    if (realpath(ta_basevalue_file, basevalue_real_path) == NULL) {
        printf("ta basevalue file path error\n");
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("create socket failed\n");
        return -1;
    }
    bzero(&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    svr_addr.sin_port = htons(12306); // test server port 12306

    if (connect(sockfd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) != 0) {
        printf("connet to server failed\n");
        close(sockfd);
        return -1;
    }
    printf("connect server success\n");

    // step1: 初始化安全通道客户端，注册消息发送函数
    g_ctx.conn_kit.send = (void *)socket_write_and_read;
    g_ctx.conn_kit.conn = &sockfd;
    g_ctx.basevalue = basevalue_real_path;  // content format:taid image_hash mem_hash
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
    // step3: 将加密后数据放到业务消息中发送到服务端处理，在enclave中调用解密接口解密
    size_t msg_len = sizeof(usr_msg_t) + encrypt_len;
    usr_msg_t *msg = calloc(1, msg_len);
    if (msg == NULL) {
        free(encrypted);
        goto finish;
    }
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

    uint8_t plain[MAXBUF] = {0};
    size_t plain_len = MAXBUF;
    uint8_t recv_buf[MAXBUF] = {0};
    usr_msg_t *usr_msg = NULL;
    result = read(sockfd, recv_buf, MAXBUF);
    usr_msg = (usr_msg_t *)recv_buf;

    // step4: 接收服务端数据处理结果密文，解密获取处理结果
    ret = cc_sec_chl_client_decrypt(&g_ctx, usr_msg->data, usr_msg->len, plain, &plain_len);
    if (ret != 0) {
        printf("client decrypt error, ret:%d\n", ret);
    }
    printf("client recv secret:%s\n", plain);

    sleep(2); // 等收到enclave加密消息后，等待2s, 再结束安全通道

  finish:
    // step5: 结束安全通道
    cc_sec_chl_client_fini(&g_ctx);
    close(sockfd);
    return 0;
}
