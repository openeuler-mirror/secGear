#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/ec.h>
#include "secure_channel_host.h"
#include "enclave.h"
#include "status.h"
#include "sc_demo_u.h"
#include "usr_msg.h"

#define MAXBUF 1024

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uint32_t len;
    int sockfd, connfd;
    struct sockaddr_in svr_addr, conn_addr;
    char buf[MAXBUF + 1] = {0};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("create socket failed\n");
        return -1;
    }
    bzero(&svr_addr, sizeof(svr_addr));

    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    svr_addr.sin_port = htons(12306); // test server port 12306

    if (bind(sockfd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) != 0) {
        printf("socket bind failed\n");
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, 5) != 0) { // 5
        printf("listen failed\n");
        close(sockfd);
        return -1;
    }
    int ret_val;
    cc_enclave_t context = {0};
    char *path = PATH;
    int ret = cc_enclave_create(path, AUTO_ENCLAVE_TYPE, 0,SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    if (ret != CC_SUCCESS) {
        printf("create enclave error %x!\n", ret);
        close(sockfd);
        return -1;
    }

    // step1: 初始化安全通道服务, 注册消息发送函数
    cc_sec_chl_svr_ctx_t svr_ctx = {0};
    svr_ctx.enclave_ctx = &context;
    svr_ctx.conn_kit.send = (void *)socket_write_adpt;
    svr_ctx.conn_kit.conn = &connfd;
    ret = cc_sec_chl_svr_init(&svr_ctx);

    while (1) {
        connfd = accept(sockfd, (struct sockaddr *)&conn_addr, &len);
        if (connfd < 0) {
            printf("accept error\n");
            continue;
        }

        while (1) {
            len = read(connfd, buf, MAXBUF);
            if (len <= 0) {
                printf("secure channel server, there is no more data\n");
                printf("secure channel server, listening new require\n");
                break;
            }
            uint8_t enclave_secret[1024] = {0};
            size_t secret_len = 1024;

            usr_msg_t *msg = calloc(1, len);
            if (msg ==  NULL) {
                break;
            }
            memcpy(msg, buf, len);
            switch (msg->type) {
                case MSG_TYPE_SEC_CHL_ESTABLISH:
                    // step2: 在业务的消息接收函数中，调用安全通道回调函数
                    ret = cc_sec_chl_svr_callback(&svr_ctx, (void *)msg->data, msg->len);
                    if (ret != CC_SUCCESS) {
                        printf("secure channel server handle require failed\n");
                    }
                    break;
                case MSG_TYPE_TEST:
                    // step3: 用户业务逻辑，处理安全通道的加密数据
                    ret = sec_chl_recv_client_data(&context, &ret_val, msg->session, msg->data, msg->len);
                    if (ret != 0 || ret_val != 0) {
                        printf("enclave decrypt error\n");
                    }
                    // step4: 将server enclave中数据加密发送到客户端
                    ret = sec_chl_get_enclave_secret(&context, &ret_val, msg->session, enclave_secret, &secret_len);
                    
                    size_t send_msg_len = sizeof(usr_msg_t) + secret_len;
                    usr_msg_t *send_msg = calloc(1, send_msg_len);
                    if (send_msg == NULL) {
                        break;
                    }
                    send_msg->type = MSG_TYPE_TEST;
                    send_msg->session = msg->session;
                    send_msg->len = secret_len;
                    memcpy(send_msg->data, enclave_secret, secret_len);

                    int result = write(connfd, (void *)send_msg, send_msg_len);
                    if (result < 0) {
                        printf("send msg error\n");
                    }
                    free(send_msg);
                    break;
                default:
                    printf("server recv error msg type\n");
                    break;
            }
            free(msg);
        }
    }
    // step5: 停止安全通道服务
    cc_sec_chl_svr_fini(&svr_ctx);
    cc_enclave_destroy(&context);
    close(sockfd);
    return 0;
}
