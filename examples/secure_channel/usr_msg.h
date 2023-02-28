#ifndef USR_MSG_H
#define USR_MSG_H

#include <stdlib.h>

typedef enum {
    MSG_TYPE_TEST,               // 业务自己的消息
    MSG_TYPE_SEC_CHL_ESTABLISH,  // 安全通道消息
} usr_msg_type_t;

typedef struct {
    usr_msg_type_t type;
    size_t  session;
    size_t  len;
    uint8_t data[0];
} usr_msg_t;

int socket_write_adpt(void *conn, void *buf, size_t count)
{
    int fd = *(int *)conn;
    size_t msg_len = sizeof(usr_msg_t) + count;
    usr_msg_t *msg = calloc(1, msg_len);
    if (msg == NULL) {
        return -1;
    }
    msg->type = MSG_TYPE_SEC_CHL_ESTABLISH;
    msg->len = count;
    memcpy(msg->data, buf, count);

    int ret = write(fd, (void *)msg, msg_len);
    free(msg);
    return ret;
}

#endif
