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
#include "qt_rpc_proxy.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <linux/vm_sockets.h>
#include <openssl/rand.h>

/* ==============vsock struct start============== */
typedef struct {
    int cid;
    int svr_fd;
    int connfd;
} qt_proxy_vsock_mng_t;
/* ==============vsock struct end================ */

/* ==============msg struct start================ */
typedef enum {
    QT_MSG_ECALL,
    QT_MSG_ECALL_RET,
    QT_MSG_OCALL,
    QT_MSG_OCALL_RET,
} qt_proxy_msg_type_t;

typedef struct {
    qt_proxy_msg_type_t         type;
    uint64_t                    task_id;
    size_t                      data_len;
    uint8_t                     data[0];
} qt_proxy_msg_t;

typedef struct qt_proxy_msg_node_t {
    qt_proxy_msg_t              *msg;
    struct qt_proxy_msg_node_t  *next;
} qt_proxy_msg_node_t;

#define QT_MSG_MAX_NUM      2000
typedef struct {
    qt_proxy_msg_node_t         *head;
    qt_proxy_msg_node_t         *tail;
    pthread_mutex_t             lock;
    uint64_t                    node_cnt;
} qt_proxy_msg_queue_t;

typedef struct {
    pthread_t                   send_tid;
    pthread_t                   recv_tid;
    qt_proxy_msg_queue_t        send_queue;
    qt_proxy_msg_queue_t        recv_queue;
    qt_handle_request_msg_t     handle_request_msg_func;
} qt_proxy_msg_mng_t;
/* ==============msg struct end=================== */

/* ==============task struct start================ */
typedef struct qt_proxy_task_node_t {
    uint64_t                    task_id;       // a ecall or ocall task id
    size_t                      recv_buf_len;
    uint8_t                     *recv_buf;
    pthread_mutex_t             lock;
    pthread_cond_t              cond;
    struct qt_proxy_task_node_t *next;
} qt_proxy_task_node_t;

#define QT_TASK_MAX_NUM 50
#define QT_THREAD_POOL_MAX_SIZE 100
typedef struct {
    uint32_t                    task_size;
    uint32_t                    thread_pool_size;
} qt_proxy_task_config_t;

typedef struct {
    uint64_t                    count;     // task num in task_list_head
    pthread_mutex_t             lock;
    qt_proxy_task_node_t        task_list_head;
    qt_proxy_task_config_t      proxy_config;
    pthread_t                   *thread_pool;
} qt_proxy_task_mng_t;
/* ==============task struct end================ */

typedef struct {
    qt_proxy_vsock_mng_t  vsock_mng;
    qt_proxy_msg_mng_t    msg_mng;
    qt_proxy_task_mng_t   task_mng;
} qt_rpc_proxy_t;

static qt_rpc_proxy_t g_qt_proxy;

// todo xuraoqing adapt cid port
static int qt_vsock_init(int cid)
{
    bool is_server = false;
    int sockfd;
    int connfd;

#ifdef ENCLAVE
    is_server = true;
#endif

#ifdef SIM
    (void)cid;
    struct sockaddr_in svr_addr, conn_addr;
    uint32_t conn_len = sizeof(conn_addr);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("create socket failed\n");
        return -1;
    }
    bzero(&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = is_server ? htonl(INADDR_ANY) : inet_addr("127.0.0.1");
    svr_addr.sin_port = htons(8082);
#else
    struct sockaddr_vm svr_addr, conn_addr;
    uint32_t conn_len = sizeof(conn_addr);
    sockfd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("create socket failed\n");
        return -1;
    }
    bzero(&svr_addr, sizeof(svr_addr));
    svr_addr.svm_family = AF_VSOCK;
    svr_addr.svm_cid = is_server ? VMADDR_CID_ANY : (unsigned int)cid;
    svr_addr.svm_port = 8082;
#endif

    if (is_server) {
        if (bind(sockfd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) != 0) {
            printf("socket bind failed\n");
            close(sockfd);
            return -1;
        }

        if (listen(sockfd, 1) != 0) {
            printf("listen failed\n");
            close(sockfd);
            return -1;
        }
        connfd = accept(sockfd, (struct sockaddr *)&conn_addr, &conn_len);
        if (connfd < 0) {
            printf("accept error\n");
            close(sockfd);
            return -1;
        }
        g_qt_proxy.vsock_mng.svr_fd = sockfd;
        g_qt_proxy.vsock_mng.connfd = connfd;

    } else {
        if (connect(sockfd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) != 0) {
            printf("connet to server failed\n");
            close(sockfd);
            return -1;
        }
        g_qt_proxy.vsock_mng.connfd = sockfd;
    }

    return 0;
}

static void qt_vsock_destroy()
{
    if (g_qt_proxy.vsock_mng.connfd != 0) {
        close(g_qt_proxy.vsock_mng.connfd);
    }
    if (g_qt_proxy.vsock_mng.svr_fd != 0) {
        close(g_qt_proxy.vsock_mng.svr_fd);
    }
    return;
}

static void qt_free_msg_node(qt_proxy_msg_node_t *node)
{
    if (node == NULL) {
        return;
    }
    if (node->msg != NULL) {
        free(node->msg);
    }
    free(node);
    return;
}

static void qt_msg_queue_push(qt_proxy_msg_queue_t *queue, qt_proxy_msg_node_t* node)
{
    pthread_mutex_lock(&queue->lock);
    if (queue->node_cnt >= QT_MSG_MAX_NUM) {
        printf("qt_msg_queue_push queue is full\n");
        pthread_mutex_unlock(&queue->lock);
        return;
    }
    if (queue->head == NULL) {
        queue->head = queue->tail = node;
    } else {
        queue->tail->next = node;
        queue->tail = node;
    }
    queue->node_cnt++;
    pthread_mutex_unlock(&queue->lock);
}

static qt_proxy_msg_node_t *qt_msg_queue_pop(qt_proxy_msg_queue_t *queue)
{
    pthread_mutex_lock(&queue->lock);
    if (queue->head == NULL) {
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }
    qt_proxy_msg_node_t *cur = queue->head;
    if (queue->head == queue->tail) {
        // printf("qt_msg_queue_pop queue to be empty\n");
        queue->head = queue->tail = NULL;
    } else {
        queue->head = cur->next;
    }
    queue->node_cnt--;
    pthread_mutex_unlock(&queue->lock);
    return cur;
}

static void qt_msg_queue_clear(qt_proxy_msg_queue_t *queue)
{
    qt_proxy_msg_node_t *cur = NULL;
    qt_proxy_msg_node_t *next = NULL;

    pthread_mutex_lock(&queue->lock);
    cur = queue->head;
    while (cur != queue->tail) {
        next = cur->next;
        queue->node_cnt--;
        qt_free_msg_node(cur);
        cur = next;
    }
    queue->head = queue->tail = NULL;
    pthread_mutex_unlock(&queue->lock);
}

// todo delete , debug code
static char *get_msg_type_string(qt_proxy_msg_type_t type)
{
    if (type == QT_MSG_ECALL) {
        return "ecall msg";
    } else if (type == QT_MSG_ECALL_RET) {
        return "ecall ret msg";
    } else if (type == QT_MSG_OCALL) {
        return "ocall msg";
    } else if (type == QT_MSG_OCALL_RET) {
        return "ocall ret msg";
    } else {
        return "error msg type";
    }
}

// todo cc_destroy_enclave 时怎么清理队列和终止线程
void *qt_msg_send_thread_proc(void *arg)
{
    (void)arg;
    int ret;
    qt_proxy_msg_node_t *node = NULL;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL); // 收到cancel信号后，state设置为CANCELED状态
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL); // 退出形式为立即退出

    while (true) {
        pthread_testcancel();
        node = qt_msg_queue_pop(&g_qt_proxy.msg_mng.send_queue);
        if (node == NULL) {
            // printf("send thread proc send queue is empty\n");
            sleep(1);
            continue;
        }

        // todo vsock send to remote peer
        printf("[send thread] send %s, task_id:%lu\n", get_msg_type_string(node->msg->type), node->msg->task_id);

        size_t rpc_msg_len = node->msg->data_len + sizeof(qt_proxy_msg_t);
        size_t send_len = sizeof(rpc_msg_len) + rpc_msg_len;

        uint8_t *send_buf = (uint8_t *)calloc(1, send_len);
        memcpy(send_buf, &rpc_msg_len, sizeof(rpc_msg_len));
        memcpy(send_buf + sizeof(rpc_msg_len), node->msg, rpc_msg_len);

        ret = write(g_qt_proxy.vsock_mng.connfd, send_buf, send_len);
        if (ret) {}
        free(send_buf);
        qt_free_msg_node(node);

    }

    return NULL;
}

static qt_proxy_msg_node_t *qt_new_recv_msg_node(uint8_t *recv_buf, size_t len)
{
    qt_proxy_msg_t *msg = (qt_proxy_msg_t *)calloc(1, len);
    if (msg == NULL) {
        return NULL;
    }
    memcpy(msg, recv_buf, len);

    qt_proxy_msg_node_t *msg_node = calloc(1, sizeof(qt_proxy_msg_node_t));
    if (msg_node == NULL) {
        free(msg);
        return NULL;
    }
    msg_node->msg = msg;

    return msg_node;
}

#define QT_VOSCK_MAX_RECV_BUF (1024 *40)
void *qt_msg_recv_thread_proc(void *arg)
{
    (void)arg;
    int len;
    size_t msg_len = 0;
    size_t tmp_msg_len = 0;
    uint8_t buf[QT_VOSCK_MAX_RECV_BUF] = {0};
    uint8_t *buf_ptr = NULL;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL); // 收到cancel信号后，state设置为CANCELED状态
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL); // 退出形式为立即退出

    while (true) {
restart:
        pthread_testcancel();
        
        len = read(g_qt_proxy.vsock_mng.connfd, &msg_len, sizeof(size_t));    // read msg len first
        if (len <= 0) {
            printf("receive no data\n");
            sleep(1);
            continue;
        }
        printf("read msg len:%zu\n", msg_len);

        memset(buf, 0, QT_VOSCK_MAX_RECV_BUF);
        len = 0;
        buf_ptr = (uint8_t *)&buf;
        tmp_msg_len = msg_len;
        while (tmp_msg_len > 0) {
            len = read(g_qt_proxy.vsock_mng.connfd, buf_ptr, tmp_msg_len);    // read msg data
            if (len <= 0) {
                printf("receive msg data failed\n");
                goto restart;
            }
            tmp_msg_len -= len;
            buf_ptr += len;
        }
        
        // new msg node by recv buf
        qt_proxy_msg_node_t *node = qt_new_recv_msg_node(buf, msg_len);
        if (node == NULL) {
            printf("recv thread malloc msg node failed\n");
            continue;
        }
        qt_msg_queue_push(&g_qt_proxy.msg_mng.recv_queue, node);
        printf("[recv thread] recv %s, len:%lu, task_id:%lu\n", get_msg_type_string(node->msg->type), msg_len, node->msg->task_id);
    }

    return NULL;
}

static void qt_msg_thread_destroy()
{
    if (g_qt_proxy.msg_mng.send_tid != 0) {
        pthread_cancel(g_qt_proxy.msg_mng.send_tid);
        pthread_join(g_qt_proxy.msg_mng.send_tid, NULL);
        g_qt_proxy.msg_mng.send_tid = 0;
    }
    if (g_qt_proxy.msg_mng.recv_tid != 0) {
        pthread_cancel(g_qt_proxy.msg_mng.recv_tid);
        pthread_join(g_qt_proxy.msg_mng.recv_tid, NULL);
        g_qt_proxy.msg_mng.recv_tid = 0;
    }
}

static int qt_msg_mng_init(qt_handle_request_msg_t handle_func)
{
    int ret;

    if (handle_func == NULL) {
        printf("register error handle request msg function\n");
        return -1;
    }
    g_qt_proxy.msg_mng.handle_request_msg_func = handle_func;

    // create send thread
    ret = pthread_create(&g_qt_proxy.msg_mng.send_tid, NULL, qt_msg_send_thread_proc, NULL);
    if (ret != 0) {
        printf("qt msg mng init create send thread failed\n");
        return ret;
    }

    // create recv thread
    ret = pthread_create(&g_qt_proxy.msg_mng.recv_tid, NULL, qt_msg_recv_thread_proc, NULL);
    if (ret != 0) {
        printf("qt msg mng init create recv thread failed\n");
        qt_msg_thread_destroy();
        return ret;
    }

    return 0;
}

static void qt_msg_mng_destroy()
{
    // before destroy list, need destroy all thread first
    // destroy all thread by qt_msg_thread_destroy and qt_task_mng_thread_pool_destroy
    qt_msg_queue_clear(&g_qt_proxy.msg_mng.send_queue);
    qt_msg_queue_clear(&g_qt_proxy.msg_mng.recv_queue);
}

static qt_proxy_msg_node_t *qt_new_send_msg_node(uint64_t task_id, uint8_t *data, size_t data_len, bool is_rsp)
{
    size_t len = data_len + sizeof(qt_proxy_msg_t);
    qt_proxy_msg_t *msg = (qt_proxy_msg_t *)calloc(1, len);
    if (msg == NULL) {
        return NULL;
    }
    // todo add define in CmakeLists.txt
#ifdef ENCLAVE
    msg->type = is_rsp ? QT_MSG_ECALL_RET : QT_MSG_OCALL;
#else
    msg->type = is_rsp ? QT_MSG_OCALL_RET : QT_MSG_ECALL;
#endif
    msg->task_id = task_id;
    msg->data_len = data_len;
    memcpy(msg->data, data, data_len);

    qt_proxy_msg_node_t *msg_node = calloc(1, sizeof(qt_proxy_msg_node_t));
    if (msg_node == NULL) {
        free(msg);
        return NULL;
    }
    msg_node->msg = msg;

    return msg_node;
}

static int add_msg_to_send_queue(uint64_t task_id, uint8_t *input, size_t input_len)
{
    qt_proxy_msg_node_t *msg_node = qt_new_send_msg_node(task_id, input, input_len, false);
    if (msg_node == NULL) {
        return -1;
    }

    qt_msg_queue_push(&g_qt_proxy.msg_mng.send_queue, msg_node);

    return 0;
}

static void qt_task_mng_thread_pool_destroy()
{
    pthread_t *thread_pool = g_qt_proxy.task_mng.thread_pool;
    uint32_t  thread_pool_size = g_qt_proxy.task_mng.proxy_config.thread_pool_size;
    for (uint32_t i = 0; i < thread_pool_size; i++) {
        if (thread_pool[i] != 0) {
            pthread_cancel(thread_pool[i]);
            pthread_join(thread_pool[i], NULL);
            thread_pool[i] = 0;
        }
    }
    return;
}

static int qt_request_msg_proc(qt_proxy_msg_t *msg)
{
    uint8_t *rsp_buf = NULL;
    size_t  rsp_len = 0;

    g_qt_proxy.msg_mng.handle_request_msg_func(msg->data, msg->data_len, &rsp_buf, &rsp_len);

    // new response msg node
    qt_proxy_msg_node_t *rsp_node = qt_new_send_msg_node(msg->task_id, rsp_buf, rsp_len, true);
    free(rsp_buf);
    if (rsp_node == NULL) {
        printf("malloc ecall ret msg failed\n");
        return -1;
    }

    // push response msg to send queue
    qt_msg_queue_push(&g_qt_proxy.msg_mng.send_queue, rsp_node);

    return 0;
}

static int qt_response_msg_proc(qt_proxy_msg_t *msg)
{
    pthread_mutex_lock(&g_qt_proxy.task_mng.lock);
    // find task node from task list
    qt_proxy_task_node_t *pre = &g_qt_proxy.task_mng.task_list_head;
    qt_proxy_task_node_t *cur = pre->next;
    
    while (cur != NULL) {
        if (cur->task_id == msg->task_id) {
            break;
        }
        pre = cur;
        cur = cur->next;
    }
    if (cur == NULL) {
        printf("ecall ret msg proc not found task node by task_id:%lu\n", msg->task_id);
        pthread_mutex_unlock(&g_qt_proxy.task_mng.lock);
        return -1;
    }

    // copy msg->data to recv_buf
    if (msg->data_len > cur->recv_buf_len) {
        printf("recv buf len:%lu is not enough, recv msg len:%lu\n", cur->recv_buf_len, msg->data_len);
        pthread_mutex_unlock(&g_qt_proxy.task_mng.lock);
        return -1;
    }
    memcpy(cur->recv_buf, msg->data, msg->data_len);
    cur->recv_buf_len = msg->data_len;

    // signal to qt_rpc_proxy_call
    pthread_mutex_lock(&cur->lock);
    pthread_cond_signal(&cur->cond);
    pthread_mutex_unlock(&cur->lock);

    pthread_mutex_unlock(&g_qt_proxy.task_mng.lock);
    return 0;
}

void *qt_recv_task_proc(void *arg)
{
    (void)arg;
    int ret;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL); // 收到cancel信号后，state设置为CANCELED状态
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL); // 退出形式为立即退出
    qt_proxy_msg_node_t *cur_node = NULL;
    qt_proxy_msg_t *recv_msg = NULL;
    while (true) {
        pthread_testcancel();
        cur_node = qt_msg_queue_pop(&g_qt_proxy.msg_mng.recv_queue);
        if (cur_node == NULL) {
            // printf("recv task thread proc recv queue is empty\n");
            sleep(1);
            continue;
        }

        // handle recv msg node
        recv_msg = cur_node->msg;
        printf("[task handle thread] handle %s, task_id:%lu\n", get_msg_type_string(recv_msg->type), recv_msg->task_id);
        switch (recv_msg->type) {
            case QT_MSG_ECALL:
            case QT_MSG_OCALL:
                ret = qt_request_msg_proc(recv_msg);
                break;
            case QT_MSG_ECALL_RET:
            case QT_MSG_OCALL_RET:
                ret = qt_response_msg_proc(recv_msg);
                break;
            default:
                 printf("recv invalid msg type:%d\n", recv_msg->type);
                break;
        }

        qt_free_msg_node(cur_node);
    }
    (void)ret;

    return NULL;
}

static int qt_task_mng_init()
{
    int ret;
    uint32_t task_size = 10;
    uint32_t thread_pool_size = 5;

    // pool_size >= task_size * 2， 由于ecall中调用ocall会阻塞一个处理线程，极端情况下，pool_size应该等于num(ecall)+num(ocall)
    if (task_size < 1 || task_size > QT_TASK_MAX_NUM ||
        thread_pool_size < 1 || thread_pool_size > QT_THREAD_POOL_MAX_SIZE) {
            printf("invalid task size or thread pool size\n");
            return -1;
    }
    g_qt_proxy.task_mng.proxy_config.task_size = task_size;
    g_qt_proxy.task_mng.proxy_config.thread_pool_size = thread_pool_size;
    pthread_t *thread_pool = (pthread_t *)calloc(thread_pool_size, sizeof(pthread_t));
    if (thread_pool == NULL) {
        printf("malloc thread pool failed\n");
        return -1;
    }
    g_qt_proxy.task_mng.thread_pool = thread_pool;

    for (uint32_t i = 0; i < thread_pool_size; i++) {
        ret = pthread_create(thread_pool + i, NULL, qt_recv_task_proc, NULL);
        if (ret != 0) {
            qt_task_mng_thread_pool_destroy();
            free(thread_pool);
            return -1;
        }
    }

    return 0;
}

static qt_proxy_task_node_t* qt_new_task_node(uint8_t *recv_buf, size_t len)
{
    qt_proxy_task_node_t *task_node = calloc(1, sizeof(qt_proxy_task_node_t));
    if (task_node == NULL) {
        return NULL;
    }
    RAND_priv_bytes((uint8_t *)&task_node->task_id, sizeof(uint64_t));
    pthread_mutex_init(&task_node->lock, NULL);
    pthread_cond_init(&task_node->cond, NULL);
    task_node->recv_buf = recv_buf;
    task_node->recv_buf_len = len;

    return task_node;
}

static void qt_free_task_node(qt_proxy_task_node_t *task_node)
{
    if (task_node == NULL) {
        return;
    }
    pthread_cond_destroy(&task_node->cond);
    pthread_mutex_destroy(&task_node->lock);
    free(task_node);
    return;
}

static void qt_task_mng_destroy()
{
    pthread_mutex_lock(&g_qt_proxy.task_mng.lock);
    // destroy task list
    qt_proxy_task_node_t *pre = &g_qt_proxy.task_mng.task_list_head;
    qt_proxy_task_node_t *cur = pre->next;
    while (cur != NULL) {
        pre->next = cur->next;
        g_qt_proxy.task_mng.count--;
        
        // free cur node
        pthread_mutex_lock(&cur->lock);
        pthread_cond_signal(&cur->cond);
        pthread_mutex_unlock(&cur->lock);
        qt_free_task_node(cur);

        cur = pre->next;
    }
    pthread_mutex_unlock(&g_qt_proxy.task_mng.lock);
    free(g_qt_proxy.task_mng.thread_pool);

    return;
}

#define LIST_ADD(type, head, node) \
    type *tmp = (head)->next; (head)->next = (node); (node)->next = tmp;

static int qt_add_task_to_mng(uint8_t *recv_buf, size_t len, qt_proxy_task_node_t **node)
{
    // new qt_proxy_task_node_t
    qt_proxy_task_node_t *task_node = qt_new_task_node(recv_buf, len);
    if (task_node == NULL) {
        return -1;
    }

    pthread_mutex_lock(&g_qt_proxy.task_mng.lock);
    if (g_qt_proxy.task_mng.count >= QT_TASK_MAX_NUM) {
        pthread_mutex_unlock(&g_qt_proxy.task_mng.lock);
        qt_free_task_node(task_node);
        return CC_ERROR_TASK_NUM_EXCEED_MAX_LIMIT;
    }
    g_qt_proxy.task_mng.count++;
    LIST_ADD(qt_proxy_task_node_t, &(g_qt_proxy.task_mng.task_list_head), task_node);
    pthread_mutex_unlock(&g_qt_proxy.task_mng.lock);
    *node = task_node;
    
    return 0;
}

int qt_rpc_proxy_init(int cid, qt_handle_request_msg_t handle_func)
{
    int ret;
    // init qingtian vsock
    ret = qt_vsock_init(cid);
    if (ret != 0) {
        printf("qt vsock init failed ret:%d\n", ret);
        return ret;
    }

    // init send/recv list and thread
    ret = qt_msg_mng_init(handle_func);
    if (ret != 0) {
        printf("qt msg mng init failed ret:%d\n", ret);
        // todo destroy vsock
        return ret;
    }

    // init task mng and thread pool
    ret = qt_task_mng_init();
    if (ret != 0) {
        printf("qt task mng init failed ret:%d\n", ret);
        // todo destroy msg mng and vsock
        return ret;
    }

    return 0;
}

void qt_rpc_proxy_destroy()
{
    // destroy all thread
    qt_msg_thread_destroy();
    qt_task_mng_thread_pool_destroy();

    // destroy msg mng
    qt_msg_mng_destroy();

    // destroy task mng
    qt_task_mng_destroy();

    // disconnet vsock
    qt_vsock_destroy();

    return;
}

static int qt_del_task_from_mng(uint64_t task_id)
{
    pthread_mutex_lock(&g_qt_proxy.task_mng.lock);
    qt_proxy_task_node_t *pre = &g_qt_proxy.task_mng.task_list_head;
    qt_proxy_task_node_t *cur = pre->next;
    
    while (cur != NULL) {
        if (cur->task_id == task_id) {
            // del cur from list
            pre->next = cur->next;
            g_qt_proxy.task_mng.count--;
            break;
        }
        pre = cur;
        cur = cur->next;
    }
    pthread_mutex_unlock(&g_qt_proxy.task_mng.lock);

    // not found task node
    if (cur == NULL) {
        printf("qt_del_task_from_mng not found task node with task_id:%lu\n", task_id);
        return -1;
    }
    qt_free_task_node(cur);

    return 0;
}

int qt_rpc_proxy_call(uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len)
{
    // new task node by input, and add to task list
    qt_proxy_task_node_t *task_node = NULL;
    int ret = qt_add_task_to_mng(output, *output_len, &task_node);
    if (ret != 0) {
        printf("add task to mng failed, ret:%d\n", ret);
        return ret;
    }

    // add send msg to send list
    ret = add_msg_to_send_queue(task_node->task_id, input, input_len);
    if (ret != 0) {
        printf("add send msg to send list failed, ret:%d\n", ret);
        // todo revert task_node
        return ret;
    }
    // wait recv msg
    pthread_mutex_lock(&task_node->lock);
    pthread_cond_wait(&task_node->cond, &task_node->lock);
    pthread_mutex_unlock(&task_node->lock);

    *output_len = task_node->recv_buf_len;
    // del task node
    ret = qt_del_task_from_mng(task_node->task_id);
    if (ret != 0) {
        printf("get rsp msg from recv list failed\n");
        // todo revert task_node
        return -1;
    }

    return 0;
}

#ifdef ENCLAVE
extern int handle_ecall_function(uint8_t *input, size_t input_len, uint8_t **output, size_t *output_len);

static __attribute__((constructor)) void qt_enclave_proxy_init()
{
    int ret = qt_rpc_proxy_init(VMADDR_CID_ANY, handle_ecall_function);
    if (ret != 0) {
        printf("enclave proxy init failed\n");
    }
    printf("enclave proxy init success\n");
}
static __attribute__((destructor)) void qt_enclave_proxy_destroy()
{
    qt_rpc_proxy_destroy();
    printf("destroy enclave proxy\n");
}
#endif
