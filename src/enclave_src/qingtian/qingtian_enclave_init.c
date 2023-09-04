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
#include "qingtian_enclave_init.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <linux/vm_sockets.h>
#include <pthread.h>
#include "secgear_log.h"
#include <qtsm_lib.h>
#include "qt_rpc_proxy.h"

extern __attribute__((weak)) int qtsm_lib_init(void);
extern __attribute__((weak)) void qtsm_lib_exit(int qtsm_dev_fd);

static int g_qtsm_fd;
static pthread_mutex_t qtsm_fd_lock;
extern cc_enclave_result_t handle_ecall_function(uint8_t *input, size_t input_len, uint8_t **output, size_t *output_len);

static __attribute__((constructor)) void qt_enclave_init(void)
{
    int ret = qt_rpc_proxy_init(VMADDR_CID_ANY, handle_ecall_function);
    if (ret != 0) {
        PrintInfo(PRINT_ERROR, "enclave proxy init failed\n");
        return;
    }
    PrintInfo(PRINT_DEBUG, "enclave proxy init success\n");
}
static __attribute__((destructor)) void qt_enclave_destroy(void)
{
    qt_rpc_proxy_destroy();
    PrintInfo(PRINT_DEBUG, "destroy enclave proxy\n");
}

int qt_get_qtsm_fd(void)
{
    if (qtsm_lib_init == NULL || qtsm_lib_exit == NULL) {
        PrintInfo(PRINT_ERROR, "there is no symbol qtsm_lib_init or qtsm_lib_exit\n");
        return -1;
    }
    pthread_mutex_lock(&qtsm_fd_lock);
    g_qtsm_fd = qtsm_lib_init();
    if (g_qtsm_fd < 0) {
        pthread_mutex_unlock(&qtsm_fd_lock);
    }
    return g_qtsm_fd;
}

void qt_release_qtsm_fd(int fd)
{
    if (fd == g_qtsm_fd) {
        qtsm_lib_exit(g_qtsm_fd);
        g_qtsm_fd = -1;
        pthread_mutex_unlock(&qtsm_fd_lock);
    }

    return;
}