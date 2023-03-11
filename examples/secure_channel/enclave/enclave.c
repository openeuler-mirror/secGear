/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * CloudEnclave is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <string.h>

#include "status.h"
#include "sc_demo_t.h"
#include "secure_channel_enclave.h"
#include "secgear_log.h"


int sec_chl_recv_client_data(size_t session_id, uint8_t *data, size_t data_len)
{
    uint8_t plain[1024] = {0};
    size_t plain_len = 1024;
    int ret = cc_sec_chl_enclave_decrypt(session_id, data, data_len, plain, &plain_len);
    if (ret != 0) {
        PrintInfo(PRINT_ERROR, "sec_chl_recv_client_data decrypt data failed\n");
        return ret;
    }
    PrintInfo(PRINT_STRACE, "enclave recv secret:%s, real_len:%u, plain_len:%lu\n", plain, strlen((char *)plain), plain_len);
    return ret;
}

int sec_chl_get_enclave_secret(size_t session_id, uint8_t* data, size_t *data_len)
{
    char enclave_secret[] = "This is enclave secret 888";

    uint8_t encrypt[1024] = {0};
    size_t encrypt_len = 1024;
    int ret = cc_sec_chl_enclave_encrypt(session_id, enclave_secret, strlen(enclave_secret), encrypt, &encrypt_len);
    if (ret != 0) {
        PrintInfo(PRINT_ERROR, "sec_chl_get_enclave_secret encrypte data failed\n");
        return ret;
    }
    memcpy(data, encrypt, encrypt_len);
    *data_len =  encrypt_len;

    PrintInfo(PRINT_STRACE, "enclave send secret:%s, plain_len:%u, encrypt_len:%lu\n", enclave_secret, strlen((char *)enclave_secret), encrypt_len);
    return ret;
}
