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

#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <stdlib.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* network transmission connection */
/**
* network transmission connection read/write function type
* @param[in] conn, The connection handle, such as the addr of fd over socket; or ssl* over SSL
*
* @param[in/out] buf, The buffer to be send
*
* @param[in] count, The number of bytes expect to send
*
* @retval On success, the actual number of bytes send is returned.
* On error, -1 is returned.
*/
typedef int (*cc_conn_opt_funcptr_t)(void *conn, void *buf, size_t count);

/* The struct of network transmission connection kit, include connection handler and send function */
typedef struct cc_connection_kit {
    cc_conn_opt_funcptr_t send;   // send msg callback
    void *conn;
} cc_conn_kit_t;

inline bool is_valid_conn_kit(cc_conn_kit_t *conn_kit)
{
    if (conn_kit == NULL || conn_kit->conn == NULL || conn_kit->send == NULL) {
        return false;
    }
    return true;
}

# ifdef  __cplusplus
}
# endif
#endif
