/*
 * Copyright (c) IPADS@SJTU 2021. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdlib.h>
#include "qt_call.h"
#include "enclave_log.h"
#include "qt_log.h"
#include "host_input.h"

static const ocall_enclave_table_t *ocall_table;

void set_ocall_table(const void *table)
{
    ocall_table = table;
}

cc_enclave_result_t handle_ocall_function(
    const uint8_t *input_buffer,
    size_t input_buffer_size,
    uint8_t **output_buffer,
    size_t *output_bytes_written)
{
    qt_comm_msg_t *msg_recv = NULL;
    qt_comm_msg_t *msg_send = NULL;
    cc_enclave_result_t result_cc = CC_SUCCESS;

    if (input_buffer == NULL || input_buffer_size == 0 || output_buffer == NULL || output_bytes_written == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    // write nothing default
    *output_bytes_written = 0;
#if DEBUG
    QT_DEBUG("ocall received(%zu): ", input_buffer_size);
    for (size_t i = 0; i < input_buffer_size; i++) {
        QT_DEBUG("%02X", input_buffer[i]);
    }
    QT_DEBUG("\n");
#endif
    msg_recv = (qt_comm_msg_t *) input_buffer;
    cc_ocall_func_t func;
    if (msg_recv->function_id >= ocall_table->num) {
        result_cc = CC_ERROR_ECALL_NOT_ALLOWED;
        printf("function id(%u) not found(%u), ocall table size = %zu\n",
            msg_recv->function_id, result_cc, ocall_table->num);
        goto end;
    }
    func = ocall_table->ocalls[msg_recv->function_id];
    if (func == NULL) {
        result_cc = CC_ERROR_ITEM_NOT_FOUND;
        printf("ocall function not found(%u)\n", result_cc);
        goto end;
    }
    size_t send_len_total = sizeof(qt_comm_msg_t) + msg_recv->out_buf_size;
    msg_send = calloc(1, send_len_total);
    if (msg_send == NULL) {
        result_cc = CC_ERROR_SHORT_BUFFER;
        printf("short buffer(%u)\n", result_cc);
        goto end;
    }
    msg_send->function_id = msg_recv->function_id;
    msg_send->out_buf_size = msg_recv->out_buf_size;
    msg_send->buf_size = msg_recv->out_buf_size;
    
    result_cc = func(msg_recv->buf, msg_recv->buf_size, msg_send->buf,
                    msg_recv->buf_size);

    *output_buffer = (uint8_t *)msg_send;
    *output_bytes_written = send_len_total;
#if DEBUG
    QT_DEBUG("ocall result send(%zu): ", send_len_total);
    for (size_t i = 0; i < send_len_total; i++) {
        QT_DEBUG("%02X", *(*output_buffer + i));
    }
    QT_DEBUG("\n");
#endif
end:
    return result_cc;
}
