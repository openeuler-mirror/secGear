#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secgear_log.h"
#include "qt_call.h"
#include "qt_rpc_proxy.h"
#include "enclave_input.h"

extern const cc_ecall_func_t cc_ecall_tables[];
extern const size_t ecall_table_size;

cc_enclave_result_t cc_ocall_enclave(
    size_t func_id,
    const void *in_buf,
    size_t in_buf_size,
    void *out_buf,
    size_t out_buf_size)
{
    return comm_call(func_id, in_buf, in_buf_size, out_buf, out_buf_size);
}

cc_enclave_result_t handle_ecall_function(
    const uint8_t *input_buffer,
    size_t input_buffer_size,
    uint8_t **output_buffer,
    size_t *output_bytes_written)
{
    qt_comm_msg_t *msg_recv = NULL;
    qt_comm_msg_t *msg_send = NULL;
    cc_enclave_result_t result_cc = CC_SUCCESS;

    if (input_buffer == NULL || input_buffer_size < sizeof(qt_comm_msg_t) ||
        output_buffer == NULL || output_bytes_written == NULL) {
        PrintInfo(PRINT_ERROR, "handle ecall parameter check fail");
        return CC_ERROR_BAD_PARAMETERS;
    }
    // write nothing default
    *output_bytes_written = 0;
    msg_recv = (qt_comm_msg_t *) input_buffer;

    if (msg_recv->buf_size != input_buffer_size - sizeof(qt_comm_msg_t)) {
        PrintInfo(PRINT_ERROR, "handle ecall input_buffer_size error");
        return CC_ERROR_BAD_PARAMETERS;
    }

    cc_ecall_func_t func;
    enclave_table_t ecall_table;
    ecall_table.ecalls = cc_ecall_tables;
    ecall_table.num = ecall_table_size;
    if (msg_recv->function_id >= ecall_table.num) {
        result_cc = CC_ERROR_ECALL_NOT_ALLOWED;
        PrintInfo(PRINT_ERROR, "function id(%u) not found(%u), ecall table size = %zu\n",
            msg_recv->function_id, result_cc, ecall_table_size);
        goto end;
    }
    func = ecall_table.ecalls[msg_recv->function_id];
    if (func == NULL) {
        result_cc = CC_ERROR_ITEM_NOT_FOUND;
        PrintInfo(PRINT_ERROR, "ecall function not found(%u)\n", result_cc);
        goto end;
    }
    if (msg_recv->out_buf_size > QT_VSOCK_MAX_DATA_LEN - sizeof(qt_comm_msg_t)) {
        PrintInfo(PRINT_ERROR, "handle ecall out buffer size out limit\n");
        result_cc = CC_ERROR_BAD_PARAMETERS;
        goto end;
    }
    size_t send_len_total = sizeof(qt_comm_msg_t) + msg_recv->out_buf_size;
    msg_send = calloc(1, send_len_total);
    if (msg_send == NULL) {
        result_cc = CC_ERROR_SHORT_BUFFER;
        PrintInfo(PRINT_ERROR, "short buffer(%u)\n", result_cc);
        goto end;
    }
    msg_send->function_id = msg_recv->function_id;
    msg_send->out_buf_size = msg_recv->out_buf_size;
    msg_send->buf_size = msg_send->out_buf_size;
    size_t write_len = 0;
    result_cc = func(msg_recv->buf, msg_recv->buf_size, msg_send->buf,
                    msg_send->buf_size, &write_len);
    msg_send->buf_size = write_len;

    *output_buffer = (uint8_t*)msg_send;
    *output_bytes_written = send_len_total - (msg_send->out_buf_size - write_len);
end:
    return result_cc;
}
