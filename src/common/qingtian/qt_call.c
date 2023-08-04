#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "status.h"
#include "qt_rpc_proxy.h"
#include "qt_log.h"
#include "qt_call.h"

// send call raw data and wait response
static int32_t msg_send_recv(uint8_t* send_buf, size_t send_buf_size, uint8_t* recv_buf, size_t recv_buf_size)
{
    size_t recv_len = recv_buf_size;
    uint64_t ret;
    ret = qt_rpc_proxy_call(send_buf, send_buf_size, recv_buf, &recv_len);
    if (ret != 0) {
        return -1;
    }
    return recv_len;
}

cc_enclave_result_t comm_call(uint32_t function_id,
    const void *input_buffer,
    size_t input_buffer_size,
    void *output_buffer,
    size_t output_buffer_size)
{
    cc_enclave_result_t result_cc = CC_SUCCESS;
    qt_comm_msg_t *msg_recv = NULL;
    qt_comm_msg_t *msg_send = NULL;
    size_t send_len_total = 0;

    if (input_buffer == NULL || input_buffer_size == 0 || output_buffer == NULL || output_buffer_size == 0) {
        QT_ERR("comm call parameter check fail\n");
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (input_buffer_size > QT_VSOCK_MAX_DATA_LEN - sizeof(qt_comm_msg_t)) {
        QT_ERR("input buffer size out limit\n");
        return CC_ERROR_BAD_PARAMETERS;
    }
    send_len_total = sizeof(qt_comm_msg_t) + input_buffer_size;
    msg_send = calloc(1, send_len_total);
    if (msg_send == NULL) {
        QT_ERR("calloc buffer for send message fail\n");
        result_cc = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    msg_send->function_id = function_id;
    msg_send->out_buf_size = output_buffer_size;
    msg_send->buf_size = input_buffer_size;
    memcpy(msg_send->buf, input_buffer, input_buffer_size);

    // send and wait receive
    if (output_buffer_size > QT_VSOCK_MAX_DATA_LEN - sizeof(qt_comm_msg_t)) {
        QT_ERR("outpur buffer size out limit\n");
        result_cc = CC_ERROR_BAD_PARAMETERS;
        goto end;
    }
    size_t recv_buf_size = sizeof(qt_comm_msg_t) + output_buffer_size;
    msg_recv = calloc(1, recv_buf_size);
    if (msg_recv == NULL) {
        QT_ERR("calloc buffer for recv message fail\n");
        result_cc = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    QT_DEBUG("msg send and wait...\n");
    int recv_len = 0;
    recv_len = msg_send_recv((uint8_t *)msg_send, send_len_total, (uint8_t *)msg_recv, recv_buf_size);
    if (recv_len < 0) {
        QT_ERR("message send and recv fail\n");
        result_cc = CC_ERROR_GENERIC;
        goto end;
    }
    (void)memcpy(output_buffer, msg_recv->buf, msg_recv->buf_size);
end:
    if (msg_send) {
        free(msg_send);
    }
    if (msg_recv) {
        free(msg_recv);
    }
    return result_cc;
}