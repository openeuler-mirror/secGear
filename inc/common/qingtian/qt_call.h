#ifndef CALL_H
#define CALL_H
#include <stdint.h>
#include <stddef.h>
#include "status.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t function_id;
    size_t   out_buf_size;
    size_t   buf_size;
    uint8_t  buf[0];
} qt_comm_msg_t;

cc_enclave_result_t comm_call(uint32_t function_id,
    const void *input_buffer,
    size_t input_buffer_size,
    void *output_buffer,
    size_t output_buffer_size);

#ifdef  __cplusplus
}
#endif

#endif