import os
from _sec_chl import ffi, lib

def sec_chl_log_init(level):
    c_level = ffi.from_buffer("char []", level)
    lib.sec_chl_log_init(c_level)

def sec_chl_open(send_callback, enclave_path):
    c_enclave_path = ffi.new("char []", os.path.abspath(enclave_path))
    lib.sec_chl_init_wrapper(send_callback, c_enclave_path)

def sec_chl_close():
    lib.sec_chl_deinit_wrapper()

# 输入：input bytes类型
def sec_chl_msg_recv_handle(input):
    input_data = ffi.from_buffer("unsigned char[]", input)
    lib.sec_chl_msg_recv_handle(input_data, len(input))


# 输入：session_id 整形， data bytes类型
# 输出：返回值格式：当前函数返回值，ecall返回值
def sec_chl_recv_client_data_ex(session_id, input):
    retval = ffi.new("int *")
    input_data = ffi.from_buffer("unsigned char[]", input)
    ret = lib.sec_chl_recv_client_data_ex(retval, session_id, input_data, len(input))
    return (ret, retval[0])

# 输入：session_id 整形，output_max_len 最大输出长度
# 输出：返回值格式：当前函数返回值，ecall返回值，ecall返回数据（bytes 类型）
def sec_chl_get_client_data_handle_result_ex(session_id, output_max_len):
    retval = ffi.new("int *")
    output = ffi.new("unsigned char[]", output_max_len)
    output_len = ffi.new("size_t *", output_max_len)
    ret = lib.sec_chl_get_client_data_handle_result_ex(retval, session_id, output, output_len)
    return (ret, retval[0], bytes(ffi.buffer(output, output_len[0])))