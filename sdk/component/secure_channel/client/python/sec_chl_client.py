import os
from _sec_chl import ffi, lib

def sec_chl_log_init(level):
    c_level = ffi.from_buffer("char []", level)
    lib.sec_chl_log_init(c_level)

# 初始化安全安全通道，返回通道上下文句柄
def sec_chl_open(send_callback, uuid):
    c_uuid = ffi.new("char []", uuid)
    chl_ctx = lib.sec_chl_init_wrapper(send_callback, c_uuid)
    if chl_ctx == ffi.NULL:
        print("secure channel open failed")
        return None
    return chl_ctx

# 关闭通道
def sec_chl_close(chl_ctx):
    print("secure channel close")
    lib.sec_chl_deinit_wrapper(chl_ctx)

# 使用指定的安全通道加密数据，返回加密后的密文
def sec_chl_encrypt(chl_ctx, plain):
    print("secure channel encrypt")

    c_plain = ffi.from_buffer("unsigned char[]", plain)
    plain_len = len(plain)
    c_cipher_len = ffi.new("size_t *", plain_len + 64) # 64 额外的加密数据空间
    c_cipher = ffi.new("unsigned char[]", c_cipher_len[0])
    result = lib.sec_chl_encrypt_wrapper(chl_ctx, c_plain, plain_len, c_cipher, c_cipher_len)
    if result != 0:
        print("encrpyt failed")
        return 0
    return bytes(ffi.buffer(c_cipher, c_cipher_len[0]))

# 使用指定的安全通道解密数据，返回明文
def sec_chl_decrypt(chl_ctx, cipher):
    print("secure channel decrypt")

    c_cipher = ffi.from_buffer("unsigned char[]", cipher)
    cipher_len = len(cipher)
    plain = ffi.new("unsigned char[]", cipher_len) # plain text length less cipher
    plain_len = ffi.new("size_t *", cipher_len)
    lib.sec_chl_decrypt_wrapper(chl_ctx, c_cipher, cipher_len, plain, plain_len)
    return bytes(ffi.buffer(plain, plain_len[0]))

# 处理安全通道接收的消息
def sec_chl_msg_recv_handle(chl_ctx, input):

    c_input = ffi.new("unsigned char[]", input)
    lib.sec_chl_msg_recv_handle(chl_ctx, c_input, len(c_input))
    return len(c_input)

def sec_chl_session_id(chl_ctx):
    return lib.sec_chl_session_id(chl_ctx)
