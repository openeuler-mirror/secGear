from cffi import FFI
ffi = FFI()
# 声明 C 函数原型
ffi.cdef("""
    typedef int (*write_callback_t)(void *chl_ctx, unsigned char *buf, size_t count);
    void sec_chl_log_init(const char *level);
    void *sec_chl_init_wrapper(write_callback_t write, const char *base_value);
    void sec_chl_deinit_wrapper(void *ctx);
    int sec_chl_encrypt_wrapper(void *ctx, unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len);
    int sec_chl_decrypt_wrapper(void *ctx, unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len);
    int sec_chl_msg_recv_handle(void *ctx, unsigned char *buf, size_t buf_len);
    size_t sec_chl_session_id(void *ch_ctx);
""", packed=True
)

ffi.set_source(
    "_sec_chl",
    r"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include "secure_channel_client.h"
    #include "enclave.h"
    #include "rust_attestation_agent.h"

    typedef int (*write_callback_t)(void *chl_ctx, unsigned char *buf, size_t count);

    void sec_chl_log_init(const char *level)
    {
        Vec_uint8_t log_level = {
            .ptr = (uint8_t *)level,
            .len = strlen(level),
            .cap = strlen(level)
        };
        init_env_logger(&log_level);
    }

    cc_sec_chl_ctx_t *sec_chl_init_wrapper(write_callback_t write, const char *uuid)
    {
        cc_enclave_result_t ret;
        cc_sec_chl_ctx_t *ch_ctx = malloc(sizeof(cc_sec_chl_ctx_t));
        if (ch_ctx == NULL) {
            return NULL;
        }
        (void)memset((void *)ch_ctx, 0, sizeof(cc_sec_chl_ctx_t));
        ch_ctx->conn_kit.send = (cc_conn_opt_funcptr_t)write;
        ch_ctx->conn_kit.conn = ch_ctx;
        ch_ctx->uuid = (char *)uuid;
        ret = cc_sec_chl_client_init(CC_SEC_CHL_ALGO_RSA_ECDH_AES_GCM, ch_ctx);
        if (ret != CC_SUCCESS) {
            printf("secure channel init failed:%u\n", ret);
            free(ch_ctx);
            return NULL;
        }
        return ch_ctx;
    }
    void sec_chl_deinit_wrapper(void *ch_ctx)
    {
        cc_sec_chl_client_fini((cc_sec_chl_ctx_t *)ch_ctx);
        free(ch_ctx);
    }
    int sec_chl_encrypt_wrapper(void *ch_ctx, unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len)
    {
        return cc_sec_chl_client_encrypt((cc_sec_chl_ctx_t *)ch_ctx, (void *)input, input_len, (void *)output, output_len);
    }
    int sec_chl_decrypt_wrapper(void *ch_ctx, unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len)
    {
        return cc_sec_chl_client_decrypt((cc_sec_chl_ctx_t *)ch_ctx, (void *)input, input_len, (void *)output, output_len);
    }
    int sec_chl_msg_recv_handle(void *ch_ctx, unsigned char *buf, int buf_len)
    {
        return cc_sec_chl_client_callback((cc_sec_chl_ctx_t *)ch_ctx, buf, buf_len);
    }
    size_t sec_chl_session_id(void *ch_ctx)
    {
        cc_sec_chl_ctx_t *ctx = (cc_sec_chl_ctx_t *)ch_ctx;
        return ctx->session_id;
    }
    """,
    include_dirs = ["/usr/include/secGear", "./",
    "../../../../thirdparty/kunpengsecl/verifier/"],
    library_dirs = ["/usr/lib64"],
    libraries = ["csecure_channel", "secgear", "teeverifier"],
    extra_compile_args=["-g", "-O1"]
)

if __name__ == "__main__":
    ffi.compile(verbose = True)