from cffi import FFI
ffi = FFI()
# 声明 C 函数原型
ffi.cdef("""
    typedef int (*write_callback_t)(void *conn, unsigned char *buf, size_t count);
    void sec_chl_log_init(const char *level);
    int sec_chl_init_wrapper(write_callback_t write, const char *enclave_path);
    int sec_chl_deinit_wrapper(void);
    int sec_chl_msg_recv_handle(unsigned char *buf, size_t buf_len);
    int sec_chl_recv_client_data_ex(int *retval, size_t session_id, unsigned char *data, size_t data_len);
    int sec_chl_get_client_data_handle_result_ex(int *retval, size_t session_id, unsigned char *data, size_t *data_len);
    """, packed=True
)

ffi.set_source(
    "_sec_chl",
    r"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include "secure_channel_host.h"
    #include "enclave.h"
    #include "sc_demo_u.h"
    #include "rust_attestation_agent.h"

    static cc_sec_chl_conn_ctx_t g_conn_ctx = {0};
    static cc_sec_chl_svr_ctx_t g_svr_ctx = {0};
    static cc_enclave_t g_enclave = {0};
    int conn = 1;

    typedef int (*write_callback_t)(void *conn, unsigned char *buf, size_t count);
    void sec_chl_log_init(const char *level)
    {
        Vec_uint8_t log_level = {
            .ptr = (uint8_t *)level,
            .len = strlen(level),
            .cap = strlen(level)
        };
        init_env_logger(&log_level);
    }

    int sec_chl_init_wrapper(write_callback_t write, const char *enclave_path)
    {
        int ret = cc_enclave_create(enclave_path, AUTO_ENCLAVE_TYPE, 0,SECGEAR_DEBUG_FLAG, NULL, 0, &g_enclave);
        if (ret != CC_SUCCESS) {
            printf("create enclave error %x!\n", ret);
            return -1;
        }
        g_svr_ctx.enclave_ctx = &g_enclave;
        ret = cc_sec_chl_svr_init(&g_svr_ctx);
        if (ret != CC_SUCCESS) {
            return -1;
        }
        g_conn_ctx.svr_ctx = &g_svr_ctx;
        g_conn_ctx.conn_kit.send = (cc_conn_opt_funcptr_t)write;
        g_conn_ctx.conn_kit.conn = &conn;
        return 0;
    }
    int sec_chl_deinit_wrapper(void)
    {
        cc_sec_chl_svr_fini(&g_svr_ctx);
        cc_enclave_destroy(&g_enclave);
        return 0;
    }
    int sec_chl_msg_recv_handle(unsigned char *buf, size_t buf_len)
    {
        int ret;
        ret = cc_sec_chl_svr_callback(&g_conn_ctx, (void *)buf, buf_len);
        if (ret != CC_SUCCESS) {
            printf("secure channel server handle require failed\n");
        }
        return ret;
    }
    int sec_chl_recv_client_data_ex(int *retval, size_t session_id, unsigned char *data, size_t data_len)
    {
        return sec_chl_recv_client_data(&g_enclave, retval, session_id, data, data_len);
    }
    int sec_chl_get_client_data_handle_result_ex(int *retval, size_t session_id, unsigned char *data, size_t *data_len)
    {
        return sec_chl_get_client_data_handle_result(&g_enclave, retval, session_id, data, data_len);
    }
    """,
    sources = ["./sc_demo_u.c"],
    include_dirs = ["/usr/include/secGear", "./"],
    library_dirs = ["/usr/lib64"],
    libraries = ["usecure_channel", "secgear"]
)

if __name__ == "__main__":
    ffi.compile(verbose = True)