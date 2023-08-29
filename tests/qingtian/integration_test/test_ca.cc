#include <gtest/gtest.h>
#include <string.h>

#include "enclave.h"
#include "test_ta_u.h"

#define BUF_LEN 256

TEST(cc_enclave_test, normal_test)
{
    int  retval = 0;
    const char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t context;
    cc_enclave_result_t res;
    enclave_features_t *feature = NULL;
    int feature_cnt = 0;
    enclave_type_t type = AUTO_ENCLAVE_TYPE;

    memset(&context, 0, sizeof(context));
    res = cc_enclave_create(path, type, 0, SECGEAR_DEBUG_FLAG, feature, feature_cnt, &context);
    ASSERT_EQ(res, CC_SUCCESS);

    res = get_string(&context, &retval, buf);
    ASSERT_EQ(res, CC_SUCCESS);
    ASSERT_EQ(retval, CC_SUCCESS);
    
    res = cc_enclave_destroy(&context);
    ASSERT_EQ(res, CC_SUCCESS);
}

TEST(cc_enclave_test, enclave_err_context)
{
    int  retval = 0;
    const char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_result_t res;
    enclave_type_t type = AUTO_ENCLAVE_TYPE;

    res = cc_enclave_create(path, type, 0, SECGEAR_DEBUG_FLAG, NULL, 0, NULL);
    ASSERT_EQ(res, CC_ERROR_INVALID_ENCLAVE_ID);
}

TEST(cc_enclave_test, enclave_err_feature)
{
    int  retval = 0;
    const char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t context;
    cc_enclave_result_t res;
    enclave_type_t type = AUTO_ENCLAVE_TYPE;

    typedef struct {
        uint32_t host_worker;
        uint32_t enclave_worker;
    } config_t;
    config_t config_test = { 2, 2 };
    enclave_features_t features_test = { 1, &config_test };
    int feature_cnt = 0;

    memset(&context, 0, sizeof(context));
    res = cc_enclave_create(path, type, 0, SECGEAR_DEBUG_FLAG, &features_test, 0, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);

    res = cc_enclave_create(path, type, 0, SECGEAR_DEBUG_FLAG, NULL, 1, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);

    res = cc_enclave_create(path, type, 0, SECGEAR_DEBUG_FLAG, NULL, 1.0, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);

    res = cc_enclave_create(path, type, 0, SECGEAR_DEBUG_FLAG, NULL, -1, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);

    res = cc_enclave_create(path, GP_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &features_test, 1, &context);
    ASSERT_EQ(res, CC_ERROR_INVALID_HANDLE);
}

TEST(cc_enclave_test, enclave_err_flags)
{
    int  retval = 0;
    const char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t context;
    cc_enclave_result_t res;
    enclave_type_t type = AUTO_ENCLAVE_TYPE;

    memset(&context, 0, sizeof(context));
    res = cc_enclave_create(path, type, 0, 2, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_NOT_SUPPORTED);

    res = cc_enclave_create(path, type, 0, -1, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_NOT_SUPPORTED);
}

TEST(cc_enclave_test, enclave_err_path)
{
    int  retval = 0;
    char buf[BUF_LEN];
    cc_enclave_t context;
    cc_enclave_result_t res;
    enclave_type_t type = AUTO_ENCLAVE_TYPE;

    const char *path_error1 = "./data/1111111";
    const char *path_error2 = "./@data/enclave.signed.so";
    const char *path_error3 = "./@data/enclave.eiff";

    memset(&context, 0, sizeof(context));

    res = cc_enclave_create(path_error1, type, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_INVALID_PATH);

    res = cc_enclave_create(path_error2, type, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_INVALID_PATH);

    res = cc_enclave_create(path_error3, type, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_INVALID_PATH);
}

TEST(cc_enclave_test, enclave_err_type)
{
    int  retval = 0;
    const char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t context;
    cc_enclave_result_t res;
    enclave_type_t type = AUTO_ENCLAVE_TYPE;

    memset(&context, 0, sizeof(context));
    res = cc_enclave_create(path, ENCLAVE_TYPE_MAX, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);

    res = cc_enclave_create(path, (enclave_type_t)4, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);

    res = cc_enclave_create(path, GP_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_INVALID_HANDLE);

    res = cc_enclave_create(path, (enclave_type_t)1, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_INVALID_HANDLE);
}

TEST(cc_enclave_test, enclave_err_version)
{
    int  retval = 0;
    const char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t context;
    cc_enclave_result_t res;
    enclave_type_t type = AUTO_ENCLAVE_TYPE;

    memset(&context, 0, sizeof(context));
    res = cc_enclave_create(path, type, 1, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);

    res = cc_enclave_create(path, type, -1, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);

    res = cc_enclave_create(path, type, 1.0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    ASSERT_EQ(res, CC_ERROR_BAD_PARAMETERS);
}

static int encalve_init(cc_enclave_t **ctx, cc_startup_t *pra)
{
    cc_enclave_result_t res;
    *ctx = (cc_enclave_t *)calloc(1, sizeof(cc_enclave_t));
    if (!*ctx) {
        return CC_ERROR_OUT_OF_MEMORY;
    }

    pra->cpus = 2; // number of cpu at least 2
    pra->enclave_cid = 4; // cid is 4 by default
    pra->mem_mb = 512; // memmory size 512 MB
    pra->query_retry = 10; // query enclave try 10 times
}

static int encalve_deinit(cc_enclave_t *ctx)
{
    free(ctx);
}

TEST(cc_enclave_test, test_enclave_repeat_start)
{
    printf("Test: start two same encalve\n");
    cc_enclave_result_t res;
    cc_enclave_t *context = NULL;
    cc_enclave_t *context2 = NULL;
    cc_startup_t pra;
    enclave_features_t feature;
    encalve_init(&context, &pra);
    encalve_init(&context2, &pra);
    feature.setting_type = QINGTIAN_STARTUP_FEATURES;
    feature.feature_desc = &pra;
    const char *path = PATH;
    
    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context);
    ASSERT_EQ(res, CC_SUCCESS);

    /* expect fail: repeat create */
    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context2);
    ASSERT_NE(res, CC_SUCCESS);

    res = cc_enclave_destroy(context);
    ASSERT_EQ(res, CC_SUCCESS);

    free(context);
    free(context2);
}

class QingtianEnclaveTest : public testing::Test {
protected:
    void SetUp()
    {
        context = (cc_enclave_t *)calloc(1, sizeof(cc_enclave_t));
        pra.cpus = 2; // number of cpu at least 2
        pra.enclave_cid = cid;
        pra.mem_mb = 512; // memmory size 512 MB
        pra.query_retry = 10; // query enclave try 10 times

        feature.setting_type = QINGTIAN_STARTUP_FEATURES;
        feature.feature_desc = &pra;
    }

    void Teardown()
    {
        free(context);
    }
    cc_enclave_t *context;
    cc_startup_t pra;
    enclave_features_t feature;
    cc_enclave_result_t res;
    const char *path = PATH;
};

TEST_F(QingtianEnclaveTest, test_enclave_repeat_destroy)
{
    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context);
    ASSERT_EQ(res, CC_SUCCESS);

    res = cc_enclave_destroy(context);
    ASSERT_EQ(res, CC_SUCCESS);

    res = cc_enclave_destroy(context);
    ASSERT_NE(res, CC_SUCCESS);
}

TEST_F(QingtianEnclaveTest, test_repeat_ecall)
{
    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context);
    ASSERT_EQ(res, CC_SUCCESS);

    int  retval = 0;
    char *buf = static_cast<char *>calloc(1, 1024);
    ASSERT_NE(buf, NULL);
    int cnt = 10; // repate 10

    int a = 11;
    int b = 22;
    while (cnt--) {
        res = get_string(context, &retval, buf);
        printf("return val = %d, buf[len = %zu] %s\n", retval, strlen(buf), buf);
        ASSERT_EQ(res, CC_SUCCESS);

        res = get_add(context, &retval, a, b);
        printf("%d + %d = %d\n", a, b, retval);
        ASSERT_EQ(res, CC_SUCCESS);
        ASSERT_EQ(retval, a + b);
        a++;
        b++;
    }

    free(buf);
    res = cc_enclave_destroy(context);
    ASSERT_EQ(res, CC_SUCCESS);
}

typedef struct {
    cc_enclave_t *ctx;
    int index;
    bool fail;
}ctx_t;
static bool ecall_continue = true;
static ctx_t *list = nullptr;
static size_t list_size = 0;
static void *ecall_thread(void *arg)
{
    ctx_t *thread_ctx = (ctx_t *)arg;
    cc_enclave_t *ctx = thread_ctx->ctx;
    int  retval = 0;
    char *buf = static_cast<char *>calloc(1, 1024);
    if (buf == nullptr) {
        thread_ctx->fail = true;
        return nullptr;
    }
    cc_enclave_result_t res;
    int a = 11;
    int b = 22;
    int inc = 0;

    while (ecall_continue) {
        res = get_string(ctx, &retval, buf);
        if (res != CC_SUCCESS) {
            thread_ctx->fail = true;
            printf("Ecall enclave error\n");
            break;
        } else {
            printf("return val = %d, buf[len = %zu] %s\n", retval, strlen(buf), buf);
        }
        res = get_add(ctx, &retval, a, b);
        if (res != CC_SUCCESS || retval != a + b) {
            thread_ctx->fail = true;
            printf("add Ecall enclave error\n");
            break;
        } else {
            printf("sum is %d\n", retval);
        }
        a++;
        b++;

        res = increase(ctx, &retval, thread_ctx->index, inc);
        if (res != CC_SUCCESS || retval != inc + 1) {
            thread_ctx->fail = true;
            printf("increase  ocall enclave error\n");
            break;
        } else {
            printf("%d + 1 = %d\n", inc, retval);
        }
        inc++;
    }
    free(buf);
    return nullptr;
}
TEST_F(QingtianEnclaveTest, test_ecall_multithread)
{
    pthread_t *thread_list;
    size_t thread_cnt = 2;
    printf("Test: ecall multithread: threads = %d\n", thread_cnt);

    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context);
    ASSERT_EQ(res, CC_SUCCESS);

    list_size = thread_cnt;
    list = static_cast<ctx_t *>calloc(1, list_size * sizeof(ctx_t));
    for (int i = 0; i < list_size; i++) {
        list[i].ctx = context;
        list[i].index = i;
        list[i].fail = false;
    }

    thread_list = (pthread_t *)calloc(1, thread_cnt * sizeof(pthread_t));
    for (int i = 0; i < thread_cnt; i++) {
        pthread_create(&thread_list[i], NULL, ecall_thread, (void *)&list[i]);
    }

    int cnt = 10;
    printf("count down\n");
    while (cnt--) {
        printf("%d\n", cnt);
        sleep(1);
    }
    ecall_continue = false;

    printf("wait thread finish\n");
    int ret = 0;
    for (int i = 0; i < thread_cnt; i++) {
        ret = pthread_join(thread_list[i], NULL);
        ASSERT_EQ(ret, 0);
        printf("thread %d finish\n", i + 1);
    }

    res = cc_enclave_destroy(context);
    ASSERT_EQ(res, CC_SUCCESS);

    for (int i = 0; i < thread_cnt; i++) {
        ASSERT_EQ(list[i].fail, false);
    }
}

TEST_F(QingtianEnclaveTest, test_ecall_multiprocess)
{
    FILE *fp1 = NULL;
    FILE *fp2 = NULL;
    char *cid1 = "4";
    char *cid2 = "5";
    printf("Test: do ecall by two process\n");
    fp1 = popen("./do_ecall 4 5", "r");
    ASSERT_TRUE(fp1 != NULL);

    fp2 = popen("./do_ecall 5 5", "r");
    ASSERT_TRUE(fp2 != NULL);

    char read_buf[1024];
    int cnt = 20;
    printf("wait and check child process result\n");
    while (cnt--) {
        printf(".%d ", cnt);
        if (fgets(read_buf, MAX_BUF_LINE_MAX, fp1) != NULL) {
            ASSERT_TRUE(strstr(read_buf, "error") == nullptr);
            printf("CID = "CID1" :%s\n", read_buf);
        }

        if (fgets(read_buf, MAX_BUF_LINE_MAX, fp2) != NULL) {
            ASSERT_TRUE(strstr(read_buf, "error") == nullptr);
            printf("CID = "CID2" :%s\n", read_buf);
        }
        sleep(1);
    }
}

TEST_F(QingtianEnclaveTest, test_func_all_types)
{
    printf("Test: do ecall with types\n");
   
    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context);
    ASSERT_EQ(res, CC_SUCCESS);

    printf("do test_void_void\n");
    res = test_void_void(context);
    ASSERT_EQ(res, CC_SUCCESS);

    printf("do test_int_void\n");
    int retval;
    res = test_int_void(context, &retval);
    ASSERT_EQ(res, CC_SUCCESS);
    ASSERT_EQ(retval, 12345); // return value 12345

    printf("do test_int_inbuf\n");
    char *inbuf = "inbuf";
    res = test_int_inbuf(context, &retval, inbuf);
    ASSERT_EQ(res, CC_SUCCESS);
    ASSERT_EQ(retval, strlen(inbuf));

    printf("do test_int_int_inbuf\n");
    int a = 123;
    res != test_int_int_inbuf(context, &retval, a, inbuf);
    ASSERT_EQ(res, CC_SUCCESS);
    ASSERT_EQ(retval, strlen(inbuf));

    printf("do test_int_outbuf\n");
    char outbuf[64] = {"\0"};
    res = test_int_outbuf(context, &retval, outbuf);
    ASSERT_EQ(res, CC_SUCCESS);
    ASSERT_EQ(retval, strlen(outbuf));

    printf("do test_int_int_outbuf\n");
    res = test_int_int_outbuf(context, &retval, a, outbuf);
    ASSERT_EQ(res, CC_SUCCESS);
    ASSERT_EQ(retval, strlen(outbuf));

    printf("do test_int_inbuf_outbuf\n");
    res = test_int_inbuf_outbuf(context, &retval, inbuf, outbuf);
    ASSERT_EQ(res, CC_SUCCESS);
    ASSERT_EQ(0, strcmp("test_int_inbuf_outbuf", outbuf));

    printf("do test_int_in_out_buf\n");
    res = test_int_in_out_buf(context, &retval, outbuf);
    ASSERT_EQ(res, CC_SUCCESS);
    ASSERT_EQ(0, strcmp("test_int_in_out_buf", outbuf));

    res = cc_enclave_destroy(context);
    ASSERT_EQ(res, CC_SUCCESS);
}

TEST_F(QingtianEnclaveTest, test_40K_ecall)
{
    printf("Test: get 40K ecall\n");
    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context);
    ASSERT_EQ(res, CC_SUCCESS);

    int  retval = 0;
    char *buf = static_cast<char *>calloc(1, 40960 + 1);
    ASSERT_NE(buf, NULL);
    int cnt = 10;
    while (cnt--) {
        res = get_40k(context, &retval, buf);
        printf("return val = %d, buf[len = %zu] %s\n", retval, strlen(buf), buf);
        ASSERT_EQ(res, CC_SUCCESS);
    }
    free(buf);
    res = cc_enclave_destroy(context);
    ASSERT_EQ(res, CC_SUCCESS);
}

TEST_F(QingtianEnclaveTest, test_func_get_random)
{
    printf("Test: get random\n");
    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context);
    ASSERT_EQ(res, CC_SUCCESS);

    uint32_t  retval = 0;
    uint8_t *buf = (uint8_t *)calloc(1, 1024 + 1);
    ASSERT_NE(buf, NULL);
    const int len = 64;
    int cnt = 10;
    size_t zero_cnt = 0;
    while (cnt--) {
        res = test_get_random(context, &retval, (char*)buf, len);
        ASSERT_EQ(res, CC_SUCCESS);
        zero_cnt = 0;
        printf("random[%d]: ", len);
        for (int i = 0; i < len; i++) {
            printf("%02X", buf[i]);
            if (buf[i] == 0x00) {
                zero_cnt++;
            }
        }
        printf("\n");
        ASSERT_NE(zero_cnt, len);
    }
    free(buf);
    res = cc_enclave_destroy(context);
    ASSERT_EQ(res, CC_SUCCESS);
}
