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