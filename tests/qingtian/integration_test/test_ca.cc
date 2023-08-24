#include <gtest/gtest.h>
#include <string.h>

#include "enclave.h"
#include "test_ta_u.h"

#define BUF_LEN 256

TEST(cc_enclave_test, normal_test)
{
    int  retval = 0;
    char *path = PATH;
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

TEST(cc_enclave_test, fail_test)
{
    // ASSERT_STREQ("100", "100");
}
