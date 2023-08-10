/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include "enclave.h"
#include "helloworld_u.h"
#include "string.h"

#define BUF_LEN 32

int main()
{
    int  retval = 0;
    char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t *context = NULL;
    context = (cc_enclave_t *)malloc(sizeof(cc_enclave_t));
    if (!context) {
        return CC_ERROR_OUT_OF_MEMORY;
    }
    cc_enclave_result_t res;

    printf("Create secgear enclave\n");

    char real_p[PATH_MAX];
    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == NULL) {
	    if (getcwd(real_p, sizeof(real_p)) == NULL) {
		    printf("Cannot find enclave.sign.so");
		    return -1;
	    }
	    if (PATH_MAX - strlen(real_p) <= strlen("/enclave.signed.so")) {
		    printf("Failed to strcat enclave.sign.so path");
		    return -1;
	    }
	    (void)strcat(real_p, "/enclave.signed.so");
    }
enclave_features_t *feature = NULL;
int feature_cnt = 0;
enclave_type_t type = AUTO_ENCLAVE_TYPE;
#ifdef QT_ENCLAVE
    enclave_features_t features[2];
    features[0].setting_type = QINGTIAN_STARTUP_FEATURES;
    cc_startup_t pra;
    pra.cpus = 2;
    pra.enclave_cid = 4;
    pra.mem_mb = 512;
    pra.query_retry = 10;
    features[0].feature_desc = &pra;
    feature = &features[0];
    feature_cnt = 1;
    type = AUTO_ENCLAVE_TYPE;// QINGTIAN_ENCLAVE_TYPE;
#endif
    res = cc_enclave_create(real_p, type, 0, SECGEAR_DEBUG_FLAG, feature, feature_cnt, context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        return res;
    }

    res = get_string(context, &retval, buf);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Ecall enclave error\n");
    } else {
        printf("%s\n", buf);
    }

    res = cc_enclave_destroy(context);
    if(res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    }
    return res;
}
