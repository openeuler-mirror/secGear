#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <linux/limits.h>
#include "enclave.h"
#include "test_ta_u.h"
int main(int argc, char *argv[])
{
    int cid = 4;
    int cnt = 5;
    if (argc < 3) { // number of parameter must not exceed 3
        printf("start like ecall $CID, example: ecall 4\n");
        return 1;
    }
    if (1 != sscanf_s(argv[1], "%d", &cid)) { // index 1: cid
        printf("start like ecall $CID, example: ecall 4 5\n");
        return 1;
    }

    if (1 != sscanf_s(argv[2], "%d", &cnt)) { // index 2: ecall repeat times
        printf("start like ecall $CID, example: ecall 4 5\n");
        return 1;
    }

    char *path = PATH;
    cc_enclave_t *context = NULL;
    context = (cc_enclave_t *)malloc(sizeof(cc_enclave_t));
    if (!context) {
        return CC_ERROR_OUT_OF_MEMORY;
    }
    cc_enclave_result_t res;
    printf("Create secgear enclave\n");
    enclave_features_t feature;
    feature.setting_type = QINGTIAN_STARTUP_FEATURES;
    cc_startup_t pra;
    pra.cpus = 2; // number of cpu at least 2
    pra.enclave_cid = cid;
    pra.mem_mb = 512; // memmory size 512 MB
    pra.query_retry = 10; // query enclave try 10 times
    feature.feature_desc = &pra;

    res = cc_enclave_create(path, QINGTIAN_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &feature, 1, context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        free(context);
        return res;
    }
    int  retval = 0;
    char *buf = calloc(1, 1024);
    if (buf == NULL) {
        free(context);
        return 1;
    }
    while (cnt--) {
        res = get_string(context, &retval, buf);
        if (res != CC_SUCCESS) {
            printf("Ecall enclave error\n");
        }
    }
    free(buf);
    res = cc_enclave_destroy(context);
    if (res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    }
    free(context);
    return res;
}