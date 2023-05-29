/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * CloudEnclave is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "secgear_log.h"
#include "sg_local_attest.h"
#include "status.h"
#include "la_demo_t.h"

int local_attest_test(char* taid, char* img_hash, char* mem_hash)
{
    cc_enclave_result_t ret = cc_local_attest(taid, img_hash, mem_hash);
    if (ret != CC_SUCCESS) {
        PrintInfo(PRINT_ERROR, "local attest failed ret:%u\n", ret);
        return ret;
    }

    return CC_SUCCESS;
}
