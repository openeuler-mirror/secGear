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
#include "sg_local_attest.h"
#include "local_attest_agent.h"

cc_enclave_result_t cc_local_attest(char *taid, char *img_hash, char *mem_hash)
{
    if (taid == NULL || img_hash == NULL || mem_hash == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    
    return agent_local_attest(taid, img_hash, mem_hash);
}
