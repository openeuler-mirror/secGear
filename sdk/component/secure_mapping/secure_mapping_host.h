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

#ifndef SECURE_MAPPING_HOST_H
#define SECURE_MAPPING_HOST_H

#define INVALID_MAPPING_ID UINT64_MAX

enum SM_ERROR_LS {
    SM_ERR_NO_ERROR = 0,
    SM_ERR_INVALID_PARAMETER_VALUE = 1,
    SM_ERR_OUT_OF_MEMORY = 5,
    SM_ERR_NO_KEY = 7,
    SM_ERR_SWL_NO_SUPPORT = 63,
};

#endif
