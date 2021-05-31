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

#ifndef _SECGEAR_LOG_H
#define _SECGEAR_LOG_H

#include<stdio.h>

#ifndef PRINT_LEVEL
#define PRINT_LEVEL 0
#endif

#define PRINT_ERROR 0
#define PRINT_WARNING 1
#define PRINT_STRACE 2
#define PRINT_DEBUG 3

#define PrintInfo(level, fmt, args...)                               \
    if (level <= PRINT_LEVEL) {                                      \
        switch (level) {                                             \
            case 0:                                                  \
                SLog("%s " fmt "\n", "[secGear][ERROR]", ## args);   \
                break;                                               \
            case 1:                                                  \
                SLog("%s " fmt "\n", "[secGear][WARNING]", ## args); \
                break;                                               \
            case 2:                                                  \
                SLog("%s " fmt "\n", "[secGear][STRACE]", ## args);  \
                break;                                               \
            default:                                                 \
                SLog("%s " fmt "\n", "[secGear][DEBUG]", ## args);   \
        }                                                            \
    }

#endif
