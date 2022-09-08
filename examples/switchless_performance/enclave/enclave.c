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
#include <string.h>
#include "switchless_t.h"


void test_toupper(char *buf, int len)
{
    if (buf == NULL || len < 0) {
        return;
    }

    for (int i = 0; i < len; ++i) {
        if (buf[i] >= 'a' && buf[i] <= 'z') {
            buf[i] = buf[i] - ('a' - 'A');
        }
    }
}

void ecall_empty(void)
{
}

void ecall_empty_switchless(void)
{
}
