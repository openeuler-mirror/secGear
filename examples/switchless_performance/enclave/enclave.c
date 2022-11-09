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

static int i = 0;
static int j = 0;

void ecall_empty(void)
{
    printf("normal %d\n", __atomic_add_fetch(&i, 1, __ATOMIC_ACQ_REL));
}

int ecall_empty1(char *buf, int len)
{
    printf("normal1 %d\n", __atomic_add_fetch(&i, 1, __ATOMIC_ACQ_REL));

    if (buf == NULL || len < 0) {
        return -1;
    }

    for (int i = 0; i < len; ++i) {
        if (buf[i] >= 'a' && buf[i] <= 'z') {
            buf[i] = buf[i] - ('a' - 'A');
        }
    }

    return 1;
}

int ecall_empty2(char *buf1, int len1, char *buf2, int len2)
{
    printf("normal2 %d\n", __atomic_add_fetch(&i, 1, __ATOMIC_ACQ_REL));

    if (buf1 == NULL || len1 < 0 || buf2 == NULL || len2 < 0) {
        return -1;
    }

    for (int i = 0; i < len2; ++i) {
        if (buf1[i] >= 'a' && buf1[i] <= 'z') {
            buf2[i] = buf1[i] - ('a' - 'A');
        } else {
            buf2[i] = buf1[i];
        }
    }

    return 2;
}

void ecall_empty_switchless(void)
{
    printf("sl %d\n", __atomic_add_fetch(&j, 1, __ATOMIC_ACQ_REL));
}

int ecall_empty_switchless1(char *buf, int len)
{
    printf("sl1 %d\n", __atomic_add_fetch(&j, 1, __ATOMIC_ACQ_REL));

    if (buf == NULL || len < 0) {
        return -1;
    }

    for (int i = 0; i < len; ++i) {
        if (buf[i] >= 'a' && buf[i] <= 'z') {
            buf[i] = buf[i] - ('a' - 'A');
        }
    }

    return 1;
}

int ecall_empty_switchless2(char *buf1, int len1, char *buf2, int len2)
{
    printf("sl2 %d\n", __atomic_add_fetch(&j, 1, __ATOMIC_ACQ_REL));

    if (buf1 == NULL || len1 < 0 || buf2 == NULL || len2 < 0) {
        return -1;
    }

    for (int i = 0; i < len2; ++i) {
        if (buf1[i] >= 'a' && buf1[i] <= 'z') {
            buf2[i] = buf1[i] - ('a' - 'A');
        } else {
            buf2[i] = buf1[i];
        }
    }

    return 2;
}
