/*
 * Copyright (c) 2026 secGear contributors.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
 * See the Mulan PSL v2 for more details.
 */

#include "starterkit_t.h"

#define MSG "hello from secGear starterkit"

#define MESSAGE_BUF_SIZE 64

static int CopyString(char *dst, int dstLen, const char *src)
{
    int i;

    if (dst == NULL || src == NULL || dstLen <= 0) {
        return -1;
    }

    for (i = 0; src[i] != '\0'; ++i) {
        if (i + 1 >= dstLen) {
            dst[0] = '\0';
            return -1;
        }
        dst[i] = src[i];
    }

    dst[i] = '\0';
    return 0;
}

int GetMessage(char *buf)
{
    return CopyString(buf, MESSAGE_BUF_SIZE, MSG);
}

int AddNumbers(int a, int b, int *sum)
{
    if (sum == NULL) {
        return -1;
    }

    *sum = a + b;
    return 0;
}
