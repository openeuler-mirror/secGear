/*
 * Copyright (c) 2026 secGear contributors.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
 * See the Mulan PSL v2 for more details.
 */

#include <string.h>
#include "seal_data_t.h"

#define ENC_PREFIX "ENC:"
#define ENC_PREFIX_LEN ((int)(sizeof(ENC_PREFIX) - sizeof(char)))
#define ENC_TAIL_LEN ((int)sizeof(char))
#define ENC_OVERHEAD_LEN (ENC_PREFIX_LEN + ENC_TAIL_LEN)

static void CopyBytes(char *dst, const char *src, int len)
{
    int i;

    if (dst == NULL || src == NULL || len <= 0) {
        return;
    }

    for (i = 0; i < len; ++i) {
        dst[i] = src[i];
    }
}

int SealData(char *plain, int plainLen, char *sealedBuf, int sealedBufLen, int *sealedLen)
{
    if (plain == NULL || sealedBuf == NULL || sealedLen == NULL) {
        return -1;
    }

    if (plainLen <= 0 || sealedBufLen < plainLen + ENC_OVERHEAD_LEN) {
        return -1;
    }

    CopyBytes(sealedBuf, ENC_PREFIX, ENC_PREFIX_LEN);
    CopyBytes(sealedBuf + ENC_PREFIX_LEN, plain, plainLen);
    sealedBuf[ENC_PREFIX_LEN + plainLen] = '\0';
    *sealedLen = plainLen + ENC_OVERHEAD_LEN;

    return 0;
}

int UnsealData(char *sealedBuf, int sealedLen, char *plainBuf, int plainBufLen, int *plainLen)
{
    int payloadLen;

    if (sealedBuf == NULL || plainBuf == NULL || plainLen == NULL) {
        return -1;
    }

    if (sealedLen <= ENC_OVERHEAD_LEN) {
        return -1;
    }

    payloadLen = sealedLen - ENC_OVERHEAD_LEN;
    if (payloadLen <= 0 || plainBufLen < payloadLen + ENC_TAIL_LEN) {
        return -1;
    }

    if (strncmp(sealedBuf, ENC_PREFIX, ENC_PREFIX_LEN) != 0) {
        return -1;
    }

    CopyBytes(plainBuf, sealedBuf + ENC_PREFIX_LEN, payloadLen);
    plainBuf[payloadLen] = '\0';
    *plainLen = payloadLen;

    return 0;
}
