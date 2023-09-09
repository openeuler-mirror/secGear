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
#include "test_ta_t.h"
#include "secgear_random.h"

#define TA_HELLO_WORLD        "secgear hello world!"
#define BUF_MAX 32
int get_string(char *buf)
{
    strncpy(buf, TA_HELLO_WORLD, strlen(TA_HELLO_WORLD) + 1);
    return 0;
}

int get_40k(char *buf)
{
    memset(buf, 'L', 40960); // 40960 = 1024 * 40
    return 40960; // return string length 40960
}

int get_add(int a, int b)
{
    return a + b;
}

int64_t get_add_int64(int64_t a, int64_t b)
{
    return a + b;
}

uint64_t get_add_uint64(uint64_t a, uint64_t b)
{
    return a + b;
}

size_t get_add_size(size_t a, size_t b)
{
    return a + b;
}

int increase(int who, int a)
{
    int ret;
    int inc = a + 1;
    printf("increase call: a = %d\n", a);
    increase_result(&ret, who, inc);
    printf("ocall %s, ret = %d\n", __func__, ret);
    return inc;
}

void test_void_void(void)
{
    printf("test_void_void\n");
    printf("do ocall_void_void\n");
    ocall_void_void();
}
void test_void_int(int a)
{
    printf("a = %d", a);
    printf("test_void_int\n");
}
int test_int_void(void)
{
    printf("test_int_void\n");
    return 12345; // return 12345 by default
}

int test_int_inbuf(char *inbuf)
{
    printf("%s", inbuf);
    return strlen(inbuf);
}
int test_int_int_inbuf(int a, char *inbuf)
{
    printf("a = %d, inbuf = %s", a, inbuf);
    return strlen(inbuf);
}
int test_int_outbuf(char *outbuf)
{
    strcpy(outbuf, "test_int_outbuf");
    return strlen(outbuf);
}
int test_int_int_outbuf(int a, char *outbuf)
{
    printf("a = %d", a);
    strcpy(outbuf, "test_int_int_outbuf");
    return strlen(outbuf);
}
int test_int_inbuf_outbuf(char *inbuf, char *outbuf)
{
    printf("inbuf = %s", inbuf);
    strcpy(outbuf, "test_int_inbuf_outbuf");
    return strlen(outbuf);
}
int test_int_in_out_buf(char *buf)
{
    printf("inbuf = %s", buf);
    strcpy(buf, "test_int_in_out_buf");
    return strlen(buf);
}
uint32_t test_get_random(char *buf, int len)
{
    cc_enclave_result_t ret;
    ret = cc_enclave_generate_random(buf, len);
    if (ret != CC_SUCCESS) {
        printf("get random error: ret = %X", ret);
    }
    return (uint32_t)ret;
}
