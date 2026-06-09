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
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <linux/limits.h>
#include <random>
#include <string>

#include "enclave.h"
#include "da_u.h"
#include "common.h"
#include "tpch.h"

#include <string>
using namespace std;

clock_t start, stop;                                // 时间参数
unsigned long long begin2, end2, total = 0;         // CPU时钟周期数
unsigned long long begin1, end1, total1 = 0;        // CPU时钟周期数
cc_enclave_t global_eid = {};                       // 全局enclave_id
cc_enclave_result_t res = CC_FAIL;                  // enclave状态结果
uint8_t buf[VALUE_SIZE] = {0};                      // 无符号缓冲区
char temp[VALUE_SIZE + 1];                          // 字符串缓冲区
int retval = 0;                                     // ecall函数返回值

// 数据加密后存储在非安全区中，首地址传入TEE中，无需ocall直接访问
CustomerItem *customer_items = new CustomerItem[MAX_ITEM_NUM + 1];

// 测量CPU时钟周期数
static __inline__ unsigned long long rdtsc(void)
{
    unsigned hi;
    unsigned lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo)|(((unsigned long long)hi)<<32);   // 32字节
}

// 创建enclave
int CreateEnclave()
{
    int  retval = 0;
    const char *path = PATH;

    char real_p[PATH_MAX] = {0};
    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == NULL) {
        if (getcwd(real_p, sizeof(real_p)) == NULL) {
            printf("Cannot find enclave.sign.so");
            return res;
        }
        if (PATH_MAX - strlen(real_p) <= strlen("/enclave.signed.so")) {
            printf("Failed to strcat enclave.sign.so path");
            return res;
        }
        (void)strcat(real_p, "/enclave.signed.so");
    }
    // 创建飞地
    res = cc_enclave_create(
        real_p,
        AUTO_ENCLAVE_TYPE,
        0,
        SECGEAR_DEBUG_FLAG,
        NULL,
        0,
        &global_eid);
    return res;
}
// 销毁enclave
void DestoryEnclave()
{
    int retval = 0;
    res = cc_enclave_destroy(&global_eid);
    if (res != CC_SUCCESS) {
        printf("host destroy enclave error\n");
    } else {
        printf("host destroy enclave success\n");
    }
}

// 打印查询结果
void print_res(CustomerItem *res_item, size_t res_len)
{
    for (size_t i = 0; i < res_len; i++) {
        cout << "=========================================\n";
        cout << (i + 1) << ":" << endl;
        cout << "Key: " << res_item[i].CustomerKey << endl;
        cout << "Name: "<< res_item[i].Name << endl;
        cout << "Address: " << res_item[i].Address << endl;
        cout << "Nation: " << res_item[i].Nation << endl;
        cout << "Phone: " << res_item[i].Phone << endl;
        cout << "MktSegment: " << res_item[i].Mktsegment << endl;
        cout << "Comment: " << res_item[i].Comment << endl;
    }
}

// 生成数据
void generate_data()
{
     // 生成测试数据
    for (int i = 0; i <= MAX_ITEM_NUM; i++) {
        string temp = "hello";
        temp += std::to_string(std::random_device{}() % 10);   // 10取余，取随机数
        customer_items[i].CustomerKey = i;
        customer_items[i].Nation = std::random_device{}() % 10 + 1;    // 10取余，取随机数
        memcpy(customer_items[i].Comment, temp.c_str(), temp.length());
        memcpy(customer_items[i].Name, temp.c_str(), temp.length());
        memcpy(customer_items[i].Address, temp.c_str(), temp.length());
        memcpy(customer_items[i].Phone, temp.c_str(), temp.length());
        memcpy(customer_items[i].Acctbal, temp.c_str(), temp.length());
        memcpy(customer_items[i].Mktsegment, temp.c_str(), temp.length());
    }
}

// 查询数据
void get_data(int32_t* FieldList, size_t field_len, CustomerItem* item, CustomerItem* res_item, size_t* res_len)
{
    res = GetData(&global_eid,
                  &retval,
                  FieldList,                  // 字段
                  field_len,                  // 查询条件字段个数
                  (uint64_t)item,             // 查询条件
                  (uint64_t)res_item,         // 查询结果返回
                  res_len);                     // 查询结果个数
    if (res != CC_SUCCESS || retval != 0) {
        cout << "Search failed\n";
    } else {
        cout << "Search success\n";
        print_res(res_item, res_len[0]);
    }
    memset(res_len, 0, sizeof(size_t));
}

// 打印测试函数（ocall-function）
void print(uint64_t c)
{
    std::cout << c << std::endl;
}


int main()
{
    // 生成数据
    generate_data();
    // 创建飞地
    if (CreateEnclave() != 0) {
        std::cout << "Create enclave failed\n";
        return -1;
    }
    // 初始化数据
    res = InitCustomerItem(&global_eid,
                           &retval,
                           (uint64_t)customer_items,
                           MAX_ITEM_NUM);
    if (res != CC_SUCCESS || retval != 0) {
        cout << "Initiation failed\n";
        return res;
    } else {
        cout << "Init success\n";
    }
    // 设置查询条件(测试用例)
    CustomerItem* item = new CustomerItem();    // 暂存查询条件
    int32_t FieldList[32] = {0};                // 查询字段列表
    FieldList[0] = 3;                           // 查询字段名称，3为测试
    size_t res_len[2] = {0};                    // 返回结果长度
    size_t field_len = 1;                       // 查询字段个数
    
    item->CustomerKey = 101;                    // 101为测试
    memcpy(item->Name, "C_NAME", 6);            // 6为测试
    memcpy(item->Address, "hello3", 6);         // 6为测试
    item->Nation = 4;                           // 4为测试
 
    // 返回结果集合
    CustomerItem* res_item = new CustomerItem[MAX_BUF_SIZE];
    // 查询数据
    begin1 = rdtsc();
    get_data(FieldList, field_len, item, res_item, res_len);
    end1 = rdtsc();

    // 再次执行查询任务
    begin2 = rdtsc();
    get_data(FieldList, field_len, item, res_item, res_len);
    end2 = rdtsc();

    cout << "第一次查询CPU cycles (get data from table): " << end1 - begin1 << endl;
    cout << "第二次查询CPU cycles (get data from bucket): " << end2 - begin2 << endl;
    // 销毁飞地
    DestoryEnclave();

    return res;
}
