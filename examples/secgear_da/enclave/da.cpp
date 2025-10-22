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


#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <any>
#include <variant>
#include <cstring>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include "common.h"
#include "tpch.h"

#include "da_t.h"
using namespace std;

#define TA_HELLO_WORLD        "secgear hello world!"
#define BUF_MAX 32

const uint8_t userkey[16] = {   // AES密钥生成参数
    '1', '2', '3', '4',
    '5', '6', '7', '8',
    '9', '0', '1', '2',
    '3', '4', '5', '6'
};
// 分组加密
uint8_t aes_in[16] = {0}, aes_out[16] = {0};

// 加解密秘钥
AES_KEY encrypt_key, decrypt_key;

// 相关数据结构定义
CustomerItem* customer_items;       // 数据指针
size_t customer_items_size = 0;
CustomerBucket customer_bucket;     // 缓存桶
AccessCounter ac_counter;           // 访问频次计数器


int get_string(char *buf)
{
    strncpy(buf, TA_HELLO_WORLD, strlen(TA_HELLO_WORLD) + 1);
    return 0;
}


// 加密
void AES_Encrypt(KEY &Key)
{
    uint8_t *value = (uint8_t *)Key.val_ptr;            // 获取value值
    AES_set_encrypt_key(userkey, 128, &encrypt_key);    // 生成128bit加密秘钥
    for (size_t i = 0; i < Key.val_size; i+=16) {       // 取16字节
        memcpy(aes_in, value+i, 16);            // 取16字节
        AES_ecb_encrypt(aes_in, aes_out, &encrypt_key, AES_ENCRYPT);    // 加密
        memcpy(value+i, aes_out, 16);           // 取16字节拷贝回去
    }
}
// 解密
void AES_Decrypt(KEY Key, uint8_t *buf)
{
    uint8_t *value = (uint8_t *)Key.val_ptr;
    AES_set_decrypt_key(userkey, 128, &decrypt_key);    // 生成128bit解密密钥
    for (size_t i = 0; i < Key.val_size; i+=16) {       // 取16字节
        memcpy(aes_in, value+i, 16);             // 取16字节
        AES_ecb_encrypt(aes_in, aes_out, &decrypt_key, AES_DECRYPT);    // 解密
        memcpy(buf+i, aes_out, 16);             // 取16字节拷贝到buf
    }
}
// char* 转string
string toString(char* arr)
{
    string str = string(arr);
    return str;
}

/**
* 初始化函数
* @param customer_items_addr customer表在不可信内存中的地址
* @param item_num customer表的大小
*/
int InitCustomerItem(uint64_t customer_items_addr, size_t cust_size)
{
    customer_items = (CustomerItem*)customer_items_addr;
    customer_items_size = cust_size;
    return 0;
}

/**
* 从表中搜索数据
* @param FieldIndex 查找字段
* @param item 查找条件
* @param res_item 结果集合
* @param res_len 返回结果长度
*/
int SearchFromTable(int FieldIndex, CustomerItem* item, CustomerItem* res_item, size_t* res_len)
{
    Variant var_tar;
    Variant var_src;
    int type_id;
    switch (FieldIndex) {
        case C_CUSTKEY_COUNTER: var_tar = item->CustomerKey; break;
        case C_NAME_COUNTER: var_tar = toString(item->Name); break;
        case C_ADDRESS_COUNTER: var_tar = toString(item->Address); break;
        case C_NATION_COUNTER: var_tar = item->Nation; break;
        case C_PHONE_COUNTER: var_tar = toString(item->Phone); break;
        case C_ACCTBAL_COUNTER: var_tar = toString(item->Mktsegment); break;
        case C_COMMENT_COUNTER: var_tar = toString(item->Comment); break;
        default: break;
    }
    type_id = var_tar.index();
    // 查找
    for (size_t i = 0; i < customer_items_size; i++) {
        switch (FieldIndex) {
            case C_CUSTKEY_COUNTER: var_src = customer_items[i].CustomerKey; break;
            case C_NAME_COUNTER: var_src = customer_items[i].Name; break;
            case C_ADDRESS_COUNTER: var_src = customer_items[i].Address; break;
            case C_NATION_COUNTER: var_src = customer_items[i].Nation; break;
            case C_PHONE_COUNTER: var_src = customer_items[i].Phone; break;
            case C_ACCTBAL_COUNTER: var_src = customer_items[i].Acctbal; break;
            case C_COMMENT_COUNTER: var_src = customer_items[i].Comment; break;
            default: break;
        }
        if (var_src == var_tar) {
            print(1);
            memcpy(&res_item[res_len[0]++], &customer_items[i], sizeof(CustomerItem));
        }
    }
    return 0;
}


/**
* 从桶中搜索数据
* @param FieldIndex 查找字段
* @param item 查找条件
* @param res_item 结果集合
* @param res_len 返回结果长度
*/
int SearchFromBucket(int FieldIndex, CustomerItem* item, CustomerItem* res_item, size_t* res_len)
{
    Variant var_tar;
    Variant var_src;       // 比较变量
    int type_id;                    // 数据类型

    switch (FieldIndex) {
        case C_CUSTKEY_COUNTER: var_tar = item->CustomerKey; break;
        case C_NAME_COUNTER: var_tar = toString(item->Name); break;
        case C_ADDRESS_COUNTER: var_tar = toString(item->Address); break;
        case C_NATION_COUNTER: var_tar = item->Nation; break;
        case C_PHONE_COUNTER: var_tar = toString(item->Phone); break;
        case C_ACCTBAL_COUNTER: var_tar = toString(item->Mktsegment); break;
        case C_COMMENT_COUNTER: var_tar = toString(item->Comment); break;
        default: break;
    }
    type_id = var_tar.index();

    // 先在桶里找
    for (BucketItem::iterator it = customer_bucket[FieldIndex].begin();it != customer_bucket[FieldIndex].end(); it++) {
        var_src = it->first;
        // 如果相等
        if (var_tar == var_src) {
            print(12580);               // 12580代成功
            res_len[0] = it->second.size();
            for (int i = 0; i < it->second.size(); i++) {
                memcpy(&res_item[it->second[i]], &customer_items[it->second[i]], sizeof(CustomerItem));
            }
        }
    }
    // 找不到再去表里搜
    if (res_len[0] == 0) {
        SearchFromTable(FieldIndex, item, res_item, res_len);
    }

    return 0;
}


/**
* 根据计数器调整桶
*/

void ProcessBucketItem(size_t bucket_type, int index, int key)
{
    switch (bucket_type) {
        case C_CUSTKEY_COUNTER:
            customer_bucket[bucket_type][customer_items[index].CustomerKey].push_back(key);
            break;    // bucketitem
        case C_NAME_COUNTER:
            customer_bucket[bucket_type][customer_items[index].Name].push_back(key);
            break;
        case C_ADDRESS_COUNTER:
            customer_bucket[bucket_type][customer_items[index].Address].push_back(key);
            break;
        case C_NATION_COUNTER:
            customer_bucket[bucket_type][customer_items[index].Nation].push_back(key);
            break;
        case C_PHONE_COUNTER:
            customer_bucket[bucket_type][customer_items[index].Phone].push_back(key);
            break;
        case C_ACCTBAL_COUNTER:
            customer_bucket[bucket_type][customer_items[index].Acctbal].push_back(key);
            break;
        case C_MKTSEGMENT_COUNTER:
            customer_bucket[bucket_type][customer_items[index].Mktsegment].push_back(key);
            break;
        case C_COMMENT_COUNTER:
            customer_bucket[bucket_type][customer_items[index].Comment].push_back(key);
            break;
        default: break;
    }
}

void ProcessCounterItems(size_t bucket_type)
{
    if (ac_counter[bucket_type].size() == 0) return;
        // 如果该字段计数器中有内容，就开始构建桶
    for (Counter::iterator it = ac_counter[bucket_type].begin();
         it != ac_counter[bucket_type].end(); it++) {
        if (it->second > 0) {
            ProcessBucketItem(bucket_type, it->first, it->first);
        }
    }
}

void AdjustBucket()
{
    // 开始往桶里面丢，桶的个数与字段个数相同，桶里面应该记录<字段值，[主码索引]>
    for (size_t i = 0; i <= C_COMMENT_COUNTER; i++) {
        ProcessCounterItems(i);
    }
}


/**
* 查询函数
* @param FieldList 要查询的字段名称（字段编号）
* @param field_len 要查询的字段个数
* @param item_addr 查询关键字的地址
* @param res_item_addr 返回结果集的地址
* @param res_len 返回结果集合的大小
*/
int GetData(int32_t* FieldIndex, size_t field_len, uint64_t item_addr, uint64_t res_item_addr, size_t* res_len)
{
    // 获取查询条件指针
    CustomerItem* item = (CustomerItem*)item_addr;

    // 获取返回结果指针
    CustomerItem* res_item = (CustomerItem*)res_item_addr;

    // 开始查询
    SearchFromBucket(FieldIndex[0], item, res_item, res_len);
    
    // 根据查找结果更新计数器的值
    for (size_t counter_i = 0; counter_i < field_len; counter_i++) {
        for (size_t i = 0; i < res_len[0]; i++) {
            ac_counter[FieldIndex[counter_i]][res_item->CustomerKey]++;
        }
    }
    
    // 根据计数器内容调整桶
    AdjustBucket();
    
    return 0;
}

