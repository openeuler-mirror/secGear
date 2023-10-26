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
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "enclave.h"
#include "secgear_ds_u.h"
#define BUF_LEN 32
#define MAX_BUF_SIZE 256
#define MAX_ITEM_NUM 32768
#define NAME_SIZE 32
#define DESP_SIZE 64 
#define OP_TIMES 5000

using namespace std;
// 键值对分别存放
typedef struct Value {
    string name;
    string address;
    string gender;
    string description;
} Value, *ValuePtr;

typedef struct Key {
    // key information
    int32_t key_info;
    // pointer to value
    Value *ptr;
} Key, *KeyPtr;

// 键值对统一存放
typedef struct KV {
    int32_t key_info;
    char name[NAME_SIZE + 1];
    char address[NAME_SIZE + 1];
    char gender[NAME_SIZE + 1];
    char description[DESP_SIZE + 1];
}KV, *KVPtr;


// 链表节点
typedef struct Node {
    int32_t key;
    struct Node *next;
}Node, *pNode;
// 链表
typedef struct LinkList {
    pNode head;
    uint32_t len;
}LinkList;

// storage filebuffer for temporary
vector<string> temp_list;
// storage key
Key key_list[MAX_ITEM_NUM];
KV kv_list[MAX_ITEM_NUM];
vector<int> elem_list;   // 关键字列表


int ITEM_NUM = 0;
// 重写getline函数
istream & getline(char *buf, int buf_size, char delim);
// 字符串分割函数
void StringSplit(string str, char split, Key& key)
{
    int index = 0;
    string *value_list = new string[BUF_LEN];
	istringstream iss(str);	// 输入流
    Value *value = new Value();
	string token;			// 接收缓冲区
    // get key information first
    getline(iss, token, split);
    istringstream tt(token);
    tt >> key.key_info;
    int bias = 0;
    while (getline(iss, token, split))	// 以split为分隔符
	{
        istringstream tt(token);
        tt >> value_list[index++];
	}
    value->name = value_list[0];
    value->address = value_list[1];
    value->gender = value_list[2];
    value->description = value_list[3];
    key.ptr = value;
}
// get CPU clock cyclesZP
static __inline__ uint64_t rdtsc(void)
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}
// 字符串拼接
string concat_str(Value* value)
{   
    string _value = value->name + " " + value->address + " " + value->gender + " " + value->description;
    return _value;
}
int in = 0;
void ocall_print(uint64_t data) 
{
    cout << in++ << ": ";
    cout << data << endl; 
}
// 打印值信息
void print_value(KeyPtr key, ValuePtr value)
{
    cout << "##########################" << endl;
    cout << "key: " << key->key_info << endl;
    cout << "value: " << concat_str(value) << endl;
    cout << "##########################" << endl;
}
/*
    键值对数据初始化
*/
void Init(cc_enclave_t context, cc_enclave_result_t res, int retval)
{
    uint64_t *key_base_addr = new uint64_t[BUF_LEN];
    key_base_addr[0] = (uint64_t)key_list;          // 取地址
    res = init_key(&context, &retval, key_base_addr, ITEM_NUM); // 设置key初始地址
    // 检查执行状况
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Initialize data enclave error\n");
    } else {
        // printf("Initialize data enclave success\n");
    }
}
/*
    搜索
*/
void Search(cc_enclave_t context, cc_enclave_result_t res, int retval, int key)
{
    int32_t *search_key_list = new int32_t[BUF_LEN];   // 键信息
    uint64_t *ret_addr = new uint64_t[2];   // 查询值结果
    search_key_list[0] = key;
    res = search_kv(&context, &retval, search_key_list, ret_addr, BUF_LEN);  
    if (res != CC_SUCCESS || retval < 0) {
        printf("Search data enclave error\n");
    } else {
        // printf("Search data enclave success\n");
    }
}
/*
    插入
*/
void Insert(cc_enclave_t context, cc_enclave_result_t res, int retval, int key)
{
    Key *insert_key = new Key();
    Value *insert_value = new Value();
    // 插入key数据初始化
    insert_key->key_info = key;
    // 指针指向
    insert_key->ptr = insert_value;
    // 插入value数据初始化
    insert_value->name = string("insert");
    insert_value->address = string("insert");
    insert_value->gender = string("insert");
    insert_value->description = string("insert");
    // 获取key基址
    uint64_t *insert_key_addr = new uint64_t[2];
    insert_key_addr[0] = (uint64_t)insert_key;
    // 插入数据
    res = insert_kv(&context, &retval, insert_key_addr, BUF_LEN);   
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Insert data enclave error\n");
    } else {
        // printf("Insert data enclave success\n");
    }
}

/*
    更新
*/
void Update(cc_enclave_t context, cc_enclave_result_t res, int retval)
{
    Value* update_value = new Value();
    Key* update_key = &key_list[5];
    int32_t kk = update_key->key_info;
    uint64_t *update_value_addr = new uint64_t[BUF_LEN];
    // 更新数据初始化
    update_value->name = string("update");
    update_value->address = string("update");
    update_value->gender = string("update");
    update_value->description = string("update");
    // 地址准备
    update_value_addr[0] = (uint64_t)update_value;

    // 开始更新
    res = update_kv(&context, &retval, update_value_addr, kk, BUF_LEN);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Update data enclave error\n");
    } else {
        // printf("Update data enclave success\n");
    }
}
/*
    删除
*/
void Delete(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    int32_t *delete_list = new int32_t[BUF_LEN];
    delete_list[0] = key;
    res = delete_kv(&context, &retval, delete_list, BUF_LEN);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        cout << "Delete data enclave failed" << endl;
    } else {
        // cout << "Delete data enclave success" << endl;
    }
}

//////////////////////////////////////////////////////

void InitKV(cc_enclave_t context, cc_enclave_result_t res, int retval)
{
    uint32_t len = temp_list.size();
    uint64_t kv_addr = (uint64_t)kv_list;
    res = init_keyvalue(&context, &retval, kv_addr, len);
    // 检查执行状况
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        cout << "Initialize data enclave failed" << endl;
    } else {
        // cout << "Initialize data enclave success" << endl;
    }
}
void InsertKV(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    KV* kv = new KV();
    kv->key_info = key;
    // 插入value数据初始化
    strcpy(kv->name, "insert");
    strcpy(kv->address, "insert");
    strcpy(kv->gender, "insert");
    strcpy(kv->description, "insert");
    // 获取key基址
    uint64_t kv_addr = (uint64_t)kv; 
    // 插入数据
    res = insert_keyvalue(&context, &retval, kv_addr, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        cout << "Insert data enclave error" << endl;
    } else {
        // cout << "Insert data enclave success" << endl;
    }

}

void DeleteKV(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = delete_keyvalue(&context, &retval, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        cout << "Delete data enclave failed" << endl;
    } else {
        // cout << "Delete data enclave success" << endl;
    }

}
void SearchKV(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    char* value_ret = new char[sizeof(KV)];
    uint64_t ret_addr = (uint64_t)value_ret;
    res = search_keyvalue(&context, &retval, ret_addr, key);
    // 检查执行状况
    if (res != CC_SUCCESS || retval < 0) {
        cout << "Search data enclave error" << endl;
    } else {
        // cout << "Search data enclave success" << endl;
    }
}


// 二叉平衡树
void InitAVL(cc_enclave_t context, cc_enclave_result_t res, int retval)
{
    int len = elem_list.size();
    int32_t *init_list = new int32_t[len];
    for (int i = 0;i < len;i++) {
        init_list[i] = elem_list[i];
        // cout << init_list[i] << endl;
    }
    uint64_t *insert_list = new uint64_t[2];
    insert_list[0] = (uint64_t)init_list;
    res = Initavl(&context, &retval, insert_list, len);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {   
        cout << "AVL init enclave error" << endl;
        
    } else {
        // cout << "AVL init enclave success" << endl;
    }

}

// 插入元素
void InsertElement(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    // 插入数据
    res = Insertavl(&context, &retval, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {  
        cout << "Insert enclave error" << endl;
    } else {
        // cout << "Insert enclave success" << endl;
    }
}

// 查找元素
void SearchELement(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = Searchavl(&context, &retval, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {  
        cout << "Search enclave error" << endl;
    } else {
        // cout << "Search enclave success" << endl;
    }
}

// 删除元素
void DeleteElement(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = Deleteavl(&context, &retval, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {  
        cout << "Delete enclave error" << endl;
    } else {
        // cout << "Delete enclave success" << endl;
    }
}

// 顺序表
void InitOrderList(cc_enclave_t context, cc_enclave_result_t res, int retval)
{
    int len = elem_list.size();
    int32_t *init_list = new int32_t[len];
    for (int i = 0;i < len;i++) {
        init_list[i] = elem_list[i];
    }
    uint64_t *insert_list = new uint64_t[2];
    insert_list[0] = (uint64_t)init_list;
    res = InitOL(&context, &retval, insert_list, len);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {   
        cout << "OrderList init enclave error" << endl;
        
    } else {
        // cout << "AVL init enclave success" << endl;
    }
}

void InsertOrderList(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = InsertOL(&context, &retval, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {   
        cout << "OrderList insert enclave error" << endl;
    } else {
        // cout << "AVL init enclave success" << endl;
    }  
}

void SearchOrderList(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = SearchOL(&context, &retval, key);
    if (res != CC_SUCCESS || retval < 0) {   
        cout << "OrderList search enclave error" << endl;
        
    } else {
        // cout << "AVL init enclave success" << endl;
    }
}
void DeleteOrderList(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = DeleteOL(&context, &retval, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {   
        cout << "OrderList delete enclave error" << endl;
        
    } else {
        // cout << "AVL init enclave success" << endl;
    }
}
// 链表
void InitLinkList(cc_enclave_t context, cc_enclave_result_t res, int retval)
{
    int len = elem_list.size();
    int32_t *init_list = new int32_t[len];
    for (int i = 0;i < len;i++) {
        init_list[i] = elem_list[i];
    }
    uint64_t key_list_addr = (uint64_t)init_list;
    res = InitLL(&context, &retval, key_list_addr, len);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {   
        cout << "LinkList init enclave error" << endl;
    } else {
        // cout << "LinkList init enclave success" << endl;
    }
}
void InsertLinkList(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = InsertLL(&context, &retval, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {   
        cout << "LinkList insert enclave error" << endl;
        
    } else {
        // cout << "LinkList init enclave success" << endl;
    }  
}

void SearchLinkList(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = SearchLL(&context, &retval, key);
    if (res != CC_SUCCESS || retval < 0) {   
        cout << "LinkList search enclave error" << endl;
        
    } else {
        // cout << "LinkList init enclave success" << endl;
    }
}
void DeleteLinkList(cc_enclave_t context, cc_enclave_result_t res, int retval, int32_t key)
{
    res = DeleteLL(&context, &retval, key);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {   
        cout << "LinkList delete enclave error" << endl;
    } else {
        // cout << "LinkList init enclave success" << endl;
    }
}
int main(int argc, char* argv[])
{
    int retval = 0;
    char *path = PATH;
    char buf[BUF_LEN];
    // return value status
    cc_enclave_result_t res;
    // enclave context
    cc_enclave_t context = {};
    // 测试运行时间
    time_t begin, end;
    double insert_time, search_time, delete_time;
    // test data
    Value* value = new Value();
    Key* key = new Key();
    key->ptr = value;
    string data_temp;
    // 乱序数字文件
    ifstream infile(argv[1]); 
    while(infile >> data_temp) {
        elem_list.push_back(atoi(data_temp.c_str()));
    }
    if (infile.is_open()) {
        cout << "open file " << argv[1] << " success!" << endl;    
    } else {
        cout << "open file failed!" << endl;
        return -1;
    }
    // 键值对数据文件
    fstream f(argv[2], ios::in);
    if (f.is_open()) {
        cout << "open file " << argv[2] << " success!" << endl;    
    } else {
        cout << "open file failed!" << endl;
        return -1;
    }
    string temp;
    while(getline(f, temp)) {
        ITEM_NUM++;
        temp_list.push_back(temp);
    }
    cout << "number of items: " << ITEM_NUM << endl;
    for (int i = 0; i < temp_list.size(); i++) {
        Key key;
        StringSplit(temp_list[i], ' ', key);
        // cout << "key: " << key.key_info << " value: " << key.ptr->name << endl; 
        // add to the key_list
        key_list[i] = key;
        kv_list[i].key_info = key.key_info;
        strcpy(kv_list[i].name, key.ptr->name.c_str());
        strcpy(kv_list[i].address, key.ptr->address.c_str());
        strcpy(kv_list[i].gender, key.ptr->gender.c_str());
        strcpy(kv_list[i].description, key.ptr->description.c_str());
    }
    
    // 创建enclave
    printf("Create secgear enclave\n");
    res = cc_enclave_create(path, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
    cout << path << endl;
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        return res;
    }
    cout << "=======================================" << endl;
    // 二叉树初始化
    InitAVL(context, res, retval);

    // 插入数据
    begin = clock();
    for (int i = 0;i < OP_TIMES; i++) {
        InsertElement(context, res, retval, 20086+i);
    }
    end = clock();
    insert_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "AVL平均插入时长(s): " << insert_time << endl;
    // 查询数据
    begin = clock();
    for (int i = 0 ;i < OP_TIMES;i++) {
        SearchELement(context, res, retval, i + 10);
    }
    end = clock();
    search_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "AVL平均查询时长(s): " << search_time << endl;
    // 删除数据
    begin = clock();
    for (int i = 0;i < OP_TIMES;i++) {
        DeleteElement(context, res, retval, 10086+i);
    }
    end = clock();
    delete_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "AVL平均插入时长(s): " << delete_time << endl;
    cout << "=======================================" << endl;
    // 顺序表初始化（升序排列） 
    InitOrderList(context, res, retval);
    // 查找数据
    begin = clock();
    for (int i = 0; i < OP_TIMES;i++) {
        SearchOrderList(context, res, retval, 10086 + i);
    }
    end = clock();
    search_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "顺序表平均查找时长(s): " << search_time << endl;
    // 插入数据
    begin = clock();
    for (int i = 0; i < OP_TIMES;i++) {
        InsertOrderList(context, res, retval, 20000);
    }   
    end = clock();
    insert_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "顺序表平均插入时长(s): " << insert_time << endl;
    // 删除数据
    begin = clock();
    for (int i = 0;i < OP_TIMES;i++) {
        DeleteOrderList(context, res, retval, 20000);
    }
    end = clock();
    delete_time = (double)(end- begin) / CLOCKS_PER_SEC;
    cout << "顺序表平均删除时长(s): " << delete_time << endl;
    cout << "=======================================" << endl;
    // 初始化链表
    InitLinkList(context, res, retval);
    // 查找数据
    begin = clock();
    for (int i = 0; i < OP_TIMES;i++) {
        SearchLinkList(context, res, retval, 10086 + i);
    }
    end = clock();
    search_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "链表平均查找时长(s): " << search_time << endl;
    // 插入数据
    begin = clock();
    for (int i = 0; i < OP_TIMES;i++) {
        InsertLinkList(context, res, retval, 20000 + i);
    }   
    end = clock();
    insert_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "链表平均插入时长(s): " << insert_time << endl;
    // 删除数据
    begin = clock();
    for (int i = 0;i < OP_TIMES;i++) {
        DeleteLinkList(context, res, retval, 20000);
    }
    end = clock();
    delete_time = (double)(end- begin) / CLOCKS_PER_SEC;
    cout << "链表平均删除时长(s): " << delete_time << endl;
    cout << "=======================================" << endl;
    // 键值对数据初始化
    Init(context, res, retval);

    // 查找
    begin = clock();
    for (int i = 0;i < OP_TIMES;i++) {
        Search(context, res, retval, 500 + i);
    }
    end = clock();
    search_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "键值对(分离)查询时长(s): " << search_time << endl;

    // 插入
    begin = clock();
    for (int i = 0 ;i < OP_TIMES;i++) {
        Insert(context, res, retval, 20086 + i);
    }
    end = clock();
    insert_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "键值对(分离)插入时长(s): " << insert_time << endl;

    // 更新，该操作功能为更新值，需要将键和新值传入enclave
    // Update(context, res, retval);

    // 删除(需要考虑内存释放操作)
    
    begin = clock();
    for (int i = 0; i < OP_TIMES;i++) {
        Delete(context, res, retval, 500 + i);
    }
    end = clock();
    delete_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "键值对(分离)删除时长(s): " << delete_time << endl;
    cout << "=======================================" << endl;
    //////////////////////////////////////////////////
    // 键值对合并初始化 
    InitKV(context, res, retval);
    // 键值对合并搜索
    begin = clock();
    for (int i = 0 ;i < OP_TIMES;i++) {
        SearchKV(context, res, retval, 732 + i);
    }
    end = clock();
    search_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "键值对(合并)查询时长(s): " << search_time << endl;

    // 键值对合并插入
    begin = clock();
    for (int i =0 ;i < OP_TIMES;i++) {
        InsertKV(context, res, retval, 20086+i);
    }
    end = clock();
    insert_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "键值对(合并)插入时长(s): " << insert_time << endl;

    // 键值对合并删除
    begin = clock();
    for (int i = 0 ;i < OP_TIMES;i++) {
        DeleteKV(context, res, retval, 732 + i);
    }
    end = clock();
    delete_time = (double)(end - begin) / CLOCKS_PER_SEC;
    cout << "键值对(合并)删除时长(s): " << delete_time << endl;
    cout << "=======================================" << endl;
    // 销毁飞地
    res = cc_enclave_destroy(&context);
    if(res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    } else {
        cout << "Destroy enclave success!" << endl;
    }
    return res;
}
