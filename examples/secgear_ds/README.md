# secGearDS

## 介绍

基于secGear的高效机密计算数据结构设计与实现。
本项目参考传统数据结构，实现了顺序结构、链式结构组织数据。
通过线性结构测试了EPC存储的性能瓶颈。从而通过AVL二叉平衡树优化查询、插入和删除性能。
最后通过分析键值对类型数据查询特性，使用键值对分离数据结构对传统键值对数据组织方式进行优化。结果表明键值对分离存储方案有效降低了性能开销。
## 安装

```shell
cd secGear/examples/secgear_ds
mkdir debug && cd debug && cmake .. && make
sudo make install
```

## 使用

### 基本使用

运行测试：

```shell
cd secGear/examples/secgear_ds
sudo ./debug/host/secgear_ds ./data/avl_data.txt ./data/kv_data.txt
```

### 实现内容

1. 根据算法过程进行基础部分开发（secGear框架内的实用程序模块），如期完成，包含：

   - `ocall_function` 与 `ecall_function` 的调用方式；

2. 实现线性结构存储

   - `OrderList` 顺序表：
     - `InitOL` 顺序表初始化 ；
     - `InsertOL` 顺序表插入；
     - `SearchOL` 顺序表搜索；
     - `DeleteOL` 顺序表删除；
   - `LinkList` 链式表：
     - `InitLL` 链表初始化；
     - `InsertLL` 链表插入；
     - `SearchLL` 链表搜索；
     - `DeleteLL` 链表删除；

3. 实现AVL二叉平衡树查询优化

   - `AVLTree` 二叉平衡树：

     - `InitAVL` AVL初始化；
     - `InsertAVL` AVL插入；
     - `SearchAVL` AVL搜索；
     - `DeleteAVL` AVL删除；

     包含插入删除后的树调整操作；

4. 实现基于键值对类型数据的组织结构优化

   - `KeyValue` 键值对连续存储结构：
     - `InitKV` 键值对数据初始化；
     - `InsertKV` 键值对数据插入；
     - `SearchKV` 键值对数据搜索；
     - `DeleteKV` 键值对数据删除；
     - `UpdateKV` 值更新；
   - `key2value` 键值对分离存储结构：
     - `InitK2V` 键值对分离结构初始化；
     - `InsertK2V` 键值对分离结构插入；
     - `SearchK2V` 键值对分离结构查询；
     - `DeleteK2V` 键值对分离结构删除；

   对比以上两种结构各种操作平均执行时长。

### 安全接口

```cpp
// 键值对分离存储
public int init_key([in, out]uint64_t* key_base_addr, uint32_t buf_len);
public int search_kv([in, out]int32_t* search_list, [in, out]uint64_t* ret_addr, uint32_t buf_len);
public int insert_kv([in, out]uint64_t* insert_list, uint32_t buf_len); 
public int update_kv([in, out]uint64_t* update_list, int32_t kk, uint32_t buf_len);
public int delete_kv([in, out]int32_t* delete_list, uint32_t buf_len);
// 键值对合并存储      
public int init_keyvalue(uint64_t kv_addr, uint32_t buf_len);
public int insert_keyvalue(uint64_t kv_addr, int32_t key);
public int search_keyvalue(uint64_t ret_addr, int32_t key);
public int delete_keyvalue(int32_t key); 
// AVL树
public int Initavl([in, out]uint64_t* insert_list, uint32_t buf_len);
public int Insertavl_([in, out]uint64_t* insert_list, uint32_t buf_len);
public int Insertavl(int32_t insert_element);
public int Searchavl(int32_t search_key);
public int Deleteavl(int32_t delete_key);
// 顺序表
public int InitOL([in, out]uint64_t* insert_list, uint32_t buf_len);
public int InsertOL(int32_t insert_key);
public int SearchOL(int32_t Search_key);
public int DeleteOL(int32_t Delete_key);
// 链表
public int InitLL(uint64_t key_list_addr, uint32_t buf_len);
public int SearchLL(int32_t key);
public int InsertLL(int32_t key);
public int DeleteLL(int32_t key);
```