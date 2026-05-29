# secGearDS

## Introduction

This project describes the design and implementation of efficient confidential computing data structures based on secGear.
Based on the traditional data structure, this project implements the sequential structure and chain structure to organize data.
The performance bottleneck of EPC storage is tested using the linear structure. In this way, the AVL binary balanced tree is used to optimize the query, insertion, and deletion performance.
Finally, by analyzing the query characteristics of key-value pairs, the traditional key-value pair organization is optimized through a separated key-value pair data structure. The results show that the separated key-value pair storage scheme effectively reduces performance overhead.

## Installation

```shell
cd secGear/examples/secgear_ds
mkdir debug && cd debug && cmake .. && make
sudo make install
```

## Usage

### Basic Usage

Run the test.

```shell
cd secGear/examples/secgear_ds
sudo ./debug/host/secgear_ds ./data/avl_data.txt ./data/kv_data.txt
```

### Implementation

1. Develop the basic part (utility module in the secGear framework) based on the algorithm process as scheduled, including:

   - `ocall_function` and `ecall_function` calling methods

2. Implement linear structure storage.

   - `OrderList` sequential table:
     - `InitOL` sequential table initialization
     - `InsertOL` sequential table insertion
     - `SearchOL` sequential table search
     - `DeleteOL` sequential table deletion
   - `LinkList` linked list:
     - `InitLL` linked list initialization
     - `InsertLL` linked list insertion
     - `SearchLL` linked list search
     - `DeleteLL` linked list deletion

3. Optimize the query of the AVL binary balanced tree.

   - `AVLTree` binary balanced tree:

     - `InitAVL` AVL initialization
     - `InsertAVL` AVL insertion
     - `SearchAVL` AVL search
     - `DeleteAVL` AVL deletion

     The tree adjustment operation after insertion and deletion is included.

4. Optimize the organizational structure based on key-value pair data.

   - `KeyValue` Key-value pair continuous storage structure:
     - `InitKV` Key-value pair data initialization
     - `InsertKV` Key-value pair data insertion
     - `SearchKV` Key-value pair data search
     - `DeleteKV` Key-value pair data deletion
     - `UpdateKV` value update
   - `key2value` Key-value pair separate storage structure:
     - `InitK2V` Key-value pair separation structure initialization
     - `InsertK2V` Key-value pair separation structure insertion
     - `SearchK2V` Key-value pair separation structure query
     - `DeleteK2V` Key-value pair separation structure deletion

   Compare the average execution duration of each operation in the preceding two structures.

### Secure Interface

```cpp
// Separated key-value pair storage
public int init_key([in, out]uint64_t* key_base_addr, uint32_t buf_len);
public int search_kv([in, out]int32_t* search_list, [in, out]uint64_t* ret_addr, uint32_t buf_len);
public int insert_kv([in, out]uint64_t* insert_list, uint32_t buf_len); 
public int update_kv([in, out]uint64_t* update_list, int32_t kk, uint32_t buf_len);
public int delete_kv([in, out]int32_t* delete_list, uint32_t buf_len);
// Combined key-value pair storage     
public int init_keyvalue(uint64_t kv_addr, uint32_t buf_len);
public int insert_keyvalue(uint64_t kv_addr, int32_t key);
public int search_keyvalue(uint64_t ret_addr, int32_t key);
public int delete_keyvalue(int32_t key); 
// AVL tree
public int Initavl([in, out]uint64_t* insert_list, uint32_t buf_len);
public int Insertavl_([in, out]uint64_t* insert_list, uint32_t buf_len);
public int Insertavl(int32_t insert_element);
public int Searchavl(int32_t search_key);
public int Deleteavl(int32_t delete_key);
// Sequential table
public int InitOL([in, out]uint64_t* insert_list, uint32_t buf_len);
public int InsertOL(int32_t insert_key);
public int SearchOL(int32_t Search_key);
public int DeleteOL(int32_t Delete_key);
// Linked list
public int InitLL(uint64_t key_list_addr, uint32_t buf_len);
public int SearchLL(int32_t key);
public int InsertLL(int32_t key);
public int DeleteLL(int32_t key);
```
