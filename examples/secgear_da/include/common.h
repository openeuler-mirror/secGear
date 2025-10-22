#ifndef COMMON_H
#define COMMON_H

#define VALUE_SIZE 128
#define TEST_ITEM_SIZE 100
using namespace std;

// 键(存储在TEE中)
typedef struct KEY {
    int key_val;                // 键
    uint8_t *val_ptr;           // 指针
    size_t val_size;            // value长度
    size_t hash_value;          // hash(这里可以选一种hash函数替换成HMAC)
} KEY;

// 值(加密存储在REE中)
typedef struct VALUE {
    uint8_t *value;
    size_t val_len;
} VALUE;

// 键值对数据
typedef struct KV {
    int32_t key_val;
    uint8_t value[VALUE_SIZE];
    size_t value_len;
} KV;

#endif