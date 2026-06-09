#ifndef TPCH_H
#define TPCH_H

#include <map>
#include <vector>
#include <array>
#include <any>
#include <variant>

/*
定义长度
*/
#define MAX_ITEM_NUM 10000
#define BUF_SIZE_16 16
#define BUF_SIZE_32 32
#define BUF_SIZE_64 64
#define BUF_SIZE_128 128
#define MAX_BUF_SIZE 10001


using namespace std;
/*
* Customer表字段名称
*/
#define C_CUSTKEY_FIELD         "C_CUSTKEY"
#define C_NAME_FIELD            "C_NAME"
#define C_ADDRESS_FIELD         "C_ADDRESS"
#define C_NATION_FIELD          "C_NATION"
#define C_PHONE_FIELD           "C_PHONE"
#define C_ACCTBAL_FIELD         "C_ACCTBAL"
#define C_MKTSEGMENT_FIELD      "C_MKTSEGMENT"
#define C_COMMENT_FIELD         "C_COMMENT"

/*
* 使用列主序存储，在相应的列查到数据之后可以通过下标索引获取其他字段数据
*/
enum CustomerDesc {
    C_NAME = 0,
    C_ADDRESS,
    C_PHONE,
    C_ACCTBAL,
    C_MKTSEGMENT,
    C_COMMENT
};
typedef array<char, 64> String_32;

/*
* 按照字段名称为计数器构建下标索引
*/
enum CustomerCounterIndex {
    C_CUSTKEY_COUNTER = 0,
    C_NAME_COUNTER,
    C_ADDRESS_COUNTER,
    C_NATION_COUNTER,
    C_PHONE_COUNTER,
    C_ACCTBAL_COUNTER,
    C_MKTSEGMENT_COUNTER,
    C_COMMENT_COUNTER
};

// 字段名称集合
std::array<std::string, C_COMMENT_COUNTER + 1> FieldNameList = {
    "C_CUSTKEY", "C_NAME", "C_ADDRESS", "C_NATION", "C_PHONE", "C_ACCTBAL", "C_MKTSEGMENT", "C_COMMENT"
};
/*
* 数据条目
*/
typedef struct CustomerItem {
    int32_t CustomerKey;
    int32_t Nation;
    char Name[BUF_SIZE_16 + 1];
    char Address[BUF_SIZE_128 + 1];
    char Phone[BUF_SIZE_16 + 1];
    char Acctbal[BUF_SIZE_128 + 1];
    char Mktsegment[BUF_SIZE_128 + 1];
    char Comment[BUF_SIZE_128 + 1];
} CustomerItem;

// 访问频次计数器
typedef std::map<int32_t, int16_t> Counter;
typedef std::array<Counter, C_COMMENT_COUNTER + 1> AccessCounter;

// 自定义Variant类型，包括int(0), string(1), double(2)三种变量类型
typedef std::variant<int32_t, std::string, double> Variant;

// 缓存桶, 用来存储<字段名称, 主键>
typedef std::map<Variant, std::vector<int32_t> > BucketItem;
typedef std::array<BucketItem, C_COMMENT_COUNTER + 1 > CustomerBucket;

//////////////////////////////////////////////////////////////////////
// 主码属性
typedef struct Customer {
    map<std::string, vector<int> > CustomerKey;
} Customer;

// 非主属性
typedef struct CustomerField {
    map<std::string, vector<std::string> > Name;
    map<std::string, vector<std::string> > Address;
    map<std::string, vector<int> > Nation;
    map<std::string, vector<std::string> > Phone;
    map<std::string, vector<std::string> > Acctbal;
    map<std::string, vector<std::string> > Mktsegment;
    map<std::string, vector<std::string> > Comment;
} CustomerField;

#endif