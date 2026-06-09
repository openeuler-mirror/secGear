#include "tpch.h"
#include <iostream>
#include <time.h>
#define MAX_ITEM_NUM 1000000
using namespace std;

static __inline__ unsigned long long rdtsc(void)
{
        unsigned hi;
        unsigned lo;
        __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
        return ((unsigned long long)lo)|(((unsigned long long)hi)<<32);   // 32字节
}

void ProcessBucketSwitch(size_t bucket_type, int index, int key, CustomerItem* items, CustomerBucket& cust_bucket)
{
    switch (bucket_type) {
        case C_CUSTKEY_COUNTER:
            cust_bucket[bucket_type][items[index].CustomerKey].push_back(key);
            break;
        case C_NAME_COUNTER:
            cust_bucket[bucket_type][items[index].Name].push_back(key);
            break;
        case C_ADDRESS_COUNTER:
            cust_bucket[bucket_type][items[index].Address].push_back(key);
            break;
        case C_NATION_COUNTER:
            cust_bucket[bucket_type][items[index].Nation].push_back(key);
            break;
        case C_PHONE_COUNTER:
            cust_bucket[bucket_type][items[index].Phone].push_back(key);
            break;
        case C_ACCTBAL_COUNTER:
            cust_bucket[bucket_type][items[index].Acctbal].push_back(key);
            break;
        case C_MKTSEGMENT_COUNTER:
            cust_bucket[bucket_type][items[index].Mktsegment].push_back(key);
            break;
        case C_COMMENT_COUNTER:
            cust_bucket[bucket_type][items[index].Comment].push_back(key);
            break;
        default: break;
    }
}

void InitializeItems(CustomerItem* items)
{
    for (int i = 1; i <= MAX_ITEM_NUM; i++) {
        items[i].CustomerKey = i;
        items[i].Comment = "hello" + to_string(i);
        items[i].Name = "hello" + to_string(i);
        items[i].Address = "hello" + to_string(i);
        items[i].Phone = "hello" + to_string(i);
        items[i].Acctbal = "hello" + to_string(i);
        items[i].Mktsegment = "hello" + to_string(i);
    }
    items[1].Comment = "hello";
    items[10].Comment = "hello";   // 10号测试
}

void PrintAccessCounter(AccessCounter& ac_counter)
{
    for (size_t i = 0; i < ac_counter.size(); i++) {
        cout << "Field: " << FieldNameList[i] << endl;
        if (!ac_counter[i].empty()) {
            for (auto& it : ac_counter[i]) {
                cout << "primary key = " << it.first << " counter = " << it.second << "; ";
            }
            cout << "\n==============\n";
        }
    }
}

void BuildCustomerBucket(AccessCounter& ac_counter, CustomerItem* items, CustomerBucket& cust_bucket)
{
    for (size_t i = 0; i <= C_COMMENT_COUNTER; i++) {
        if (!ac_counter[i].empty()) {
            for (auto& it : ac_counter[i]) {
                if (it.second != 0) {
                    ProcessBucketSwitch(i, it.first, it.first, items, cust_bucket);
                }
            }
        }
    }
}

void RunPerformanceTest1(CustomerBucket& cust_bucket, Variant& var1)
{
    clock_t start = clock();
    if (start == static_cast<clock_t>(-1)) {
        cerr << "Error: clock() failed to get processor time" << endl;
        return;
    }
    unsigned long long begin = rdtsc();

    for (auto& it : cust_bucket[C_COMMENT_COUNTER]) {
        Variant var = it.first;
        if (var == var1) {
            cout << it.second.size() << " ";
        }
    }

    unsigned long long stop = rdtsc();
    clock_t end = clock();
    if (end == static_cast<clock_t>(-1)) {
        cerr << "Error: clock() failed to get processor time" << endl;
        return;
    }
    double during = static_cast<double>(end - start) / CLOCKS_PER_SEC;
    cout << "\nTime: " << during << endl;
    cout << "CPU Cycles: " << stop - begin << endl;
}

int main()
{
    unsigned long long int begin;
    unsigned long long int stop;
    unsigned long long int total = 0;
    CustomerItem *items = new CustomerItem[MAX_ITEM_NUM + 1];   // ???????????????????????TEE?��???TEE????ocall??????
    CustomerBucket cust_bucket;                                 // ?????
    clock_t start;
    clock_t end;
    double during = 0;
    Variant var;
    InitializeItems(items);

    for (int i = 500000; i <= 600000; i++) {      // 500000 到 600000 号测试
        items[i].Comment == "hello";
    }

    Variant var1 = "hello";
    CustomerItem item = items[10];

    AccessCounter ac_counter;

    ac_counter[C_COMMENT_COUNTER][item.CustomerKey]++;
    ac_counter[C_CUSTKEY_COUNTER][item.CustomerKey]++;
    ac_counter[C_COMMENT_COUNTER][1] = 10;   // 计数10
    
    PrintAccessCounter(ac_counter);

    BuildCustomerBucket(ac_counter, items, cust_bucket);

    RunPerformanceTest1(cust_bucket, var1);
    
    start = clock();
    begin = rdtsc();
    vector<int32_t> res;
    for (int i = 1;i <= MAX_ITEM_NUM;i++) {
        var = items[i].Comment;
        if (var == var1) {
            // cout << items[i].CustomerKey << " ";
            res.push_back(items[i].CustomerKey);
        }
    }
    cout << res.size() << " ";
    stop = rdtsc();
    end = clock();
    during = (double)(end - start) / CLOCKS_PER_SEC;
    cout << "\nTime: " << during << endl;
    cout << "CPU Cycles: " << stop - begin << endl;

    return 0;
}