# secGearDA

## 介绍

本项目旨在基于openEuler的统一可信执行环境（TEE）开发框架——secGear，设计并实现一种高效的数据库存储方案。在保障数据机密性、完整性和可用性的前提下，重点解决Intel SGX EPC（Enclave Page Cache）内存限制导致的性能瓶颈问题。

在架构上，系统采用关键数据入Enclave与非敏感数据存储于非可信内存的混合模式，并设计了访问热点缓存机制，使访问频繁的数据优先驻留于EPC，从而减少频繁的页面交换带来的性能开销。缓存模块主要由访问频次计数器（AccessCounter）和缓存桶 （CacheBucket）两个关键部分组成。AccessCounter 负责根据查询结果更新数据字段访问频次，当访问频次超过设定阈值后，将其中的访问频次作为缓存构建依据构建CacheBucket。之后查询任务中，即可优先访问CacheBucket，提高查询效率。

## 安装

```shell
cd secGear/examples/secgear_da
mkdir debug && cd debug && cmake .. && make
sudo make install
```

## 使用

### 基本使用

运行测试：

```shell
cd secGear/examples/secgear_da
sudo ./test_ec_group
```

### 关键模块

```cpp
// 加密解密
void AES_Encrypt(KEY &Key)
void AES_Decrypt(KEY Key, uint8_t *buf)
// 从表中搜索数据    
int SearchFromTable(int FieldIndex, CustomerItem* item, CustomerItem* res_item, size_t* res_len)
// 从桶中搜索数据
int SearchFromBucket(int FieldIndex, CustomerItem* item, CustomerItem* res_item, size_t* res_len)
// 根据计数器调整桶
void AdjustBucket()
// 查询函数
int GetData(int32_t* FieldIndex, size_t field_len, uint64_t item_addr, uint64_t res_item_addr, size_t* res_len) 
```