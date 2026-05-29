# secGearDA

## Introduction

This project aims to design and implement an efficient database storage solution based on secGear, the unified trusted execution environment (TEE) development framework of openEuler. The solution focuses on overcoming the performance bottleneck caused by the limited enclave page cache (EPC) size of Intel Software Guard Extensions (Intel SGX) while ensuring data confidentiality, integrity, and availability.

In terms of architecture, the system adopts a hybrid model in which critical data resides inside the enclave, while non-sensitive data is stored in untrusted memory. In addition, a hot-data caching mechanism is introduced to keep frequently accessed data in the EPC with priority, thereby reducing the performance overhead caused by frequent page swapping. The cache module consists of two key components: AccessCounter and CacheBucket. The AccessCounter updates the access frequency of data fields based on query results. Once the frequency exceeds a predefined threshold, it uses this value as the basis for constructing a CacheBucket. In subsequent query tasks, the CacheBucket can be accessed first, improving query efficiency.

## Installation

```shell
cd secGear/examples/secgear_da
mkdir debug && cd debug && cmake .. && make
sudo make install
```

## Usage

### Basic Usage

Run the test.

```shell
cd secGear/examples/secgear_da
sudo ./test_ec_group
```

### Key Module

```cpp
// Encrypt and decrypt data.
void AES_Encrypt(KEY &Key)
void AES_Decrypt(KEY Key, uint8_t *buf)
// Search for data in a table.   
int SearchFromTable(int FieldIndex, CustomerItem* item, CustomerItem* res_item, size_t* res_len)
// Search for data in a bucket.
int SearchFromBucket(int FieldIndex, CustomerItem* item, CustomerItem* res_item, size_t* res_len)
// Adjust the bucket based on the counter.
void AdjustBucket()
// Query a function.
int GetData(int32_t* FieldIndex, size_t field_len, uint64_t item_addr, uint64_t res_item_addr, size_t* res_len) 
```
