# 安全映射
## 客户痛点
现有的机密计算应用在计算时面临很大的加解密开销。以加密数据库作为典例，每次执行计算（如 SUM/AVG 等聚合）时，数据库系统都需要将密文逐一传入 TEE，由 TEE 解密后进行运算，再加密返回。以 SUM 为例，若表有 N 行数据，则需要进行 N−1 次跨域调用，每次涉及 2 次解密和 1 次加密。这种高频率的加/解密操作在真实业务场景中往往达到数千万级别，成为系统的关键性能瓶颈，导致吞吐量下降、查询延迟大幅增加。

## 解决方案
安全映射方案通过去加密来解决这个问题。本方案在 REE 的数据库中不再存放密文，而是存放固定宽度的随机映射 ID。TEE 内部维护一张高效的映射表（ID→明文），运算过程通过查表获得明文并在本地完成计算，结果再写回映射表生成新的 ID 返回 DBMS。最终结果在返回用户前统一进行加密。这样一来，查询关键路径由频繁的加/解密变为 O(1) 的查表与本地计算，极大减少跨域 RPC 与密码学开销，同时不泄露隐私，保持与现有数据库及应用的兼容。

## 使用方法
安全映射以lib库方式提供，主要有服务端 enclave 库，由服务端 TA 调用。还提供了服务端 host 所需的头文件。
| 模块         | 头文件                      | 库文件                   | 依赖      |
|------------|--------------------------|-----------------------|---------|
| 服务端host    | secure_mapping_host.h    | - | - |
| 服务端enclave | secure_mapping_enclave.h | libtsecure_mapping.a| TEE及TEE软件栈     |

## 接口
### CA API

本系统提供如下 CA-TA 接口调用：

``` C
public int cc_sm_transition_c2i(uint32_t session_id,
                [in, size = in_size] const uint8_t *in_data,
                size_t in_size,
                uint64_t key_id,
                [out] uint64_t *id_res);

public int cc_sm_transition_i2c(uint32_t session_id,
                [in] uint64_t *mapping_id,
                [out, size = 256] uint8_t *out_data,   // 256 为密文最大大小，可修改
                [out] size_t *out_size);
public int cc_sm_flush_data(uint32_t session_id);
```

1. cc_sm_transition_c2i：将输入的密文（in_data）转化为 ID 并返回（id_res）。也可以支持 replace 操作，也即若 key_id 不为 INVALID_PLAIN_ID，则解除 key_id 原本对应的明文映射，更换为与当前输入密文对应明文的新映射。

2. cc_sm_transition_i2c：将输入的 ID （mapping_id）转化为密文并返回（out_data）。

3. cc_sm_flush_data：持久化映射表到存储介质中。

### TA API

由于本系统与加解密实现解耦，用户可能需要自定义加解密实现方案、密钥管理方案等，故而选择提供若干钩子函数以兼得开发的便捷性和灵活性。
TA 应用开发时，可选择实现以下四个钩子函数：

``` C
/* hooks */
extern int cipher2plain(uint32_t session_id,
                        const char *cipher, size_t clen,
                        unsigned char *plain, size_t *plen);

extern int plain2cipher(uint32_t session_id,
                        const char *plain, size_t plen,
                        unsigned char *cipher, size_t *clen);

extern int c2i_post_process(uint32_t session_id,
                            const uint8_t *in_data, size_t in_size,
                            uint64_t mapping_id, uint64_t *id_res);

extern int i2c_pre_process(uint32_t session_id,
                           uint64_t *mapping_id,
                           uint8_t *out_data, size_t *out_size);
```

1. cipher2plain：必须实现。用于将输入的密文（cipher）转化为要存入表中的明文形式（plain）。

2. plain2cipher：必须实现。用于将查表得到的明文（plain）转化为要进入不可信环境（存储、网络、CA 等）的密文形式（cipher）。

3. c2i_post_process：可选实现。用于在 cc_sm_transition_c2i 被调用时、cipher2plain 被调用和插入表之后，做一些后续处理操作。可修改 in_data、id_res。

4. i2c_pre_process：可选实现。 用于在 cc_sm_transition_i2c 被调用时、查找表和 plain2cipher 被调用之前，做一些前序处理操作。可修改 mapping_id、out_data、out_size。


## 注意事项

1. 目前仅支持非确定性加密。这种方式更安全（避免明文模式泄露），但不支持等值比较的快速索引与匹配。

2. 当前多线程支持尚未完全。复杂场景下，需要在 读入 cache slot 后加写锁，并在完成更新后将写锁降级为读锁，以实现更高效的并发访问。
