# Security Mapping

## Customer Pain Points

Existing confidential computing applications face high encryption and decryption overheads during computation. For example, in an encrypted database, each computation (such as SUM/AVG aggregation) requires the database system to pass the ciphertext to the TEE one by one, and the TEE to decrypt the ciphertext, perform computation, and then encrypt and return the result. Take SUM as an example: If a table contains *N* rows of data, *N* – 1 cross-domain calls are required, each involving two decryptions and one encryption. In real-world services, such high-frequency encryption and decryption operations often reach tens of millions, creating a critical performance bottleneck that reduces throughput and sharply increases query latency.

## Solution

The secure mapping solution solves this problem by reducing encryptions. In this solution, the database in the REE stores fixed-width random mapping IDs instead of ciphertext. The TEE maintains an efficient mapping table (ID → plaintext). During computation, the plaintext is obtained by querying the table and computation is performed locally. The result is written back to the mapping table to generate a new ID, which is returned to the DBMS. The final result is encrypted before being returned to the user. In this way, the key query path is changed from frequent encryption and decryption operations to O(1) table lookups and local computation, greatly reducing the cross-domain RPC and cryptographic overheads, while preserving privacy and maintaining compatibility with existing databases and applications.

## Usage

The secure mapping is provided as a library, mainly the server enclave library, which is called by the server TA. The header file required by the server host is also provided.

| Module        | Header File                     | Library File                  | Dependency     |
|------------|--------------------------|-----------------------|---------|
| Server host   | secure_mapping_host.h    | - | - |
| Server enclave| secure_mapping_enclave.h | libtsecure_mapping.a| TEE and TEE software stack    |

## APIs

### CA APIs

The system provides the following CA-TA APIs:

```C
public int cc_sm_transition_c2i(uint32_t session_id,
                [in, size = in_size] const uint8_t *in_data,
                size_t in_size,
                uint64_t key_id,
                [out] uint64_t *id_res);

public int cc_sm_transition_i2c(uint32_t session_id,
                [in] uint64_t *mapping_id,
                [out, size = 256] uint8_t *out_data,   // 256 indicates the maximum size of the ciphertext, which can be changed.
                [out] size_t *out_size);
public int cc_sm_flush_data(uint32_t session_id);
```

1. **cc_sm_transition_c2i**: converts the input ciphertext (**in_data**) into an ID and returns the ID (**id_res**). The replace operation is also supported. That is, if **key_id** is not **INVALID_PLAIN_ID**, the original plaintext mapping corresponding to **key_id** is removed and replaced with a new plaintext mapping corresponding to the current input ciphertext.

2. **cc_sm_transition_i2c**: converts the input ID (**mapping_id**) into ciphertext and returns the ciphertext (**out_data**).

3. **cc_sm_flush_data**: flushes the mapping table to the storage medium.

### TA APIs

The system is decoupled from the encryption and decryption. Therefore, users may need to customize the encryption and decryption implementation and key management solutions. To ensure development convenience and flexibility, several hook functions are provided.
The following hook functions can be implemented during TA development:

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

1. **cipher2plain**: (mandatory) converts the input ciphertext (**cipher**) into the plaintext (**plain**) to be stored in the table.

2. **plain2cipher**: (mandatory) converts the plaintext (**plain**) queried from the table into the ciphertext (**cipher**) to be stored in an untrusted environment (such as storage, network, and CA).

3. **c2i_post_process**: (optional) performs post-processing operations when cc_sm_transition_c2i is called (after cipher2plain is called and data is inserted into the table). **in_data** and **id_res** can be modified.

4. **i2c_pre_process**: (optional) performs pre-processing operations when cc_sm_transition_i2c is called (before the table is queried and plain2cipher is called). **mapping_id**, **out_data**, and **out_size** can be modified.

## Precautions

1. Currently, only non-deterministic encryption is supported. This mode is more secure (avoiding plaintext leakage), but does not support fast index and matching for equality comparison.

2. Currently, multi-thread support is not fully implemented. In complex scenarios, a write lock needs to be added after the cache slot is read, and the write lock needs to be downgraded to a read lock after the update is complete to achieve more efficient concurrent access.
