# API Reference

The secGear unified programming framework for confidential computing consists of the TEE and REE. This section describes the APIs required for developing applications. In addition to these APIs, the TEE inherits the open-source POSIC APIs of ARM TrustZone and Intel SGX.

## cc_enclave_create

Creates an enclave API.

**Function:**

Initialization API. The function calls different TEE creation functions based on the type to initialize the enclave context in different TEE solutions. This API is called by the REE.

> [!NOTE]NOTE  
> Due to Intel SGX restrictions, memory mapping contention exists when multiple thread invoke cc_enclave_create concurrently. As a result, the creation of the enclave API may fail. Avoid concurrent invocations of cc_enclave_create in your code.

**Function Declaration:**

```c
cc_enclave_result_t cc_enclave_create(const char* path, enclave_type_t type, uint32_t version,uint32_t flags,const enclave_features_t* features,uint32_t features_count,
 cc_enclave_t  ** enclave);
```

**Parameters:**

- Path: input parameter, which specifies a path of the enclave to be loaded.
- Type: input parameter, which specifies the TEE solution, for example, SGX_ENCLAVE_TYPE, GP_ENCLAVE_TYPE and AUTO_ENCLAVE_TYPE.
- version: input parameter, which specifies the enclave engine version. Currently, there is only one version, and the value is 0.
- Flags: input parameter, which specifies the running status of the enclave. For example, SECGEAR_DEBUG_FLAG indicates the debugging status, and SECGEAR_SIMULATE_FLAG indicates the simulation status (not supported currently).
- features: input parameter, which specifies some features supported by the enclave, for example, PCL and switchless of the SGX. This parameter is not supported currently. Set it to NULL.
- features_count: input parameter, which specifies the number of features. This parameter is not supported currently. Set it to 0.
- enclave: output parameter, which specifies the created enclave context.

**Return Values:**

- CE_SUCCESS: The authentication information is verified successfully.
- CE_ERROR_INVALID_PARAMETER: The input parameter is incorrect.
- CE_ERROR_OUT_OF_MEMORY: No memory is available.
- CC_FAIL: Common failure.
- CC_ERROR_UNEXPECTED: Unexpected error.
- CC_ERROR_ENCLAVE_MAXIMUM: The number of enclaves created by a single app reaches the maximum.
- CC_ERROR_INVALID_PATH: The secure binary path is invalid.
- CC_ERROR_NO_FIND_REGFUNC: The enclave search fails.

## cc_enclave_destroy

Destroys the enclave API.

**Function:**

This API is called by the REE to call the exit functions of different TEEs to release the created enclave entities.

**Function Declaration:**

```c
cc_enclave_result_t cc_enclave_destroy (cc_enclave_t ** enclave);
```

**Parameter:**

- enclave: input parameter, which specifies the context of the created enclave.

**Return Values:**

- CE_SUCCESS: The authentication information is verified successfully.
- CE_ERROR_INVALID_PARAMETER: The input parameter is incorrect.
- CE_ERROR_OUT_OF_MEMORY: No memory is available.
- CC_ERROR_NO_FIND_UNREGFUNC: The enclave search fails.
- CC_FAIL: common failure.
- CC_ERROR_UNEXPECTED: unexpected error.

## cc_malloc_shared_memory

Creates the shared memory.

**Functions**

After the switchless feature is enabled, this API is called by the REE to create the shared memory that can be accessed by both the TEE and REE.

**Function Declaration:**

```c
void *cc_malloc_shared_memory(cc_enclave_t *enclave, size_t size);
```

**Parameters:**

- enclave: input parameter, which indicates the context handle of the secure environment. Different platforms have different shared memory models. To ensure cross-platform interface consistency, this parameter is used only on the ARM platform and is ignored on the SGX platform.
- size: input parameter, which indicates the size of the shared memory.

**Return Values:**

- NULL: Failed to apply for the shared memory.
- Other values: start address of the created shared memory.

## cc_free_shared_memory

Releases the shared memory.

**Functions**

This API is called by the REE to release the shared memory after the switchless feature is enabled.

**Function Declaration:**

```c
cc_enclave_result_t cc_free_shared_memory(cc_enclave_t *enclave, void *ptr);
```

**Parameters:**

- enclave: input parameter, which indicates the context handle of the secure environment. Different platforms have different shared memory models. To ensure cross-platform interface consistency, this parameter is used only on the ARM platform (the value of this parameter must be the same as the value of enclave passed when cc_malloc_shared_memory is invoked). It is ignored on the SGX platform.
- ptr: input parameter, which indicates the shared memory address returned by cc_malloc_shared_memory.

**Return Values:**

- CC_ERROR_BAD_PARAMETERS: invalid input parameter.
- CC_ERROR_INVALID_HANDLE: The enclave is invalid or the input enclave does not match the enclave corresponding to the ptr. (It takes effect only on the ARM platform. The SGX platform ignores the enclave and therefore does not check the enclave.)
- CC_ERROR_NOT_IMPLEMENTED: The API is not implemented.
- CC_ERROR_SHARED_MEMORY_START_ADDR_INVALID: ptr is not the shared memory address returned by cc_malloc_shared_memory (valid only on the ARM platform).
- CC_ERROR_OUT_OF_MEMORY: insufficient memory (valid only on the ARM platform).
- CC_FAIL: common failure.
- CC_SUCCESS: success

## cc_enclave_generate_random

Generates random numbers.

**Function:**

Generate a secure random number for the password on the TEE.

**Function Declaration:**

```c
cc_enclave_result_t cc_enclave_generate_random(void *buffer, size_t size)
```

**Parameters:**

- buffer: input parameter, which specifies the buffer for generating random numbers.
- size: input parameter, which specifies the buffer length.

**Return Values:**

- CE_OK: Authentication information is verified successfully.
- CE_ERROR_INVALID_PARAMETER: incorrect input parameter.
- CE_ERROR_OUT_OF_MEMORY: no memory is available.

## cc_enclave_seal_data

Ensures data persistence.

**Function:**

This API is called by the TEE to encrypt the internal data of the enclave so that the data can be persistently stored outside the enclave.

**Function Declaration:**

```c
cc_enclave_result_t cc_enclave_seal_data(uint8_t *seal_data, uint32_t seal_data_len,

    cc_enclave_sealed_data_t *sealed_data, uint32_t sealed_data_len,

    uint8_t *additional_text, uint32_t additional_text_len)
```

**Parameters:**

- seal_data: input parameter, which specifies the data to be encrypted.
- seal_data_len: input parameter, which specifies the length of the data to be encrypted.
- sealed_data: output parameter, which specifies the encrypted data processing handle.
- sealed_data_len: output parameter, which specifies the length of the encrypted ciphertext.
- additional_text: input parameter, which specifies the additional message required for encryption.
- additional_text_len: input parameter, which specifies the additional message length.

**Return Values:**

- CE_SUCCESS: Data encryption succeeds.
- CE_ERROR_INVALID_PARAMETER: incorrect input parameter.
- CE_ERROR_OUT_OF_MEMORY: no memory is available.
- CC_ERROR_SHORT_BUFFER: The input buffer is too small.
- CC_ERROR_GENERIC: Common bottom-layer hardware error.

## cc_enclave_unseal_data

Decrypts data.

**Function:**

This API is called by the TEE to decrypt the data sealed by the enclave and import the external persistent data back to the enclave.

**Function Declaration:**

```c
cc_enclave_result_t cc_enclave_unseal_data(cc_enclave_sealed_data_t *sealed_data,

    uint8_t *decrypted_data, uint32_t *decrypted_data_len,

    uint8_t *additional_text, uint32_t *additional_text_len)
```

**Parameters:**

- sealed_data: input parameter, which specifies the handle of the encrypted data.
- decrypted_data: output parameter, which specifies the buffer of the decrypted ciphertext data.
- decrypted_data_len: output parameter, which specifies the length of the decrypted ciphertext.
- additional_text: output parameter, which specifies an additional message after decryption.
- additional_text_len: output parameter, which specifies the length of the additional message after decryption.

**Return Values:**

- CE_SUCCESS: Data decryption is successful.
- CE_ERROR_INVALID_PARAMETER: incorrect input parameter.
- CE_ERROR_OUT_OF_MEMORY: no memory is available.
- CC_ERROR_SHORT_BUFFER: The input buffer is too small.
- CC_ERROR_GENERIC: common bottom-layer hardware error.

## cc_enclave_get_sealed_data_size

Obtains the size of the encrypted data.

**Function:**

Obtain the size of the sealed_data data. This API can be called by the TEE and REE to allocate the decrypted data space.

**Function Declaration:**

```c
uint32_t cc_enclave_get_sealed_data_size(const uint32_t add_len, const uint32_t seal_data_len);
```

**Parameters:**

- add_len: input parameter, which specifies the additional message length.
- sealed_data_len: input parameter, which specifies the length of the encrypted information.

**Return Values:**

- UINT32_MAX: Parameter error or function execution error.
- others: The function is successfully executed, and the return value is the size of the sealed_data structure.

## cc_enclave_get_encrypted_text_size

Obtains the length of an encrypted message.

**Function:**

This API is called by the TEE to obtain the length of the encrypted message in the encrypted data.

**Function Declaration:**

```c
uint32_t cc_enclave_get_encrypted_text_size(const cc_enclave_sealed_data_t *sealed_data);
```

**Parameter:**

- sealed_data: input parameter, which specifies the handle of the encrypted data

**Return Values:**

- UINT32_MAX: Parameter error or function execution error.
- others: The function is executed successfully, and the return value is the length of the encrypted message in sealed_data.

## cc_enclave_get_add_text_size

Obtains the length of an additional message.

**Function:**

This API is called by the TEE to obtain the length of the additional message in the encrypted data.

**Function Declaration:**

```c
uint32_t cc_enclave_get_add_text_size(const cc_enclave_sealed_data_t *sealed_data);
```

**Parameter:**

- sealed_data: input parameter, handle of the encrypted data.

**Return Values:**

- UINT32_MAX: Parameter error or function execution error.
- others: The function is successfully executed, and the return value is the length of the additional message in sealed_data.

## cc_enclave_memory_in_enclave

Performs security memory check.

**Function:**

This API is called by the TEE to check whether the memory addresses of the specified length belong to the TEE.

**Function Declaration:**

```c
bool cc_enclave_memory_in_enclave(const void *addr, size_t size)
```

**Parameters:**

- *addr: input parameter, which specifies the memory address to be verified.
- size: input parameter, which specifies the length to be verified starting from the memory address.

**Return Values:**

- true: The memory in the specified zone is in the secure zone.
- false: Some or all memory in the specified area is not within the secure range.

## cc_enclave_memory_out_enclave

Performs security memory check.

**Function:**

This API is called by the TEE to check whether the memory addresses of the specified length belong to the REE.

**Function Declaration:**

```c
bool cc_enclave_memory_out_enclave(const void *addr, size_t size)
```

**Parameters:**

- *addr: input parameter, which specifies the memory address to be verified.
- size: input parameter, length to be verified starting from the memory address.

**Return Values:**

- true: The memory of the specified area is in the non-secure area.
- false: Some or all of the memory in the specified zone is in the secure area.

## PrintInfo

Prints messages.

**Function:**

Print TEE logs. This API outputs the information that the TEE user wants to print. The input logs are stored in the REE /var/log/secgear/secgear.log.

**Function Declaration:**

```c
void PrintInfo(int level, const char *fmt, ...);
```

**Parameters:**

- level: log print level, which is an input parameter. The value can be PRINT_ERROR, PRINT_WARNING, PRINT_STRACE, and PRINT_DEBUG.
- fmt: Input parameter, and a character to be output.

**Return Value:**

- None
