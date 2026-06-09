# secGearKMS

## Overview

secGearKMS is a key management system (KMS) implemented based on secGear.
It complies with GM/T 0018-2012, and provides functions such as device management, symmetric encryption, asymmetric encryption, and digital digest. All keys are stored in the trusted execution environment (TEE) to prevent attacks from privileged attackers. In terms of encryption algorithms, secGearKMS primarily supports SM series cryptographic algorithms.

## Installation

```shell
mkdir build && cd build && cmake .. && make
sudo make install
```

## Usage

### Basic Usage

Run the unit test.

```shell
sudo ./bin/secgear_kms_test
```

### Device Management APIs

```cpp
int SDF_InitDevice(const char * dev_path, const uint8_t * root_password, unsigned int root_password_len);
int SDF_OpenDevice(void * * phDeviceHandle);
int SDF_OpenDevice_ext(void * * phDeviceHandle, const char * dev_path);
int SDF_CloseDevice(void * hDeviceHandle);
int SDF_CreatePrivateKeyAccessPassword(void * hDeviceHandle, unsigned char * root_password, unsigned int root_password_len, unsigned int key_id, unsigned char * pucPassword, unsigned int uiPwdLength);
int SDF_OpenSession(void * hDeviceHandle, void * * phSessionHandle);
int SDF_CloseSession(void * hSessionHandle);
int SDF_GetDeviceInfo(void * hSessionHandle, DeviceInfo * pstDeviceInfo);
int SDF_GenerateRandom(void * hSessionHandle, unsigned int uiLength, unsigned char * pucRandom);
int SDF_GetPrivateKeyAccessRight(void * hSessionHandle, unsigned int uiKeyIndex, unsigned char * pucPassword, unsigned int uiPwdLength);
int SDF_ReleasePrivateKeyAccessRight(void * hSessionHandle, unsigned int uiKeyIndex);
```

Generally, you need to call the `SDF_InitDevice` API to initialize keys before using secGearKMS. This API requires the key storage path and root password. It then generates six random keys:
Keys 0, 1, and 2 can be used for symmetric encryption, and keys 3, 4, and 5 can be used for asymmetric encryption. Once initialized, the keys are sealed and saved to the passed storage path.
During normal use, first call the `SDF_OpenDevice` or `SDF_OpenDevice_ext` API
to open the device and use `SDF_CreatePrivateKeyAccessPassword`
to set access passwords for the keys. This function requires the root password, which is the value set by `SDF_InitDevice`. Then, call the `SDF_OpenSession` API
to create a session with the device and obtain the access permissions for the keys in the session. You may then use these keys to call the encryption API.
After use, call the `SDF_CloseSession` and `SDF_CloseDevice` APIs to release related resources.

For more details about the usage process, see [example](./test/test.cpp).

### Symmetric Encryption

```cpp
int SDF_Encrypt(void * hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char * pucIV, unsigned char * pucData, unsigned int uiDataLength, unsigned char * pucEncData, unsigned int * puiEncDataLength);
int SDF_Decrypt(void * hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char * pucIV, unsigned char * pucEncData, unsigned int uiEncDataLength, unsigned char * pucData, unsigned int * puiDataLength);
```

### Asymmetric Encryption

```cpp
int SDF_InternalSign_ECC(void * hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char * pucRefData, unsigned int uiRefDataLength, ECCSignature * pucSignature);
int SDF_ExternalVerify_ECC(void * hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char * pucDataInput, unsigned int uiInputLength, ECCSignature * pucSignature);
int SDF_InternalDecrypt_ECC(void * hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char * pucData, unsigned int * uiDataLength, int SDF_ExternalEncrypt_ECC(void * hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey * pucPublicKey, unsigned char * pucData, unsigned int uiDataLength, ECCCipher * pucEncData);
int SDF_ExportEncPublicKey_ECC(void * hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey * pucPublicKey);
```

### Hash Algorithm

```cpp
int SDF_HashInit(void * hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey * pucPublicKey, unsigned char * pucID, unsigned int uiIDLength);
int SDF_HashUpdate(void * hSessionHandle, unsigned char * pucData, unsigned int uiDataLength);
int SDF_HashFinal(void * hSessionHandle, unsigned char * pucHash, unsigned int * puiHashLength);
```
