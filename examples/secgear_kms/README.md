# secGearKMS

## 介绍

基于secGear实现的密钥管理系统。
本密钥管理系统参考了 GMT0018-2012
标准，实现了设备管理、对称加密、非对称加密、数字摘要的功能。所有的密钥都保存在可信执行环境内部，避免特权攻击者的攻击。在加密算法上，本密钥管理系统主要支持国密系列的加密算法。

## 安装

```shell
mkdir build && cd build && cmake .. && make
sudo make install
```

## 使用

### 基本使用

运行单测：

```shell
sudo ./bin/secgear_kms_test
```

### 设备管理 API

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

通常来说，在开始使用之前，需要调用 `SDF_InitDevice` API，来初始化密钥。它需要传入密钥的存储路径、以及根密码。之后，它会随机生成
6 个密钥，其中 0、1、2 号密钥可以用来做对称几秒，3、4、5 号密钥可以用来做非对称加密。密钥初始化好以后，会被密封并保存到传入的存储路径上。
之后，在正常使用的过程中，需要先调用 `SDF_OpenDevice` 或 `SDF_OpenDevice_ext`
打开设备，并通过 `SDF_CreatePrivateKeyAccessPassword`
设置各个密钥的访问密码。这个函数需要传入根密码，根密码就是 `SDF_InitDevice` 设定的值。然后，调用 `SDF_OpenSession`
创建与设备的会话，并在会话中获取各个密钥的访问权限。此后，就可以使用各个密钥来调用加密 API 了。
在使用完成以后，需要调用 `SDF_CloseSession`、`SDF_CloseDevice` 来释放相关资源。

更详细的使用过程，可以参考[单元测试](./test/test.cpp)

### 对称加密

```cpp
int SDF_Encrypt(void * hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char * pucIV, unsigned char * pucData, unsigned int uiDataLength, unsigned char * pucEncData, unsigned int * puiEncDataLength);
int SDF_Decrypt(void * hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char * pucIV, unsigned char * pucEncData, unsigned int uiEncDataLength, unsigned char * pucData, unsigned int * puiDataLength);
```

### 非对称加密

```cpp
int SDF_InternalSign_ECC(void * hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char * pucRefData, unsigned int uiRefDataLength, ECCSignature * pucSignature);
int SDF_ExternalVerify_ECC(void * hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char * pucDataInput, unsigned int uiInputLength, ECCSignature * pucSignature);
int SDF_InternalDecrypt_ECC(void * hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char * pucData, unsigned int * uiDataLength, int SDF_ExternalEncrypt_ECC(void * hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey * pucPublicKey, unsigned char * pucData, unsigned int uiDataLength, ECCCipher * pucEncData);
int SDF_ExportEncPublicKey_ECC(void * hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey * pucPublicKey);
```

### 杂凑算法

```cpp
int SDF_HashInit(void * hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey * pucPublicKey, unsigned char * pucID, unsigned int uiIDLength);
int SDF_HashUpdate(void * hSessionHandle, unsigned char * pucData, unsigned int uiDataLength);
int SDF_HashFinal(void * hSessionHandle, unsigned char * pucHash, unsigned int * puiHashLength);
```