#ifndef SECGEAR_KMS_H
#define SECGEAR_KMS_H

#include "error_code.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DeviceInfo_st {
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility;
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DeviceInfo;

#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN  ((RSAref_MAX_BITS+7)/8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS+1)/2)
#define RSAref_MAX_PLEN  ((RSAref_MAX_PBITS+7)/8)
typedef struct RSArefPublicKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN  ((ECCref_MAX_BITS+7)/8)
typedef struct ECCrefPublicKey_st {
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st {
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

// 在初始化时，需要分配足够的内存，以存储密文数据（C的空间应该大于等于L）
typedef struct ECCCipher_st {
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
    unsigned char C[1];
} ECCCipher;

typedef struct ECCSignature_st {
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

// 设备管理函数

/**
 * @brief SDF_InitDevice 初始化设备
 * @param [in] dev_path 设备文件存储路径，可以为 nullptr，此时设备文件会存储在默认路径
 * @param [in] root_password 根密码
 * @param [in] root_password_len 根密码长度
 * @return 错误码
*/
int SDF_InitDevice(const char *dev_path, const uint8_t *root_password, unsigned int root_password_len);

/**
 * @brief SDF_OpenDevice 打开设备
 * @param [out] phDeviceHandle 设备句柄
 * @return 错误码
 */
int SDF_OpenDevice(void **phDeviceHandle);

/**
 * @brief SDF_OpenDevice_ext 打开设备，设备文件会存储在用户指定的路径
 * @param [out] phDeviceHandle 设备句柄
 * @param dev_path 设备文件存储路径
 * @return 错误码
 */
int SDF_OpenDevice_ext(void **phDeviceHandle, const char *dev_path);

/**
 * @brief SDF_CloseDevice 关闭设备
 * @param [in] hDeviceHandle 设备句柄
 * @return 错误码
 */
int SDF_CloseDevice(void *hDeviceHandle);

/**
 * @brief SDF_CreatePrivateKeyAccessPassword 修改设备密钥的访问密码
 * @param [in] hDeviceHandle 设备句柄
 * @param [in] root_password 根密码
 * @param [in] root_password_len 根密码长度
 * @param [in] key_id 密钥索引
 * @param [in] pucPassword 用户密码
 * @param [in] uiPwdLength 用户密码长度
 * @return 错误码
 */
int
SDF_CreatePrivateKeyAccessPassword(void *hDeviceHandle, unsigned char *root_password, unsigned int root_password_len,
                                   unsigned int key_id, unsigned char *pucPassword, unsigned int uiPwdLength);

/**
 * @brief SDF_OpenSession 打开会话
 * @param [in] hDeviceHandle 设备句柄
 * @param [out] phSessionHandle 会话句柄
 * @return 错误码
 */
int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);

/**
 * @brief SDF_CloseSession 关闭会话
 * @param [in] hSessionHandle 会话句柄
 * @return 错误码
 */
int SDF_CloseSession(void *hSessionHandle);

/**
 * @brief SDF_GetDeviceInfo 获取设备信息
 * @param [in] hSessionHandle 会话句柄
 * @param [out] pstDeviceInfo 设备信息
 * @return 错误码
 */
int SDF_GetDeviceInfo(void *hSessionHandle, DeviceInfo *pstDeviceInfo);

/**
 * @brief SDF_GenerateRandom 生成随机数
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiLength 随机数长度
 * @param [out] pucRandom 随机数
 * @return 错误码
 */
int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom);

/**
 * @brief SDF_GetPrivateKeyAccessRight 获取私钥访问权限
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiKeyIndex 密钥索引
 * @param [in] pucPassword 密码
 * @param [in] uiPwdLength 密码长度
 * @return 错误码
 */
int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword,
                                 unsigned int uiPwdLength);

/**
 * @brief SDF_ReleasePrivateKeyAccessRight 释放私钥访问权限
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiKeyIndex 密钥索引
 * @return 错误码
 */
int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex);

// 非对称算法运算类函数

/**
 * @brief SDF_InternalSign_ECC 内部私钥 ECC 签名
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiKeyIndex 密钥索引
 * @param [in] uiAlgID 算法标识
 * @param [in] pucRefData 待签名数据
 * @param [in] uiRefDataLength 待签名数据长度
 * @param [out] pucSignature 签名结果
 * @return 错误码
 */
int SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char *pucRefData,
                         unsigned int uiRefDataLength, ECCSignature *pucSignature);

/**
 * @brief SDF_ExternalVerify_ECC 外部公钥 ECC 验签
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiAlgID 算法标识
 * @param [in] pucPublicKey 公钥
 * @param [in] pucDataInput 待验签数据
 * @param [in] uiInputLength 待验签数据长度
 * @param [in] pucSignature 签名结果
 * @return 错误码
 */
int SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                           unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);

/**
 * @brief SDF_InternalDecrypt_ECC 内部私钥 ECC 解密
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiKeyIndex 密钥索引
 * @param [in] uiAlgID 算法标识
 * @param [in] pucData 明文数据缓冲区
 * @param [in, out] uiDataLength 输入时，代表明文数据缓冲区长度；输出时，代表明文数据长度
 * @param [in] pucEncData 密文数据
 * @return 错误码
 */
int SDF_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char *pucData,
                            unsigned int *uiDataLength, ECCCipher *pucEncData);

/**
 * @brief SDF_ExternalEncrypt_ECC 外部公钥 ECC 加密
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiAlgID 算法标识
 * @param [in] pucPublicKey 公钥
 * @param [in] pucData 明文数据
 * @param [in] uiDataLength 明文数据长度
 * @param [out] pucEncData 密文数据，需要分配足够的内存空间，通常来说，应为明文数据长度加上 ECCCipher 结构体的长度，即 uiDataLength + sizeof(ECCCipher)
 * @return 错误码
 */
int SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
                            unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncData);

/**
 * @brief SDF_ExportEncPublicKey_ECC 导出 ECC 公钥
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiKeyIndex 密钥索引
 * @param [out] pucPublicKey 公钥
 * @return 错误码
 */
int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);

// 对称算法运算类函数

/**
 * @brief SDF_Encrypt 对称密钥加密
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiKeyIndex 密钥索引
 * @param [in] uiAlgID 算法标识
 * @param [in] pucIV 初始化向量
 * @param [in] pucData 明文数据
 * @param [in] uiDataLength 明文数据长度
 * @param [out] pucEncData 密文数据缓冲区
 * @param [in, out] puiEncDataLength 输入时，代表密文数据缓冲区长度；输出时，代表密文数据长度，通常来说，应为明文数据长度加上一个分组长度，即 uiDataLength + SDF_SM4_GROUP_LENGTH
 * @return 错误码
 */
int SDF_Encrypt(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char *pucIV,
                unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData,
                unsigned int *puiEncDataLength);

/**
 * @brief SDF_Decrypt 对称密钥解密
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiKeyIndex 密钥索引
 * @param [in] uiAlgID 算法标识
 * @param [in] pucIV 初始化向量
 * @param [in] pucEncData 密文数据
 * @param [in] uiEncDataLength 密文数据长度
 * @param [out] pucData 明文数据缓冲区
 * @param [in, out] puiDataLength 输入时，代表明文数据缓冲区长度；输出时，代表明文数据长度，通常来说，不会超过密文数据长度
 * @return 错误码
 */
int SDF_Decrypt(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, unsigned char *pucIV,
                unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData,
                unsigned int *puiDataLength);

// 杂凑算法运算类函数

/**
 * @brief SDF_HashInit 杂凑算法初始化
 * @param [in] hSessionHandle 会话句柄
 * @param [in] uiAlgID 算法标识
 * @param [in] pucPublicKey 公钥
 * @param [in] pucID 用户 ID
 * @param [in] uiIDLength 用户 ID 长度
 * @return 错误码
 */
int SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucID,
                 unsigned int uiIDLength);

/**
 * @brief SDF_HashUpdate 杂凑算法更新
 * @param [in] hSessionHandle 会话句柄
 * @param [in] pucData 数据
 * @param [in] uiDataLength 数据长度
 * @return 错误码
 */
int SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);

/**
 * @brief SDF_HashFinal 杂凑算法结束
 * @param [in] hSessionHandle 会话句柄
 * @param [out] pucHash 杂凑值
 * @param [in, out] puiHashLength 输入时，代表杂凑值缓冲区长度；输出时，代表杂凑值长度，通常来说，应为杂凑算法的输出长度
 * @return 错误码
 */
int SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength);

#ifdef __cplusplus
}
#endif


#endif  // SECGEAR_KMS_H
