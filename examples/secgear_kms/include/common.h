#ifndef SECGEAR_KMS_COMMON_H
#define SECGEAR_KMS_COMMON_H

#include <cstdio>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// 设备管理
#define DEFAULT_STORAGE_FILE_PATH "/tmp/secgear_kms_storage"

// 对称加密

#define SGD_SM4_ECB 0x00000101
#define SGD_SM4_CBC 0x00000102
#define SGD_SM4_CFB 0x00000104
#define SGD_SM4_OFB 0x00000108

#define SDF_SM4_GROUP_LENGTH 16
#define SDF_SM4_IV_LENGTH SDF_SM4_GROUP_LENGTH

// 非对称加密
#define SGD_SM2 0x00020100

// 杂凑算法
#define SGD_SM3 0x00000001
#define SGD_SM3_SM2 0x00020101
#define SGD_SHA1 0x00000002

#define SGD_MAX_MD_SIZE 64

const static size_t SESSION_KEY_LEN = 32;

#ifdef __cplusplus
}
#endif

#endif  // SECGEAR_KMS_COMMON_H