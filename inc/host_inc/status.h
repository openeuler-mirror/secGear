/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef FINAL_SECGEAR_STATUS_H
#define FINAL_SECGEAR_STATUS_H

# ifdef  __cplusplus
extern "C" {
# endif

#ifndef NULL
#define NULL    ((void *)0)
#endif
#define SECGEAR_ENUM_MAX 0xffffffff

typedef enum _enclave_result_t
{
    CC_SUCCESS = 0x0,                /* *< 成功  */
    CC_ERROR_INVALID_CMD,            /* *< 非法命令 */
    CC_ERROR_SERVICE_NOT_EXIST,      /* *< 服务不存在 */
    CC_ERROR_ENCLAVE_LOST,      /* *< gp:TEE_ERROR_SESSION_NOT_EXIST 连接不存在 */
    CC_ERROR_ENCLAVE_MAXIMUM,        /* *< 连接数或enclave数量已满 */
    CC_ERROR_REGISTER_EXIST_SERVICE, /* *< 注册已经存在的服务 */
    CC_ERROR_TARGET_DEAD_FATAL,      /* *< Global Task 崩溃  */
    CC_ERROR_READ_DATA,              /* *< 读取文件错误 */
    CC_ERROR_WRITE_DATA,             /* *< 写入文件错误 */
    CC_ERROR_TRUNCATE_OBJECT,        /* *< 截断文件错误 */
    CC_ERROR_SEEK_DATA,              /* *< 查找文件错误 */
    CC_ERROR_SYNC_DATA,              /* *< 同步文件错误 */
    CC_ERROR_RENAME_OBJECT,          /* *< 重命名文件错误 */
    CC_ERROR_INVALID_ENCLAVE, /* *< 打开会话时，加载可信应用程序失败 */
    CC_ERROR_INVALID_PATH,
    CC_ERROR_INVALID_TYPE,	    /*trust framwork sdk is not recognized*/
    CC_ERROR_OUT_OF_TCS,           /*SPECIFICATION FOR SGX*/
    CC_ERROR_ECALL_NOT_ALLOWED,      /* ecall function is not available*/
    CC_ERROR_OCALL_NOT_ALLOWED,      /*ocall function is not available*/
    CC_ERROR_INVALID_ENCLAVE_ID,     /*enclave ID invalid*/
    CC_ERROR_NDEBUG_ENCLAVE,         /*cc_enclave is not in debug mode*/
    CC_ERROR_OUT_OF_EPC,          /*Not enough EPC is available to load the enclave*/
    CC_ERROR_NO_DEVICE,              /*Can't find enclave device*/
    CC_ERROR_MEMORY_MAP_FAIL,        /* Page mapping failed in driver */
    CC_ERROR_INVALID_METADATA,       /* The metadata is incorrect */
    CC_ERROR_INVALID_VERSION,        /* Metadata version is inconsistent */
    CC_ERROR_INVALID_MISC,           /* The MiscSelct/MiscMask settings are not correct */
    CC_ERROR_INVALID_ATTRIBUTE,      /* The enclave is not authorized */
    CC_ERROR_INVALID_CPUSVN,         /* The cpu svn is beyond platform's cpu svn value */
    CC_ERROR_INVALID_ISVSVN,         /* The isv svn is greater than the enclave's isv svn */
    CC_ERROR_INVALID_KEYNAME,        /* The key name is an unsupported value */  
    CC_ERROR_AE_INVALID_EPIDBLOB,    /* Indicates epid blob verification error */
    CC_ERROR_SERVICE_INVALID_PRIVILEGE,  /* Enclave not authorized to run */
    CC_ERROR_EPID_MEMBER_REVOKED,        /* The EPID group membership is revoked */
    CC_ERROR_UPDATE_NEEDED,          /* SDK need to be update*/
    CC_ERROR_MC_NOT_FOUND,           /* The Monotonic Counter doesn't exist or has been invalided */
    CC_ERROR_MC_NO_ACCESS_RIGHT,     /* Caller doesn't have the access right to specified VMC */
    CC_ERROR_MC_USED_UP,             /* Monotonic counters are used out */
    CC_ERROR_MC_OVER_QUOTA,          /* Monotonic counters exceeds quota limitation */
    CC_ERROR_KDF_MISMATCH,           /* Key derivation function doesn't match during key exchange */
    CC_ERROR_UNRECOGNIZED_PLATFORM,  /* EPID Provisioning failed due to platform not recognized by backend */
    CC_ERROR_UNSUPPORTED_CONFIG,     /* The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid */
/*PLC*/
    CC_ERROR_PCL_ENCRYPTED,         /* trying to encrypt an already encrypted enclave */
    CC_ERROR_PCL_NOT_ENCRYPTED,     /* PCL enclave is not encrepted  */
    CC_ERROR_PCL_MAC_MISMATCH,      /* section mac result does not match build time mac */
    CC_ERROR_PCL_SHA_MISMATCH,      /* Unsealed key MAC does not match MAC of key hardcoded in enclave binary */
    CC_ERROR_PCL_GUID_MISMATCH,     /* GUID in sealed blob does not match GUID hardcoded in enclave binary */
/*attestation*/
    CC_ERROR_UNSUPPORTED_ATT_KEY_ID,            /* platform quoting infrastructure does not support the key */
    CC_ERROR_ATT_KEY_CERTIFICATION_FAILURE,     /* Failed to generate and certify the attestation key */
    CC_ERROR_ATT_KEY_UNINITIALIZED,             /* attestation key is not initialized*/
    CC_ERROR_INVALID_ATT_KEY_CERT_DATA,         /* attestation data is not valid*/
    CC_ERROR_PLATFORM_CERT_UNAVAILABLE,         /* cert is not available*/
    
    CC_ERROR_OTRP_BASE = 0x80000100,  /* sec file config source is not inconsistent with the loading mode. */
    CC_ERROR_STORAGE_EIO        = 0x80001001, /* *<安全存储I/O错误 */
    CC_ERROR_STORAGE_EAGAIN     = 0x80001002, /* *<安全存储分区暂时不可用，请重试 */
    CC_ERROR_STORAGE_ENOTDIR    = 0x80001003, /* *<操作不是目录，无法操作 */
    CC_ERROR_STORAGE_EISDIR     = 0x80001004, /* *<操作对象是目录，无法操作 */
    CC_ERROR_STORAGE_ENFILE     = 0x80001005, /* *<对于系统来说，打开文件数已达到最大值 */
    CC_ERROR_STORAGE_EMFILE     = 0x80001006, /* *<对于进程来说，打开文件数已达到最大值 */
    CC_ERROR_STORAGE_EROFS      = 0x80001007, /* *<安全存储分区只读 */
    CC_ERROR_STORAGE_INSE_NOTSUPPORT =  0x80001008, /* SFS inse not supported beacause not up on or platform not supported */
    CC_ERROR_STORAGE_INSE_ERROR      = 0x80001009, /* SFS inse encrypto / decrypto error */
    CC_ERROR_STORAGE_NOT_FOUND       = 0x8000100A, /*gp:CC_ERROR_STORAGE_PATH_WRONG 文件未找到 */
    CC_ERROR_MSG_QUEUE_OVERFLOW      = 0x8000100B, /* sevice msg queue overflow*/
    CC_ERROR_STORAGE_NO_KEY_ID,                    /* storage key id not found*/
    CC_ERROR_FILE_FLUSH_FAILED,                    /* storage file flush fail*/
    CC_ERROR_FILE_CLOSE_FAILED,                    /* storage file close fail*/
    
    CC_ERROR_CORRUPT_OBJECT           = 0xF0100001, /* *<文件被损坏 */
    CC_ERROR_STORAGE_NOT_AVAILABLE    = 0xF0100003, /* *<安全存储分区不可用 */
    CC_ERROR_CIPHERTEXT_INVALID       = 0xF0100006, /* 密文错误 */
    CC_ISOCKET_ERROR_PROTOCOL         = 0xF1007001,
    CC_ISOCKET_ERROR_REMOTE_CLOSED    = 0xF1007002,
    CC_ISOCKET_ERROR_TIMEOUT          = 0xF1007003,
    CC_ISOCKET_ERROR_OUT_OF_RESOURCES = 0xF1007004,
    CC_ISOCKET_ERROR_LARGE_BUFFER     = 0xF1007005,
    CC_ISOCKET_WARNING_PROTOCOL       = 0xF1007006,
    CC_ERROR_GENERIC                  = 0xFFFF0000, /* *< 通用错误  */
    CC_ERROR_ACCESS_DENIED            = 0xFFFF0001, /* *< 权限校验失败  */
    CC_ERROR_CANCEL                   = 0xFFFF0002, /* *< 操作已取消  */
    CC_ERROR_ACCESS_CONFLICT          = 0xFFFF0003, /* *< 并发访问导致冲突  */
    CC_ERROR_EXCESS_DATA              = 0xFFFF0004, /* *< 操作包含的数据太多  */
    CC_ERROR_BAD_FORMAT               = 0xFFFF0005, /* *< 数据格式不正确  */
    CC_ERROR_BAD_PARAMETERS           = 0xFFFF0006, /* *< 参数无效  */
    CC_ERROR_BAD_STATE                = 0xFFFF0007, /* *< 当前状态下的操作无效  */
    CC_ERROR_ITEM_NOT_FOUND           = 0xFFFF0008, /* *< 请求的数据未找到  */
    CC_ERROR_NOT_IMPLEMENTED          = 0xFFFF0009, /* *< 请求的操作存在但暂未实现  */
    CC_ERROR_NOT_SUPPORTED            = 0xFFFF000A, /* *< 请求的操作有效但未支持  */
    CC_ERROR_NO_DATA                  = 0xFFFF000B, /* *< 数据错误  */
    CC_ERROR_OUT_OF_MEMORY            = 0xFFFF000C, /* *< 系统没有可用资源  */
    CC_ERROR_BUSY                     = 0xFFFF000D, /* *< 系统繁忙  */
    CC_ERROR_COMMUNICATION            = 0xFFFF000E, /* *< 与第三方通信失败  */
    CC_ERROR_SECURITY                 = 0xFFFF000F, /* *< 检测到安全错误  */
    CC_ERROR_SHORT_BUFFER             = 0xFFFF0010, /* *< 内存输入长度小于输出长度  */
    CC_ERROR_EXTERNAL_CANCEL          = 0xFFFF0011, /* *< 操作被中断  */
    CC_PENDING                        = 0xFFFF2000, /* *< 可信服务处于等待状态(异步调用) */
    CC_PENDING2                       = 0xFFFF2001, /* *< 可信服务处于等待状态2(命令未完成) */
    CC_PENDING3                       = 0xFFFF2002,
    CC_ERROR_TIMEOUT                  = 0xFFFF3001, /* *< 请求超时 */
    CC_ERROR_OVERFLOW                 = 0xFFFF300f, /* *< 计算溢出 */
    CC_ERROR_ENCLAVE_DEAD              = 0xFFFF3024, /* *< Trusted Application崩溃  */
    CC_ERROR_STORAGE_NO_SPACE         = 0xFFFF3041, /* *< 没有足够的Flash空间来存储文件 */
    CC_ERROR_MAC_INVALID              = 0xFFFF3071, /* *< MAC值校验错误 */
    CC_ERROR_SIGNATURE_INVALID        = 0xFFFF3072, /* *< 校验失败 */
    CC_CLIENT_INTR                    = 0xFFFF4000, /* Interrupted by CFC. Broken control flow is detected. */
    CC_ERROR_TIME_NOT_SET             = 0xFFFF5000, /* *< 时间未设置 */
    CC_ERROR_TIME_NEEDS_RESET         = 0xFFFF5001, /* *< 时间需要重置 */
    CC_FAIL                           = 0xFFFF5002, /* *< 时间需要重置 */
    CC_ERROR_TIMER                    = 0xFFFF6000,
    CC_ERROR_TIMER_CREATE_FAILED,
    CC_ERROR_TIMER_DESTORY_FAILED,
    CC_ERROR_TIMER_NOT_FOUND,
    CC_ERROR_RPMB_BASE    = 0xFFFF7000,               /* *< RPMB安全存储错误码基址 */
    CC_ERROR_TUI_BASE = 0xFFFF7110,                       /*tui base error*/
    CC_ERROR_SEC_FLASH_NOT_AVAILABLE,
    CC_ERROR_SESRV_NOT_AVAILABLE,
    CC_ERROR_BIOSRV_NOT_AVAILABLE,
    CC_ERROR_ROTSRV_NOT_AVAILABLE,
    CC_ERROR_ARTSRV_NOT_AVAILABLE,
    CC_ERROR_ANTIROOT_RSP_FAIL     = 0xFFFF9110,
    CC_ERROR_ANTIROOT_INVOKE_ERROR = 0xFFFF9111,
    CC_ERROR_AUDIT_FAIL            = 0xFFFF9112,
    CC_ERROR_UNEXPECTED,			   /*Undefine value*/
    CC_ERROR_INVALID_HANDLE,			   /*Invalid sdk or engine handler*/
    CC_ERROR_NO_FIND_REGFUNC,			   /*can't find register function*/
    CC_ERROR_NO_FIND_UNREGFUNC,			   /*can't find unregister function*/
    CC_MAXIMUM_ERROR,
} cc_enclave_result_t;

typedef struct
{
        unsigned int errnum;
        const char   *errstr;
} err2str;


__attribute__((visibility("default"))) const char *cc_enclave_res2_str(cc_enclave_result_t res);

/*only check the cloud enclave_result_t type in the status.h */
#define SECGEAR_CHECK_MUTEX_RES(RES)                          \
    do{                                                            \
        int32_t _res = (RES);                                      \
        if (_res != 0) {                                           \
            print_error_goto("Mutex acquisition or release error \n");  \
        }                                                          \
    } while(0)


#define SECGEAR_CHECK_MUTEX_RES_CC(RES, CCRES)                          \
    do{                                                                 \
        int32_t _res = (RES);                                           \
        if (_res != 0) {                                                \
            CCRES = CC_FAIL;                                            \
            print_error_goto("%s Mutex acquisition or release error\n", cc_enclave_res2_str(CCRES)); \
        }                                                               \
    } while(0)


#define SECGEAR_CHECK_MUTEX_RES_UNLOCK(RES)                             \
    do{                                                                 \
        int32_t _res = (RES);                                           \
        if (_res != 0) {                                                \
            pthread_mutex_unlock(&(g_list_ops.mutex_work));             \
            print_error_goto("Mutex acquisition or release error \n");  \
        }                                                               \
    } while(0)

/* jump to done and log according to the type of res */
#define SECGEAR_CHECK_RES(RES)                                          \
    do {                                                                \
        cc_enclave_result_t _res = (RES);                               \
        if (_res != CC_SUCCESS) {                                       \
            print_error_goto("%s \n", cc_enclave_res2_str(_res));       \
        }                                                               \
    } while(0)

#define SECGEAR_CHECK_RES_UNLOCK(RES)                                   \
    do {                                                                \
        cc_enclave_result_t _res = (RES);                               \
        if (_res != CC_SUCCESS) {                                       \
            pthread_mutex_unlock(&(g_list_ops.mutex_work));             \
            print_error_goto("%s \n", cc_enclave_res2_str(_res));       \
        }                                                               \
    } while(0)

/* jump done, error log already printed in the previous error function */
#define SECGEAR_CHECK_RES_NO_LOG(RES)                     \
    do {                                                       \
        cc_enclave_result_t _res = (RES);                    \
        if(_res != CC_SUCCESS) {                               \
            goto done;                                         \
        }                                                      \
    } while(0)

#define SECGEAR_CHECK_RES_NO_LOG_UNLOCK(RES)              \
    do {                                                       \
        cc_enclave_result_t _res = (RES);                    \
        if(_res != CC_SUCCESS) {                               \
            pthread_mutex_unlock(&(g_list_ops.mutex_work));    \
            goto done;                                         \
        }                                                      \
    } while(0)

#define SECGEAR_CHECK_SIZE(SIZE)                          \
    do {                                                       \
         uint32_t _size = (SIZE);                              \
         if (_size == 0) {                                     \
              print_error_goto("The length of the input is 0\n");   \
         }                                                     \
    } while(0)

#define SECGEAR_CHECK_CHAR(CHAR)                          \
    do {                                                       \
         char *_char = (CHAR);                                 \
         if (_char == NULL) {                                  \
              print_error_goto("The input string is NULL\n");       \
         }                                                     \
    } while(0)

# ifdef  __cplusplus
}
# endif

#endif //FINAL_SECGEAR_STATUS_H
