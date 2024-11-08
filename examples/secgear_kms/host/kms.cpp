#include <cerrno>
#include <linux/limits.h>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>
#include <string>

#include "common.h"
#include "enclave.h"
#include "error_code.h"
#include "kms_u.h"
#include "secgear_kms.h"

struct SDF_DevicdHandle {
    cc_enclave_t context;
};
struct SDF_SessionHandle {
    SDF_DevicdHandle *device_handle;
    uint8_t session_key[SESSION_KEY_LEN];
};

static const char *ISSUER_NAME = "SecGear";
static const char *DEVICE_NAME = "KMS";
static const char *DEVICE_SERIAL = "000000000000000";
static const unsigned int DEVICE_VERSION = 1;
static const unsigned int STANDARD_VERSION = 1;
static const unsigned int ASYM_ALG_ABILITY = 0;
static const unsigned int SYM_ALG_ABILITY = 0;
static const unsigned int HASH_ALG_ABILITY = 0;
static const unsigned int BUFFER_SIZE = 1;

static std::string storage_path = DEFAULT_STORAGE_FILE_PATH;

////////////////////////////////// 设备管理 /////////////////////////////////

int create_storage_file() {
    FILE *fp = fopen(storage_path.c_str(), "w");
    if (fp == nullptr) {
        perror("Cannot create file");
        return Err_STORAGE;
    }
    fclose(fp);
    return Err_OK;
}

int get_store_file_length(size_t *len) {
    *len = 0;
    struct stat st;
    if (stat(storage_path.c_str(), &st) == -1) {
        if (errno != ENOENT) {
            perror("Cannot get file size");
            return Err_STORAGE;
        } else {
            return Err_SEALED_DATA_FILE_NOT_EXIST;
        }
    }
    *len = st.st_size;
    return Err_OK;
}

int load_store_file(uint8_t *data, size_t len) {
    FILE *fp = fopen(storage_path.c_str(), "rb");
    if (fp == nullptr) {
        if (errno == ENOENT) {
            return Err_SEALED_DATA_FILE_NOT_EXIST;
        }
        perror("Cannot open file");
        return Err_STORAGE;
    }
    while (len > 0) {
        size_t read_len = fread(data, 1, len, fp);
        if (read_len == 0) {
            if (feof(fp)) {
                fprintf(stderr, "Error: unexpected end of file\n");
            } else if (ferror(fp)) {
                perror("Error reading");
            }
            fclose(fp);
            return Err_STORAGE;
        } else if (read_len < len) {
            fprintf(stderr, "Error: read %ld bytes, expected %ld\n", read_len,
                    len);
            fclose(fp);
            return Err_STORAGE;
        }
        len -= read_len;
        data += read_len;
    }
    fclose(fp);
    return Err_OK;
}

int save_store_file(uint8_t *data, size_t len) {
    FILE *fp = fopen(storage_path.c_str(), "wb");
    if (fp == nullptr) {
        if (errno == ENOENT) {
            return Err_SEALED_DATA_FILE_NOT_EXIST;
        }
        perror("Cannot open file");
        return Err_STORAGE;
    }
    while (len > 0) {
        size_t write_len = fwrite(data, 1, len, fp);
        if (write_len == 0) {
            if (feof(fp)) {
                fprintf(stderr, "Error: unexpected end of file\n");
            } else if (ferror(fp)) {
                perror("Error writing");
            }
            fclose(fp);
            return Err_STORAGE;
        } else if (write_len < len) {
            fprintf(stderr, "Error: write %ld bytes, expected %ld\n", write_len,
                    len);
            fclose(fp);
            return Err_STORAGE;
        }
        len -= write_len;
        data += write_len;
    }
    fclose(fp);
    return Err_OK;
}

int SDF_InitDevice(const char *dev_path, const uint8_t *root_password, unsigned int root_password_len) {
    storage_path = dev_path;

    int retval = 0;
    const char *path = PATH;
    cc_enclave_t context;
    memset(&context, 0, sizeof(cc_enclave_t));
    cc_enclave_result_t res = CC_FAIL;

    char real_p[PATH_MAX];
    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == nullptr) {
        if (getcwd(real_p, sizeof(real_p)) == nullptr) {
            fprintf(stderr, "Cannot find enclave.signed.so\n");
            return Err_BAD_ENCLAVE_PATH;
        }
        if (PATH_MAX - strlen(real_p) <= strlen("/enclave.signed.so")) {
            fprintf(stderr, "Failed to strcat enclave.sign.so path\n");
            return Err_BAD_ENCLAVE_PATH;
        }
        (void) strcat(real_p, "/enclave.signed.so");
    }

    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG,
                            nullptr, 0, &context);
    if (res != CC_SUCCESS) {
        fprintf(stderr, "create enclave error: %s\n", cc_enclave_res2_str(res));
        return Err_CREATE_ENCLAVE;
    }

    size_t sealed_keys_len = 0;
    retval = get_store_file_length(&sealed_keys_len);
    if (retval != Err_SEALED_DATA_FILE_NOT_EXIST) {
        fprintf(stderr, "storage file %s already used by another device\n", storage_path.c_str());
        return Err_PATH_ALREAD_USED;
    }

    create_storage_file();

    res = init_device(&context, &retval, root_password, root_password_len);
    if (res != CC_SUCCESS || retval != Err_OK) {
        fprintf(stderr, "Init Device ECall error: %s\n",
                cc_enclave_res2_str(res));
        return retval == Err_OK ? Err_CREATE_DEVICE : retval;
    }

    // close enclave
    res = prepare_close_device(&context, &retval, &sealed_keys_len);
    if (res != CC_SUCCESS || retval != Err_OK) {
        fprintf(stderr, "Prepare Close Device ECall error: %s\n",
                cc_enclave_res2_str(res));
        return retval == Err_OK ? Err_CLOSE_DEVICE : retval;
    }

    std::vector <uint8_t> sealed_keys(sealed_keys_len);

    res = close_device(&context, &retval, sealed_keys.data(),
                       sealed_keys_len);
    if (res != CC_SUCCESS || retval != Err_OK) {
        fprintf(stderr, "Close Device ECall error: %s\n",
                cc_enclave_res2_str(res));
        return retval == Err_OK ? Err_CLOSE_DEVICE : retval;
    }

    retval = save_store_file(sealed_keys.data(), sealed_keys_len);
    if (retval != Err_OK) {
        fprintf(stderr, "save_store_file error: %d\n", retval);
        return retval;
    }

    res = cc_enclave_destroy(&context);
    if (res != CC_SUCCESS) {
        fprintf(stderr, "destroy enclave error: %s\n",
                cc_enclave_res2_str(res));
        return Err_DESTORY_ENCLAVE;
    }
    fprintf(stdout, "init device success\n");
    return Err_OK;
}

int SDF_OpenDevice(void **phDeviceHandle) {
    *phDeviceHandle = nullptr;

    int retval = 0;
    const char *path = PATH;
    cc_enclave_t context;
    memset(&context, 0, sizeof(cc_enclave_t));
    cc_enclave_result_t res = CC_FAIL;

    char real_p[PATH_MAX];
    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == nullptr) {
        if (getcwd(real_p, sizeof(real_p)) == nullptr) {
            fprintf(stderr, "Cannot find enclave.signed.so\n");
            return Err_BAD_ENCLAVE_PATH;
        }
        if (PATH_MAX - strlen(real_p) <= strlen("/enclave.signed.so")) {
            fprintf(stderr, "Failed to strcat enclave.sign.so path\n");
            return Err_BAD_ENCLAVE_PATH;
        }
        (void) strcat(real_p, "/enclave.signed.so");
    }

    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG,
                            nullptr, 0, &context);
    if (res != CC_SUCCESS) {
        fprintf(stderr, "create enclave error: %s\n", cc_enclave_res2_str(res));
        return Err_CREATE_ENCLAVE;
    }
    fprintf(stdout, "create enclave success\n");

    size_t sealed_keys_len = 0;
    retval = get_store_file_length(&sealed_keys_len);
    if (retval != Err_OK) {
        fprintf(stderr, "get_store_file_length error: %d\n", retval);
        return retval;
    }

    std::vector <uint8_t> sealed_keys(sealed_keys_len);
    retval = load_store_file(sealed_keys.data(), sealed_keys_len);
    if (retval != Err_OK) {
        fprintf(stderr, "load_store_file error: %d\n", retval);
        return retval;
    }
    fprintf(stdout, "sealed_keys_len = %ld\n", sealed_keys_len);
    res = create_device(&context, &retval, sealed_keys.data(), sealed_keys_len);
    if (res != CC_SUCCESS || retval != Err_OK) {
        fprintf(stderr, "Create Device ECall error: %s\n",
                cc_enclave_res2_str(res));
        return retval == Err_OK ? Err_CREATE_DEVICE : retval;
    }

    SDF_DevicdHandle *handle = new SDF_DevicdHandle;
    handle->context = context;
    *phDeviceHandle = handle;
    return Err_OK;
}

int SDF_OpenDevice_ext(void **phDeviceHandle, const char *dev_path) {
    storage_path = dev_path;
    return SDF_OpenDevice(phDeviceHandle);
}

int SDF_CloseDevice(void *hDeviceHandle) {
    if (hDeviceHandle == nullptr) {
        return Err_INVALID_DEVICE;
    }
    SDF_DevicdHandle *handle =
            reinterpret_cast<SDF_DevicdHandle *>(hDeviceHandle);
    cc_enclave_result_t res;
    int retval = 0;

    size_t sealed_keys_len = 0;
    res = prepare_close_device(&handle->context, &retval, &sealed_keys_len);
    if (res != CC_SUCCESS || retval != Err_OK) {
        fprintf(stderr, "Prepare Close Device ECall error: %s\n",
                cc_enclave_res2_str(res));
        return retval == Err_OK ? Err_CLOSE_DEVICE : retval;
    }

    std::vector <uint8_t> sealed_keys(sealed_keys_len);

    res = close_device(&handle->context, &retval, sealed_keys.data(),
                       sealed_keys_len);
    if (res != CC_SUCCESS || retval != Err_OK) {
        fprintf(stderr, "Close Device ECall error: %s\n",
                cc_enclave_res2_str(res));
        return retval == Err_OK ? Err_CLOSE_DEVICE : retval;
    }

    retval = save_store_file(sealed_keys.data(), sealed_keys_len);
    if (retval != Err_OK) {
        fprintf(stderr, "save_store_file error: %d\n", retval);
        return retval;
    }

    res = cc_enclave_destroy(&handle->context);
    if (res != CC_SUCCESS) {
        fprintf(stderr, "destroy enclave error: %s\n",
                cc_enclave_res2_str(res));
        delete handle;
        return Err_DESTORY_ENCLAVE;
    }
    fprintf(stdout, "destroy enclave success\n");
    delete handle;
    return Err_OK;
}

int SDF_CreatePrivateKeyAccessPassword(void *hDeviceHandle,
                                       unsigned char *root_password,
                                       unsigned int root_password_len,
                                       unsigned int key_id,
                                       unsigned char *pucPassword,
                                       unsigned int uiPwdLength) {
    if (root_password == nullptr || pucPassword == nullptr) {
        return Err_INVALID_PARAM;
    }
    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;
    SDF_DevicdHandle *deviceHandle =
            reinterpret_cast<SDF_DevicdHandle *>(hDeviceHandle);

    res = create_private_key_access_password(&deviceHandle->context, &ret_val,
                                             root_password, root_password_len,
                                             key_id, pucPassword, uiPwdLength);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "Create Private Key Access Password ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_CREATE_PRIVATE_KEY_ACCESS_PASSWORD
                                 : ret_val;
    }
    return Err_OK;
}

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) {
    if (hDeviceHandle == nullptr) {
        return Err_INVALID_DEVICE;
    }
    *phSessionHandle = nullptr;
    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;
    uint8_t session_key[SESSION_KEY_LEN];
    SDF_DevicdHandle *deviceHandle =
            reinterpret_cast<SDF_DevicdHandle *>(hDeviceHandle);

    res = create_session(&deviceHandle->context, &ret_val, session_key);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "Create Session ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_CREATE_SESSION : ret_val;
    }

    SDF_SessionHandle *handle = new SDF_SessionHandle;
    handle->device_handle = deviceHandle;
    memcpy(handle->session_key, session_key, SESSION_KEY_LEN);
    *phSessionHandle = handle;

    return Err_OK;
}

int SDF_CloseSession(void *hSessionHandle) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }
    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;
    uint8_t session_key[SESSION_KEY_LEN];

    memcpy(session_key, handle->session_key, SESSION_KEY_LEN);
    res = close_session(&handle->device_handle->context, &ret_val, session_key);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "Close Session ECall error: %s\n",
                cc_enclave_res2_str(res));
        delete handle;
        return ret_val == Err_OK ? Err_CLOSE_SESSION : ret_val;
    }

    delete handle;
    return Err_OK;
}

int SDF_GetDeviceInfo(void *hSessionHandle, DeviceInfo *pstDeviceInfo) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }
    memset(pstDeviceInfo, 0, sizeof(DeviceInfo));
    strcpy((char *) pstDeviceInfo->IssuerName, ISSUER_NAME);
    strcpy((char *) pstDeviceInfo->DeviceName, DEVICE_NAME);
    strcpy((char *) pstDeviceInfo->DeviceSerial, DEVICE_SERIAL);
    pstDeviceInfo->DeviceVersion = DEVICE_VERSION;
    pstDeviceInfo->StandardVersion = STANDARD_VERSION;
    pstDeviceInfo->AsymAlgAbility = ASYM_ALG_ABILITY;
    pstDeviceInfo->SymAlgAbility = SYM_ALG_ABILITY;
    pstDeviceInfo->HashAlgAbility = HASH_ALG_ABILITY;
    pstDeviceInfo->BufferSize = BUFFER_SIZE;
    return Err_OK;
}

int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
                       unsigned char *pucRandom) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }
    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = generate_random(&handle->device_handle->context, &ret_val,
                          handle->session_key, pucRandom, uiLength);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "Generate Random ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_GENERATE_RANDOM : ret_val;
    }

    return Err_OK;
}

int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex,
                                 unsigned char *pucPassword,
                                 unsigned int uiPwdLength) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }
    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = get_private_key_access_right(&handle->device_handle->context,
                                       &ret_val, handle->session_key,
                                       uiKeyIndex, pucPassword, uiPwdLength);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "Get Private Key Access Right ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_GET_PRIVATE_KEY_ACCESS_RIGHT : ret_val;
    }

    return Err_OK;
}

int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,
                                     unsigned int uiKeyIndex) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }
    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = release_private_key_access_right(&handle->device_handle->context,
                                           &ret_val, handle->session_key,
                                           uiKeyIndex);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "Release Private Key Access Right ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_RELEASE_PRIVATE_KEY_ACCESS_RIGHT
                                 : ret_val;
    }

    return Err_OK;
}

//////////////////////////// 对称加密 ////////////////////////////

int SDF_Encrypt(void *hSessionHandle, unsigned int uiKeyIndex,
                unsigned int uiAlgID, unsigned char *pucIV,
                unsigned char *pucData, unsigned int uiDataLength,
                unsigned char *pucEncData, unsigned int *puiEncDataLength) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucData == nullptr || pucEncData == nullptr ||
        puiEncDataLength == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    if (uiDataLength % SDF_SM4_GROUP_LENGTH != 0) {
        fprintf(stderr, "SDF_Encrypt: uiDataLength must be multiple of %d\n",
                SDF_SM4_GROUP_LENGTH);
        return Err_INVALID_PARAM;
    }

    res = sym_encrypt(&handle->device_handle->context, &ret_val,
                      handle->session_key, uiKeyIndex, uiAlgID, pucIV, pucData,
                      uiDataLength, pucEncData,
                      uiDataLength + SDF_SM4_IV_LENGTH, puiEncDataLength);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "sym_encrypt ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_SYM_ENCRYPT : ret_val;
    }
    return Err_OK;
}

int SDF_Decrypt(void *hSessionHandle, unsigned int uiKeyIndex,
                unsigned int uiAlgID, unsigned char *pucIV,
                unsigned char *pucEncData, unsigned int uiEncDataLength,
                unsigned char *pucData, unsigned int *puiDataLength) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucEncData == nullptr || pucData == nullptr ||
        puiDataLength == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = sym_decrypt(&handle->device_handle->context, &ret_val,
                      handle->session_key, uiKeyIndex, uiAlgID, pucIV,
                      pucEncData, uiEncDataLength, pucData, puiDataLength);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "sym_decrypt ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_SYM_DECRYPT : ret_val;
    }
    return Err_OK;
}

int SDF_CalculateMAC(void *hSessionHandle, unsigned int uiKeyIndex,
                     unsigned int uiAlgID, unsigned char *pucIV,
                     unsigned char *pucData, unsigned int uiDataLength,
                     unsigned char *pucMAC, unsigned int *puiMACLength) {
    return Err_NOT_SUPPORT;
}

//////////////////////////// 杂凑 ////////////////////////////
int SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID,
                 ECCrefPublicKey *pucPublicKey, unsigned char *pucID,
                 unsigned int uiIDLength) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = hash_init(&handle->device_handle->context, &ret_val,
                    handle->session_key, uiAlgID);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "hash_init ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_HASH_INIT : ret_val;
    }
    return Err_OK;
}

int SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData,
                   unsigned int uiDataLength) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucData == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = hash_update(&handle->device_handle->context, &ret_val,
                      handle->session_key, pucData, uiDataLength);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "hash_update ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_HASH_UPDATE : ret_val;
    }
    return Err_OK;
}

int SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash,
                  unsigned int *puiHashLength) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucHash == nullptr || puiHashLength == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = hash_final(&handle->device_handle->context, &ret_val,
                     handle->session_key, pucHash, SGD_MAX_MD_SIZE,
                     puiHashLength);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "hash_final ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_HASH_FINAL : ret_val;
    }
    return Err_OK;
}

//////////////////////////// 非对称加密 ////////////////////////////
// 内部私钥 ECC 签名
int SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                         unsigned int uiAlgID, unsigned char *pucRefData,
                         unsigned int uiRefDataLength,
                         ECCSignature *pucSignature) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucRefData == nullptr || pucSignature == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = ECC_InternalPrivateKeySign(&handle->device_handle->context, &ret_val,
                                     handle->session_key, uiKeyIndex, uiAlgID,
                                     pucRefData, uiRefDataLength,
                                     pucSignature->r, pucSignature->s);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "ecc_sign ECall error: %s\n", cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_SIGNERR : ret_val;
    }
    return Err_OK;
}

// 外部公钥 ECC 验签
int SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID,
                           ECCrefPublicKey *pucPublicKey,
                           unsigned char *pucDataInput,
                           unsigned int uiInputLength,
                           ECCSignature *pucSignature) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucPublicKey == nullptr || pucDataInput == nullptr ||
        pucSignature == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    unsigned char pubKey[64];
    memccpy(pubKey, pucPublicKey->x, 0, 32);
    memccpy(pubKey + 32, pucPublicKey->y, 0, 32);
    res = ECC_ExternalPublicKeyVerify(
            &handle->device_handle->context, &ret_val, handle->session_key, uiAlgID,
            pubKey, pucDataInput, uiInputLength, pucSignature->r, pucSignature->s);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "ecc_verify ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_VERIFYERR : ret_val;
    }
    return Err_OK;
}

// 内部私钥 ECC 解密
int SDF_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                            unsigned int uiAlgID, unsigned char *pucData,
                            unsigned int *uiDataLength, ECCCipher *pucEncData) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucData == nullptr || pucEncData == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    res = ECC_InternalPrivateKeyDecrypt(
            &handle->device_handle->context, &ret_val, handle->session_key,
            uiKeyIndex, uiAlgID, pucEncData->x, pucEncData->y, pucEncData->M,
            pucEncData->C, pucEncData->L, pucData, *uiDataLength, uiDataLength);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "ecc_decrypt ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_ECC_DECRYPT : ret_val;
    }
    return Err_OK;
}

// 外部公钥 ECC 加密
int SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID,
                            ECCrefPublicKey *pucPublicKey,
                            unsigned char *pucData, unsigned int uiDataLength,
                            ECCCipher *pucEncData) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucPublicKey == nullptr || pucData == nullptr ||
        pucEncData == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    unsigned char pubKey[64];
    memccpy(pubKey, pucPublicKey->x, 0, 32);
    memccpy(pubKey + 32, pucPublicKey->y, 0, 32);
    res = ECC_ExternalPublicKeyEncrypt(
            &handle->device_handle->context, &ret_val, handle->session_key, uiAlgID,
            pubKey, pucData, uiDataLength, pucEncData->x, pucEncData->y,
            pucEncData->M, pucEncData->C);
    pucEncData->L = uiDataLength;
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "ecc_encrypt ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_ECC_ENCRYPT : ret_val;
    }
    return Err_OK;
}

// 导出 ECC 公钥
int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex,
                               ECCrefPublicKey *pucPublicKey) {
    if (hSessionHandle == nullptr) {
        return Err_INVALID_SESSION;
    }

    if (pucPublicKey == nullptr) {
        return Err_INVALID_PARAM;
    }

    cc_enclave_result_t res = CC_FAIL;
    int ret_val = 0;

    SDF_SessionHandle *handle =
            reinterpret_cast<SDF_SessionHandle *>(hSessionHandle);
    unsigned char pubKey[64];
    res = ECC_ExportEncPublicKey(&handle->device_handle->context, &ret_val,
                                 handle->session_key, uiKeyIndex, pubKey);
    if (res != CC_SUCCESS || ret_val != Err_OK) {
        fprintf(stderr, "ecc_export_public_key ECall error: %s\n",
                cc_enclave_res2_str(res));
        return ret_val == Err_OK ? Err_ECC_EXPORT_PUBLIC_KEY : ret_val;
    }
    memccpy(pucPublicKey->x, pubKey, 0, 32);
    memccpy(pucPublicKey->y, pubKey + 32, 0, 32);
    return Err_OK;
}
