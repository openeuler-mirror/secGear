#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <cstdio>
#include <cstring>
#include <cassert>

#include <array>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "common.h"
#include "error_code.h"
#include "kms_t.h"
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <rapidjson/encodings.h>
#include "secgear_dataseal.h"
#include "secgear_random.h"
#include "status.h"

///////////////////////////// 设备管理 /////////////////////////////////

using SessionKey = std::array<uint8_t, SESSION_KEY_LEN>;
static std::map <SessionKey, std::vector<uint32_t>>
        session_access_right;
const static char* const K_DEVICE_KEY_KEY_ID = "key_id";
const static char* const K_DEVICE_KEY_KEY = "key";
const static char* const K_DEVICE_KEY_VALID_PASSWORD = "valid_password";
using ByteArray = std::vector<uint8_t>;
struct DeviceKey {
    uint32_t key_id;
    ByteArray key;
    std::vector <std::string>
            valid_password;  // specify the type of elements that the set will hold
};

const static char* const K_DEVICE_KEYS = "device_keys";
static std::vector <DeviceKey> device_keys;
const static char* const K_ROOT_PASSWORD = "root_password";
static std::string root_password;

static ByteArray hexToBytes(const std::string &hexString) {
    ByteArray bytes;

    // 逐个读取每两个字符，将其转换为对应的二进制字节
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        unsigned char byte =
                static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

static std::string bytesToHex(const std::vector<unsigned char> &bytes) {
    std::string hexString;
    hexString.reserve(bytes.size() * 2);

    // 将每个字节转换为两个十六进制字符
    for (const auto &byte: bytes) {
        constexpr char hexChars[] = "0123456789abcdef";
        hexString.push_back(hexChars[(byte >> 4) & 0x0F]);
        hexString.push_back(hexChars[byte & 0x0F]);
    }

    return hexString;
}

class Waper_cc_enclave_sealed_data_t {
public:
    Waper_cc_enclave_sealed_data_t(size_t data_len, bool only_body_len = true) {
        if (only_body_len) {
            data_ = malloc(sizeof(cc_enclave_sealed_data_t) + data_len);
        } else {
            data_ = malloc(data_len);
        }
    }

    ~Waper_cc_enclave_sealed_data_t() {
        if (data_ != nullptr) {
            free(data_);
        }
    }

    Waper_cc_enclave_sealed_data_t(const Waper_cc_enclave_sealed_data_t &) =
    delete;

    Waper_cc_enclave_sealed_data_t &operator=(
            const Waper_cc_enclave_sealed_data_t &) = delete;

    Waper_cc_enclave_sealed_data_t(Waper_cc_enclave_sealed_data_t &&other) {
        data_ = other.data_;
        other.data_ = nullptr;
    }

    Waper_cc_enclave_sealed_data_t &operator=(
            Waper_cc_enclave_sealed_data_t &&other) {
        if (this != &other) {
            data_ = other.data_;
            other.data_ = nullptr;
        }
        return *this;
    }

    cc_enclave_sealed_data_t *get() {
        return (cc_enclave_sealed_data_t *) data_;
    }

private:
    void *data_;
};

// 0、1、2 号密钥为对称加密使用，3、4、5 号密钥为非对称加密使用
static int init_device_keys(const uint8_t *root_password_str, size_t root_password_len) {
    device_keys.clear();
    root_password = std::string((char *) root_password_str, root_password_len);
    for (int i = 0; i < 6; i++) {
        DeviceKey dk;
        dk.key_id = i;
        if (i < 3) {
            dk.key.resize(64);
        } else {
            dk.key.resize(32);
        }
        cc_enclave_result_t ret = CC_SUCCESS;
        ret = cc_enclave_generate_random(dk.key.data(), dk.key.size());
        if (ret != CC_SUCCESS) {
            PrintInfo(PRINT_WARNING, "cc_enclave_generate_random failed, error: %d",
                      ret);
            return Err_INTERNAL;
        }
        device_keys.emplace_back(dk);
    }
    return Err_OK;
}

static void load_device_keys_from_string(std::string s) {
    device_keys.clear();
    rapidjson::Document doc;
    doc.Parse(s.c_str());
    device_keys.resize(doc[K_DEVICE_KEYS].GetArray().Size());
    for (auto &v: doc[K_DEVICE_KEYS].GetArray()) {
        DeviceKey dk;
        dk.key_id = v[K_DEVICE_KEY_KEY_ID].GetUint();
        dk.key = hexToBytes(v[K_DEVICE_KEY_KEY].GetString());
        for (auto &p: v[K_DEVICE_KEY_VALID_PASSWORD].GetArray()) {
            dk.valid_password.emplace_back(p.GetString());
        }
        device_keys[dk.key_id] = dk;
    }
    root_password = std::string(doc[K_ROOT_PASSWORD].GetString());
}

static std::string store_device_keys_to_string() {
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
    rapidjson::Value device_keys_doc(rapidjson::kArrayType);
    for (auto &dk: device_keys) {
        rapidjson::Value dk_doc(rapidjson::kObjectType);

        dk_doc.AddMember(rapidjson::GenericValue<rapidjson::UTF8<>>::StringRefType(K_DEVICE_KEY_KEY_ID), dk.key_id, allocator);
        std::string dk_key = bytesToHex(dk.key);
        dk_doc.AddMember(rapidjson::GenericValue<rapidjson::UTF8<>>::StringRefType(K_DEVICE_KEY_KEY),
                         rapidjson::Value().SetString(
                                 dk_key.c_str(), dk_key.length(), allocator),
                         allocator);
        rapidjson::Value valid_password_doc(rapidjson::kArrayType);
        for (auto &p: dk.valid_password) {
            valid_password_doc.PushBack(
                    rapidjson::Value().SetString(p.c_str(), p.length(), allocator),
                    allocator);
        }
        dk_doc.AddMember(rapidjson::GenericValue<rapidjson::UTF8<>>::StringRefType(K_DEVICE_KEY_VALID_PASSWORD), valid_password_doc,
                         allocator);
        device_keys_doc.PushBack(dk_doc, allocator);
    }

    doc.AddMember(rapidjson::GenericValue<rapidjson::UTF8<>>::StringRefType(K_DEVICE_KEYS), device_keys_doc, allocator);
    doc.AddMember(rapidjson::GenericValue<rapidjson::UTF8<>>::StringRefType(K_ROOT_PASSWORD),
                  rapidjson::Value().SetString(
                          root_password.c_str(), root_password.length(), allocator),
                  allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer <rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    return std::string(buffer.GetString());
}

static int load_device_key_from_file(uint8_t *sealed_data, size_t len) {
    int ret_val = Err_OK;
    cc_enclave_result_t ret = CC_SUCCESS;

    if (sealed_data == nullptr || len == 0) {
        return Err_SEALED_DATA_FILE_NOT_EXIST;
    }

    Waper_cc_enclave_sealed_data_t seal_data(len, true);
    seal_data.get()->data_body_len = len;
    memcpy(seal_data.get()->data_body, sealed_data, len);

    uint32_t encrypt_add_len = cc_enclave_get_add_text_size(seal_data.get());
    uint32_t decrypt_data_len =
            cc_enclave_get_encrypted_text_size(seal_data.get());

    std::vector <uint8_t> decrypted_seal_data(decrypt_data_len);
    std::vector <uint8_t> demac_data(encrypt_add_len);

    ret = cc_enclave_unseal_data(seal_data.get(), decrypted_seal_data.data(),
                                 &decrypt_data_len, demac_data.data(),
                                 &encrypt_add_len);
    if (ret != CC_SUCCESS) {
        PrintInfo(PRINT_WARNING, "cc_enclave_unseal_data failed, error %d",
                  ret);
        return Err_INTERNAL;
    }
    load_device_keys_from_string(
            std::string((char *) decrypted_seal_data.data(), decrypt_data_len));

    return ret_val;
}

static int get_sealed_data_len(size_t *len) {
    int ret_val = Err_OK;

    std::string device_keys_str = store_device_keys_to_string();

    uint32_t seal_data_len =
            cc_enclave_get_sealed_data_size(0, device_keys_str.size());
    *len = seal_data_len;

    return ret_val;
}

static int store_device_to_file(uint8_t *sealed_data, size_t len) {
    int ret_val = Err_OK;
    cc_enclave_result_t ret = CC_SUCCESS;

    std::string device_keys_str = store_device_keys_to_string();

    uint32_t seal_data_len =
            cc_enclave_get_sealed_data_size(0, device_keys_str.size());
    Waper_cc_enclave_sealed_data_t seal_data(seal_data_len, false);

    ret = cc_enclave_seal_data((uint8_t *) device_keys_str.data(),
                               device_keys_str.size(), seal_data.get(),
                               seal_data_len, nullptr, 0);
    if (ret != CC_SUCCESS) {
        PrintInfo(PRINT_WARNING, "cc_enclave_seal_data failed, error: %d", ret);
        return Err_INTERNAL;
    }

    if (len != seal_data.get()->data_body_len) {
        PrintInfo(PRINT_WARNING,
                  "sealed_data len not match, len = %d, seal_data_len = %d",
                  len, seal_data.get()->data_body_len);
        return Err_INVALID_PARAM;
    }

    memcpy(sealed_data, seal_data.get()->data_body,
           seal_data.get()->data_body_len);
    return ret_val;
}

static const int key_type_all = 0;
static const int key_type_symmetric = 1;
static const int key_type_asymmetric = 2;

static bool valid_session_key_access(uint8_t *session_key, uint32_t key_id,
                                     int key_type) {
    SessionKey sk;
    memcpy(sk.data(), session_key, sk.size());
    auto it = session_access_right.find(sk);
    if (it == session_access_right.end()) {
        return false;
    }
    if (key_id == UINT32_MAX) {
        return true;
    }
    for (auto &id: it->second) {
        if ((key_type == key_type_symmetric && id >= 3) ||
            (key_type == key_type_asymmetric && id < 3)) {
            continue;
        }
        if (id == key_id) {
            return true;
        }
    }
    return false;
}

static int get_key_access(uint8_t *session_key, uint32_t key_id,
                          uint8_t *pucPassword, size_t uiPwdLength) {
    int ret_val = Err_OK;

    if (valid_session_key_access(session_key, key_id, key_type_all)) {
        return Err_OK;
    }

    std::string password((char *) pucPassword, uiPwdLength);
    bool valid = false;
    for (auto &dk: device_keys) {
        if (dk.key_id == key_id) {
            for (auto &p: dk.valid_password) {
                if (p == password) {
                    valid = true;
                    break;
                }
            }
            break;
        }
    }
    if (!valid) {
        return Err_PASSWORD_NOT_MATCH;
    }

    SessionKey sk;
    memcpy(sk.data(), session_key, sk.size());
    session_access_right[sk].emplace_back(key_id);

    return ret_val;
}

int init_device(const uint8_t *root_password, size_t len) {
    int ret_val = Err_OK;

    ret_val = init_device_keys(root_password, len);
    if (ret_val != Err_OK) {
        PrintInfo(PRINT_WARNING, "init_device_keys failed, ret = %d", ret_val);
        return ret_val;
    }

    return ret_val;
}

int create_device(uint8_t *sealed_data, size_t len) {
    int ret_val = Err_OK;

    ret_val = load_device_key_from_file(sealed_data, len);
    if (ret_val != Err_OK) {
        PrintInfo(PRINT_WARNING, "load_device_key_from_file failed, ret = %d", ret_val);
        return ret_val;
    }

    return ret_val;
}

int prepare_close_device(size_t *sealed_data_len) {
    return get_sealed_data_len(sealed_data_len);
}

int close_device(uint8_t *sealed_data, size_t len) {
    int ret_val = Err_OK;

    ret_val = store_device_to_file(sealed_data, len);
    if (ret_val != Err_OK) {
        PrintInfo(PRINT_WARNING, "store_device_to_file failed, ret = %d",
                  ret_val);
        return ret_val;
    }

    return ret_val;
}

int create_private_key_access_password(uint8_t *root_password,
                                       size_t root_password_len,
                                       uint32_t key_id, uint8_t *pucPassword,
                                       size_t uiPwdLength) {
    int ret_val = Err_OK;

    std::string password((char *) pucPassword, uiPwdLength);
    for (auto &dk: device_keys) {
        if (dk.key_id == key_id) {
            for (auto &p: dk.valid_password) {
                if (p == password) {
                    return Err_PASSWORD_ALREADY_EXIST;
                }
            }
            dk.valid_password.emplace_back(password);
            return Err_OK;
        }
    }
    return Err_KEY_NOT_EXIST;
}

int create_session(uint8_t *session_key) {
    cc_enclave_result_t ret = CC_SUCCESS;
    int ret_val = Err_OK;

    SessionKey sk;
    ret = cc_enclave_generate_random(sk.data(), sk.size());
    if (ret != CC_SUCCESS) {
        PrintInfo(PRINT_WARNING, "cc_enclave_generate_random failed, error: %d",
                  ret);
        return Err_INTERNAL;
    }
    memcpy(session_key, sk.data(), sk.size());

    session_access_right[sk] = std::vector<uint32_t>();

    return ret_val;
}

int close_session(uint8_t *session_key) {
    SessionKey sk;
    memcpy(sk.data(), session_key, sk.size());
    session_access_right.erase(sk);
    return Err_OK;
}

int generate_random(uint8_t *session_key, uint8_t *random, size_t len) {
    if (!valid_session_key_access(session_key, UINT32_MAX, key_type_all)) {
        return Err_INVALID_SESSION;
    }
    cc_enclave_result_t ret = CC_SUCCESS;
    ret = cc_enclave_generate_random(random, len);
    if (ret != CC_SUCCESS) {
        PrintInfo(PRINT_WARNING, "cc_enclave_generate_random failed, error: %d",
                  ret);
        return Err_INTERNAL;
    }
    return Err_OK;
}

int get_private_key_access_right(uint8_t *session_key, uint32_t key_id,
                                 uint8_t *pucPassword, size_t uiPwdLength) {
    return get_key_access(session_key, key_id, pucPassword, uiPwdLength);
}

int release_private_key_access_right(uint8_t *session_key, uint32_t key_id) {
    SessionKey sk;
    memcpy(sk.data(), session_key, sk.size());
    auto it = session_access_right.find(sk);
    if (it == session_access_right.end()) {
        return Err_INVALID_SESSION;
    }
    for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++) {
        if (*it2 == key_id) {
            it->second.erase(it2);
            return Err_OK;
        }
    }
    return Err_INVALID_SESSION;
}

////////////////////////////// 对称加密 ////////////////////////////////

static const EVP_CIPHER *alg2cipher(uint32_t alg_id) {
    switch (alg_id) {
        case SGD_SM4_ECB:
            return EVP_sm4_ecb();
        case SGD_SM4_CBC:
            return EVP_sm4_cbc();
        case SGD_SM4_CFB:
            return EVP_sm4_cfb();
        case SGD_SM4_OFB:
            return EVP_sm4_ofb();
        default:
            return EVP_sm4_ecb();
    }
}

int sym_encrypt(uint8_t *session_key, uint32_t key_id, uint32_t alg_id,
                uint8_t *iv, uint8_t *data, size_t data_len, uint8_t *enc_data,
                size_t cipher_buffer_len, unsigned int *enc_data_len) {
    if (!valid_session_key_access(session_key, key_id, key_type_symmetric)) {
        return Err_INVALID_SESSION;
    }
    if (data_len % SDF_SM4_GROUP_LENGTH != 0) {
        return Err_INVALID_PARAM;
    }

    int ret_val = Err_OK;
    EVP_CIPHER_CTX *ctx;
    *enc_data_len = 0;
    int len;
    const ByteArray *key;
    for (auto &dk: device_keys) {
        if (dk.key_id == key_id) {
            key = &dk.key;
            break;
        }
    }

    /* 创建并初始化EVP加密上下文 */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        PrintInfo(PRINT_WARNING, "EVP_CIPHER_CTX_new failed");
        return Err_INTERNAL;
    }

    /* 初始化加密操作 */
    if (1 !=
        EVP_EncryptInit_ex(ctx, alg2cipher(alg_id), nullptr, key->data(), iv)) {
        PrintInfo(PRINT_WARNING, "EVP_EncryptInit_ex failed");
        return Err_INTERNAL;
    }

    /* 执行加密操作 */
    if (1 != EVP_EncryptUpdate(ctx, enc_data, &len, data, data_len)) {
        PrintInfo(PRINT_WARNING, "EVP_EncryptUpdate failed");
        return Err_INTERNAL;
    }
    *enc_data_len += len;

    /* 结束加密操作 */
    if (1 != EVP_EncryptFinal_ex(ctx, enc_data + *enc_data_len, &len)) {
        PrintInfo(PRINT_WARNING, "EVP_EncryptFinal_ex failed");
        return Err_INTERNAL;
    }
    *enc_data_len += len;

    /* 清除并释放EVP加密上下文 */
    EVP_CIPHER_CTX_free(ctx);
    return Err_OK;
}

int sym_decrypt(uint8_t *session_key, uint32_t key_id, uint32_t alg_id,
                uint8_t *iv, uint8_t *enc_data, size_t enc_data_len,
                uint8_t *data, unsigned int *data_len) {
    if (!valid_session_key_access(session_key, key_id, key_type_symmetric)) {
        return Err_INVALID_SESSION;
    }
    if (enc_data_len % SDF_SM4_GROUP_LENGTH != 0) {
        return Err_INVALID_PARAM;
    }

    int ret_val = Err_OK;
    EVP_CIPHER_CTX *ctx;
    *data_len = 0;
    int len;

    const ByteArray *key;
    for (auto &dk: device_keys) {
        if (dk.key_id == key_id) {
            key = &dk.key;
            break;
        }
    }

    /* 创建并初始化EVP解密上下文 */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        PrintInfo(PRINT_WARNING, "EVP_CIPHER_CTX_new failed");
        return Err_INTERNAL;
    }

    /* 初始化解密操作 */
    if (1 !=
        EVP_DecryptInit_ex(ctx, alg2cipher(alg_id), nullptr, key->data(), iv)) {
        PrintInfo(PRINT_WARNING, "EVP_DecryptInit_ex failed");
        return Err_INTERNAL;
    }

    /* 执行解密操作 */
    if (1 != EVP_DecryptUpdate(ctx, data, &len, enc_data, enc_data_len)) {
        PrintInfo(PRINT_WARNING, "EVP_DecryptUpdate failed");
        return Err_INTERNAL;
    }
    *data_len += len;

    /* 结束解密操作 */
    if (1 != EVP_DecryptFinal_ex(ctx, data + *data_len, &len)) {
        PrintInfo(PRINT_WARNING, "EVP_DecryptFinal_ex failed");
        return Err_INTERNAL;
    }
    *data_len += len;

    /* 清除并释放EVP解密上下文 */
    EVP_CIPHER_CTX_free(ctx);

    return Err_OK;
}

////////////////////////////// 非对称加密 ////////////////////////////////
static int sm2_create_key_pair(ByteArray &private_key, ByteArray &public_key) {
    int ret_val = Err_INTERNAL;
    BN_CTX *ctx = nullptr;
    BIGNUM *bn_d = nullptr, *bn_x = nullptr, *bn_y = nullptr;
    const BIGNUM *bn_order;
    EC_GROUP *group = nullptr;
    EC_POINT *ec_pt = nullptr;
    unsigned char pub_key_x[32], pub_key_y[32];

    if (!(ctx = BN_CTX_secure_new())) {
        goto clean_up;
    }
    BN_CTX_start(ctx);
    bn_d = BN_CTX_get(ctx);
    bn_x = BN_CTX_get(ctx);
    bn_y = BN_CTX_get(ctx);
    if (!(bn_y)) {
        goto clean_up;
    }

    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2))) {
        goto clean_up;
    }
    if (!(bn_order = EC_GROUP_get0_order(group))) {
        goto clean_up;
    }
    if (!(ec_pt = EC_POINT_new(group))) {
        goto clean_up;
    }

    do {
        if (!(BN_rand_range(bn_d, bn_order))) {
            goto clean_up;
        }
    } while (BN_is_zero(bn_d));

    if (!(EC_POINT_mul(group, ec_pt, bn_d, nullptr, nullptr, ctx))) {
        goto clean_up;
    }
    if (!(EC_POINT_get_affine_coordinates_GFp(group, ec_pt, bn_x, bn_y, ctx))) {
        goto clean_up;
    }

    private_key.resize(32);
    if (BN_bn2binpad(bn_d, private_key.data(), private_key.size()) != 32) {
        goto clean_up;
    }
    if (BN_bn2binpad(bn_x, pub_key_x, sizeof(pub_key_x)) != sizeof(pub_key_x)) {
        goto clean_up;
    }
    if (BN_bn2binpad(bn_y, pub_key_y, sizeof(pub_key_y)) != sizeof(pub_key_y)) {
        goto clean_up;
    }

    public_key.resize(32 + 32);
    memcpy((public_key.data()), pub_key_x, sizeof(pub_key_x));
    memcpy((public_key.data() + 32), pub_key_y, sizeof(pub_key_y));
    ret_val = Err_OK;

    clean_up:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (group) {
        EC_GROUP_free(group);
    }
    if (ec_pt) {
        EC_POINT_free(ec_pt);
    }
    return ret_val;
}

int sm2_generate_public_key(const ByteArray &private_key,
                            ByteArray &public_key) {
    int ret_val = Err_INTERNAL;
    BN_CTX *ctx = nullptr;
    BIGNUM *bn_d = nullptr, *bn_x = nullptr, *bn_y = nullptr;
    const BIGNUM *bn_order;
    EC_GROUP *group = nullptr;
    EC_POINT *ec_pt = nullptr;
    unsigned char pub_key_x[32], pub_key_y[32];

    if (!(ctx = BN_CTX_secure_new())) {
        goto clean_up;
    }
    BN_CTX_start(ctx);
    bn_d = BN_CTX_get(ctx);
    bn_x = BN_CTX_get(ctx);
    bn_y = BN_CTX_get(ctx);
    if (!(bn_y)) {
        goto clean_up;
    }

    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2))) {
        goto clean_up;
    }
    if (!(bn_order = EC_GROUP_get0_order(group))) {
        goto clean_up;
    }
    if (!(ec_pt = EC_POINT_new(group))) {
        goto clean_up;
    }

    if (!BN_bin2bn(private_key.data(), 32, bn_d)) {
        goto clean_up;
    }

    if (!(EC_POINT_mul(group, ec_pt, bn_d, nullptr, nullptr, ctx))) {
        goto clean_up;
    }
    if (!(EC_POINT_get_affine_coordinates_GFp(group, ec_pt, bn_x, bn_y, ctx))) {
        goto clean_up;
    }

    if (BN_bn2binpad(bn_x, pub_key_x, sizeof(pub_key_x)) != sizeof(pub_key_x)) {
        goto clean_up;
    }
    if (BN_bn2binpad(bn_y, pub_key_y, sizeof(pub_key_y)) != sizeof(pub_key_y)) {
        goto clean_up;
    }

    public_key.resize(32 + 32);
    memcpy((public_key.data()), pub_key_x, sizeof(pub_key_x));
    memcpy((public_key.data() + 32), pub_key_y, sizeof(pub_key_y));
    ret_val = Err_OK;

    clean_up:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (group) {
        EC_GROUP_free(group);
    }
    if (ec_pt) {
        EC_POINT_free(ec_pt);
    }
    return ret_val;
}

static int sm2_encrypt(const unsigned char *message, const int message_len,
                       const unsigned char *pub_key, uint8_t *cipher_x,
                       uint8_t *cipher_y, uint8_t *cipher_M,
                       uint8_t *cipher_L) {
    int ret_val = Err_INTERNAL;
    unsigned char pub_key_x[32], pub_key_y[32], c1_x[32], c1_y[32], x2[32],
            y2[32];
    unsigned char x2_y2[64];
    unsigned char *t = nullptr;
    BN_CTX *ctx = nullptr;
    BIGNUM *bn_k = nullptr, *bn_c1_x = nullptr, *bn_c1_y = nullptr;
    BIGNUM *bn_pub_key_x = nullptr, *bn_pub_key_y = nullptr;
    BIGNUM *bn_x2 = nullptr, *bn_y2 = nullptr;
    const BIGNUM *bn_order, *bn_cofactor;
    EC_GROUP *group = nullptr;
    const EC_POINT *generator;
    EC_POINT *pub_key_pt = nullptr, *c1_pt = nullptr, *s_pt = nullptr, *ec_pt = nullptr;
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx = nullptr;
    int i, flag;

    memcpy(pub_key_x, (pub_key), sizeof(pub_key_x));
    memcpy(pub_key_y, (pub_key + sizeof(pub_key_x)), sizeof(pub_key_y));
    if (!(t = (unsigned char *) malloc(message_len))) {
        goto clean_up;
    }
    if (!(ctx = BN_CTX_new())) {
        goto clean_up;
    }
    BN_CTX_start(ctx);
    bn_k = BN_CTX_get(ctx);
    bn_c1_x = BN_CTX_get(ctx);
    bn_c1_y = BN_CTX_get(ctx);
    bn_pub_key_x = BN_CTX_get(ctx);
    bn_pub_key_y = BN_CTX_get(ctx);
    bn_x2 = BN_CTX_get(ctx);
    bn_y2 = BN_CTX_get(ctx);
    if (!(bn_y2)) {
        goto clean_up;
    }
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2))) {
        goto clean_up;
    }

    if (!(pub_key_pt = EC_POINT_new(group))) {
        goto clean_up;
    }
    if (!(c1_pt = EC_POINT_new(group))) {
        goto clean_up;
    }
    if (!(s_pt = EC_POINT_new(group))) {
        goto clean_up;
    }
    if (!(ec_pt = EC_POINT_new(group))) {
        goto clean_up;
    }

    if (!(md_ctx = EVP_MD_CTX_new())) {
        goto clean_up;
    }

    if (!(BN_bin2bn(pub_key_x, sizeof(pub_key_x), bn_pub_key_x))) {
        goto clean_up;
    }
    if (!(BN_bin2bn(pub_key_y, sizeof(pub_key_y), bn_pub_key_y))) {
        goto clean_up;
    }

    if (!(bn_order = EC_GROUP_get0_order(group))) {
        goto clean_up;
    }
    if (!(bn_cofactor = EC_GROUP_get0_cofactor(group))) {
        goto clean_up;
    }
    if (!(generator = EC_GROUP_get0_generator(group))) {
        goto clean_up;
    }

    if (!(EC_POINT_set_affine_coordinates_GFp(group, pub_key_pt, bn_pub_key_x,
                                              bn_pub_key_y, ctx))) {
        goto clean_up;
    }

    /* Compute EC point s = [h]Pubkey, h is the cofactor.
       If s is at infinity, the function returns and reports an error. */
    if (!(EC_POINT_mul(group, s_pt, nullptr, pub_key_pt, bn_cofactor, ctx))) {
        goto clean_up;
    }
    if (EC_POINT_is_at_infinity(group, s_pt)) {
        goto clean_up;
    }
    md = EVP_sm3();

    do {
        if (!(BN_rand_range(bn_k, bn_order))) {
            goto clean_up;
        }
        if (BN_is_zero(bn_k)) {
            continue;
        }
        if (!(EC_POINT_mul(group, c1_pt, bn_k, nullptr, nullptr, ctx))) {
            goto clean_up;
        }
        if (!(EC_POINT_mul(group, ec_pt, nullptr, pub_key_pt, bn_k, ctx))) {
            goto clean_up;
        }
        if (!(EC_POINT_get_affine_coordinates_GFp(group, ec_pt, bn_x2, bn_y2,
                                                  ctx))) {
            goto clean_up;
        }
        if (BN_bn2binpad(bn_x2, x2, sizeof(x2)) != sizeof(x2)) {
            goto clean_up;
        }
        if (BN_bn2binpad(bn_y2, y2, sizeof(y2)) != sizeof(y2)) {
            goto clean_up;
        }
        memcpy(x2_y2, x2, sizeof(x2));
        memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));

        if (!(ECDH_KDF_X9_62(t, message_len, x2_y2, sizeof(x2_y2), nullptr, 0,
                             md))) {
            goto clean_up;
        }

        /* If each component of t is zero, the random number k
           should be re-generated. */
        flag = 1;
        for (i = 0; i < message_len; i++) {
            if (t[i] != 0) {
                flag = 0;
                break;
            }
        }
    } while (flag);

    if (!(EC_POINT_get_affine_coordinates_GFp(group, c1_pt, bn_c1_x, bn_c1_y,
                                              ctx))) {
        goto clean_up;
    }

    if (BN_bn2binpad(bn_c1_x, c1_x, sizeof(c1_x)) != sizeof(c1_x)) {
        goto clean_up;
    }
    if (BN_bn2binpad(bn_c1_y, c1_y, sizeof(c1_y)) != sizeof(c1_y)) {
        goto clean_up;
    }
    memcpy((cipher_x), c1_x, sizeof(c1_x));
    memcpy((cipher_y), c1_y, sizeof(c1_y));

    EVP_DigestInit_ex(md_ctx, md, nullptr);
    EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
    EVP_DigestUpdate(md_ctx, message, message_len);
    EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
    EVP_DigestFinal_ex(md_ctx, cipher_M, nullptr);

    for (i = 0; i < message_len; i++) {
        cipher_L[i] = message[i] ^ t[i];
    }
    ret_val = Err_OK;

    clean_up:
    if (t) {
        free(t);
    }
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (group) {
        EC_GROUP_free(group);
    }

    if (pub_key_pt) {
        EC_POINT_free(pub_key_pt);
    }
    if (c1_pt) {
        EC_POINT_free(c1_pt);
    }
    if (s_pt) {
        EC_POINT_free(s_pt);
    }
    if (ec_pt) {
        EC_POINT_free(ec_pt);
    }
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }

    return ret_val;
}

int sm2_decrypt(const unsigned char *cipher_x, const unsigned char *cipher_y,
                const unsigned char *cipher_M, const unsigned char *cipher_L,
                const int cipher_L_len, const unsigned char *pri_key,
                uint8_t *plain_data, unsigned int *plain_data_len) {
    int ret_val = Err_INTERNAL;
    unsigned char c1_x[32], c1_y[32], x2[32], y2[32];
    unsigned char x2_y2[64], digest[32];
    unsigned char *t = nullptr, *M = nullptr;
    BN_CTX *ctx = nullptr;
    BIGNUM *bn_d = nullptr, *bn_c1_x = nullptr, *bn_c1_y = nullptr;
    BIGNUM *bn_x2 = nullptr, *bn_y2 = nullptr;
    const BIGNUM *bn_cofactor;
    EC_GROUP *group = nullptr;
    EC_POINT *c1_pt = nullptr, *s_pt = nullptr, *ec_pt = nullptr;
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx = nullptr;
    int message_len, i, flag;

    message_len = cipher_L_len;
    memcpy(c1_x, (cipher_x), sizeof(c1_x));
    memcpy(c1_y, (cipher_y), sizeof(c1_y));

    if (!(ctx = BN_CTX_new())) {
        PrintInfo(PRINT_WARNING, "BN_CTX_new failed");
        goto clean_up;
    }
    BN_CTX_start(ctx);
    bn_d = BN_CTX_get(ctx);
    bn_c1_x = BN_CTX_get(ctx);
    bn_c1_y = BN_CTX_get(ctx);
    bn_x2 = BN_CTX_get(ctx);
    bn_y2 = BN_CTX_get(ctx);
    if (!(bn_y2)) {
        PrintInfo(PRINT_WARNING, "BN_CTX_get bn_y2 failed");
        goto clean_up;
    }
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2))) {
        PrintInfo(PRINT_WARNING, "EC_GROUP_new_by_curve_name failed");
        goto clean_up;
    }

    if (!(c1_pt = EC_POINT_new(group))) {
        PrintInfo(PRINT_WARNING, "EC_POINT_new c1_pt failed");
        goto clean_up;
    }
    if (!(s_pt = EC_POINT_new(group))) {
        PrintInfo(PRINT_WARNING, "EC_POINT_new s_pt failed");
        goto clean_up;
    }
    if (!(ec_pt = EC_POINT_new(group))) {
        PrintInfo(PRINT_WARNING, "EC_POINT_new ec_pt failed");
        goto clean_up;
    }

    if (!(md_ctx = EVP_MD_CTX_new())) {
        PrintInfo(PRINT_WARNING, "EVP_MD_CTX_new failed");
        goto clean_up;
    }

    if (!(BN_bin2bn(pri_key, 32, bn_d))) {
        PrintInfo(PRINT_WARNING, "BN_bin2bn pri_key failed");
        goto clean_up;
    }
    if (!(BN_bin2bn(c1_x, sizeof(c1_x), bn_c1_x))) {
        PrintInfo(PRINT_WARNING, "BN_bin2bn c1_x failed");
        goto clean_up;
    }
    if (!(BN_bin2bn(c1_y, sizeof(c1_y), bn_c1_y))) {
        PrintInfo(PRINT_WARNING, "BN_bin2bn c1_y failed");
        goto clean_up;
    }

    if (!(EC_POINT_set_affine_coordinates_GFp(group, c1_pt, bn_c1_x, bn_c1_y,
                                              ctx))) {
        PrintInfo(PRINT_WARNING,
                  "EC_POINT_set_affine_coordinates_GFp c1_pt failed");
        goto clean_up;
    }
    if (EC_POINT_is_on_curve(group, c1_pt, ctx) != 1) {
        PrintInfo(PRINT_WARNING, "EC_POINT_is_on_curve c1_pt failed");
        goto clean_up;
    }

    if (!(bn_cofactor = EC_GROUP_get0_cofactor(group))) {
        PrintInfo(PRINT_WARNING, "EC_GROUP_get0_cofactor failed");
        goto clean_up;
    }
    if (!(EC_POINT_mul(group, s_pt, nullptr, c1_pt, bn_cofactor, ctx))) {
        PrintInfo(PRINT_WARNING, "EC_POINT_mul s_pt failed");
        goto clean_up;
    }
    if (EC_POINT_is_at_infinity(group, s_pt)) {
        PrintInfo(PRINT_WARNING, "EC_POINT_is_at_infinity s_pt failed");
        goto clean_up;
    }

    if (!(EC_POINT_mul(group, ec_pt, nullptr, c1_pt, bn_d, ctx))) {
        PrintInfo(PRINT_WARNING, "EC_POINT_mul ec_pt failed");
        goto clean_up;
    }
    if (!(EC_POINT_get_affine_coordinates_GFp(group, ec_pt, bn_x2, bn_y2,
                                              ctx))) {
        PrintInfo(PRINT_WARNING,
                  "EC_POINT_get_affine_coordinates_GFp ec_pt failed");
        goto clean_up;
    }
    if (BN_bn2binpad(bn_x2, x2, sizeof(x2)) != sizeof(x2)) {
        PrintInfo(PRINT_WARNING, "BN_bn2binpad bn_x2 failed");
        goto clean_up;
    }
    if (BN_bn2binpad(bn_y2, y2, sizeof(y2)) != sizeof(y2)) {
        PrintInfo(PRINT_WARNING, "BN_bn2binpad bn_y2 failed");
        goto clean_up;
    }
    memcpy(x2_y2, x2, sizeof(x2));
    memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));
    md = EVP_sm3();

    if (!(t = (unsigned char *) malloc(message_len))) {
        PrintInfo(PRINT_WARNING, "malloc t failed");
        goto clean_up;
    }


    if (!(ECDH_KDF_X9_62(t, message_len, x2_y2, sizeof(x2_y2), nullptr, 0, md))) {
        PrintInfo(PRINT_WARNING, "ECDH_KDF_X9_62 failed");
        goto clean_up;
    }

    /* If each component of t is zero, the function
    returns and reports an error. */
    flag = 1;
    for (i = 0; i < message_len; i++) {
        if (t[i] != 0) {
            flag = 0;
            break;
        }
    }
    if (flag) {
        PrintInfo(PRINT_WARNING, "t is zero");
        goto clean_up;
    }

    if (!(M = (unsigned char *) malloc(message_len))) {
        PrintInfo(PRINT_WARNING, "malloc M failed");
        goto clean_up;
    }
    for (i = 0; i < message_len; i++) {
        M[i] = cipher_L[i] ^ t[i];
    }

    EVP_DigestInit_ex(md_ctx, md, nullptr);
    EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
    EVP_DigestUpdate(md_ctx, M, message_len);
    EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
    EVP_DigestFinal_ex(md_ctx, digest, nullptr);

    if (memcmp(digest, cipher_M, sizeof(digest))) {
        ret_val = Err_SIGNATURE_NOT_MATCH;
        goto clean_up;
    }
    memcpy(plain_data, M, message_len);
    *plain_data_len = static_cast<unsigned int>(message_len);
    ret_val = Err_OK;

    clean_up:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (group) {
        EC_GROUP_free(group);
    }

    if (c1_pt) {
        EC_POINT_free(c1_pt);
    }
    if (s_pt) {
        EC_POINT_free(s_pt);
    }
    if (ec_pt) {
        EC_POINT_free(ec_pt);
    }

    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }

    if (t) {
        free(t);
    }
    if (M) {
        free(M);
    }

    return ret_val;
}

int sm2_sign(const unsigned char *message, const int message_len,
             const unsigned char *pri_key, uint8_t *sign_r, uint8_t *sign_s) {
    int ret_val = Err_INTERNAL;
    unsigned char digest[32];

    EC_KEY *ec_key = nullptr;
    BIGNUM *bn_private_key = nullptr;
    ECDSA_SIG *ecdsa_sig = nullptr;
    const BIGNUM *r_bn = nullptr, *s_bn = nullptr;
    unsigned char szSign[256] = {0};
    unsigned int len_sig = 0;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);

    bn_private_key = BN_bin2bn(pri_key, 32, nullptr);
    if (bn_private_key == nullptr) {
        goto clean_up;
    }

    if (EC_KEY_set_private_key(ec_key, bn_private_key) != 1) {
        goto clean_up;
    }

    if (1 != ECDSA_sign(0, message, message_len, szSign, &len_sig, ec_key)) {
        goto clean_up;
    } else {
        const unsigned char *p = szSign;

        ecdsa_sig = d2i_ECDSA_SIG(nullptr, &p, len_sig);
        r_bn = ECDSA_SIG_get0_r(ecdsa_sig);
        s_bn = ECDSA_SIG_get0_s(ecdsa_sig);

        if (BN_bn2bin(r_bn, sign_r) != 32) {
            goto clean_up;
        }
        if (BN_bn2bin(s_bn, sign_s) != 32) {
            goto clean_up;
        }
        ret_val = Err_OK;
    }

    clean_up:
    if (ec_key != nullptr) {
        EC_KEY_free(ec_key);
    }
    if (bn_private_key != nullptr) {
        BN_free(bn_private_key);
    }
    if (ecdsa_sig != nullptr) {
        ECDSA_SIG_free(ecdsa_sig);
    }
    return ret_val;
}

int sm2_verify(const unsigned char *message, const int message_len,
               const unsigned char *pub_key, const unsigned char *sign_r,
               const unsigned char *sign_s) {
    int ret_val = Err_INTERNAL;
    EC_KEY *ec_key = nullptr;
    BIGNUM *bn_x = nullptr, *bn_y = nullptr;
    EC_POINT *ec_point = nullptr;
    BIGNUM *r_bn = nullptr, *s_bn = nullptr;
    unsigned char *der = nullptr;
    ECDSA_SIG *ecdsa_sig = nullptr;

    unsigned char raw_x[32];
    unsigned char raw_y[32];
    unsigned char der_sig[128];
    int der_size = 0;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    memcpy(raw_x, (pub_key), sizeof(raw_x));
    memcpy(raw_y, (pub_key + sizeof(raw_x)), sizeof(raw_y));
    size_t raw_x_size = sizeof(raw_x);
    size_t raw_y_size = sizeof(raw_y);

    bn_x = BN_bin2bn(raw_x, raw_x_size, nullptr);
    bn_y = BN_bin2bn(raw_y, raw_y_size, nullptr);
    if (bn_x == nullptr || bn_y == nullptr) {
        goto clean_up;
    }

    ec_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
    if (ec_point == nullptr ||
        EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ec_key), ec_point,
                                            bn_x, bn_y, nullptr) != 1) {
        goto clean_up;
    }

    if (EC_KEY_set_public_key(ec_key, ec_point) != 1) {
        goto clean_up;
    }

    r_bn = BN_bin2bn(sign_r, 32, nullptr);
    s_bn = BN_bin2bn(sign_s, 32, nullptr);

    ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig || !ECDSA_SIG_set0(ecdsa_sig, r_bn, s_bn)) {
        goto clean_up;
    }

    der_size = i2d_ECDSA_SIG(ecdsa_sig, &der);

    if (1 != ECDSA_verify(0, message, message_len, der, der_size, ec_key)) {
        ret_val = Err_SIGNATURE_NOT_MATCH;
        goto clean_up;
    } else {
        ret_val = 0;
    }

    clean_up:
    if (ec_key != nullptr) {
        EC_KEY_free(ec_key);
    }
    if (bn_x != nullptr) {
        BN_free(bn_x);
    }
    if (bn_y != nullptr) {
        BN_free(bn_y);
    }
    if (ec_point != nullptr) {
        EC_POINT_free(ec_point);
    }
    if (ecdsa_sig != nullptr) {
        ECDSA_SIG_free(ecdsa_sig);
    }
    if (der != nullptr) {
        OPENSSL_free(der);
    }
    if (r_bn != nullptr) {
        BN_free(r_bn);
    }
    if (s_bn != nullptr) {
        BN_free(s_bn);
    }

    return ret_val;
}

int ECC_ExportEncPublicKey(uint8_t *session_key, unsigned int uiKeyIndex,
                           uint8_t *pucPublicKey) {
    if (!valid_session_key_access(session_key, uiKeyIndex,
                                  key_type_asymmetric)) {
        return Err_INVALID_SESSION;
    }

    int ret_val = Err_OK;
    cc_enclave_result_t ret = CC_SUCCESS;

    const ByteArray *key;
    for (auto &dk: device_keys) {
        if (dk.key_id == uiKeyIndex) {
            key = &dk.key;
            break;
        }
    }
    ByteArray pub_key;
    ret_val = sm2_generate_public_key(*key, pub_key);
    if (ret_val != Err_OK) {
        PrintInfo(PRINT_WARNING, "sm2_generate_public_key failed, ret = %d",
                  ret_val);
        return ret_val;
    }
    memcpy(pucPublicKey, pub_key.data(), pub_key.size());

    return ret_val;
}

int ECC_ExternalPublicKeyEncrypt(uint8_t *session_key, unsigned int uiAlgID,
                                 uint8_t *pucPublicKey, unsigned char *pucData,
                                 unsigned int uiDataLength, uint8_t *cipher_x,
                                 uint8_t *cipher_y, uint8_t *cipher_M,
                                 uint8_t *cipher_L) {
    if (!valid_session_key_access(session_key, UINT32_MAX, key_type_all)) {
        return Err_INVALID_SESSION;
    }
    if (uiAlgID != SGD_SM2) {
        return Err_INVALID_PARAM;
    }

    int ret_val = Err_OK;
    cc_enclave_result_t ret = CC_SUCCESS;

    ByteArray pub_key;
    pub_key.resize(32 + 32);
    memcpy(pub_key.data(), pucPublicKey, 32);
    memcpy((pub_key.data() + 32), (pucPublicKey + 32), 32);

    ret_val = sm2_encrypt(pucData, uiDataLength, pub_key.data(), cipher_x,
                          cipher_y, cipher_M, cipher_L);
    if (ret_val != Err_OK) {
        PrintInfo(PRINT_WARNING, "sm2_encrypt failed, ret = %d", ret_val);
        return ret_val;
    }

    return ret_val;
}

int ECC_InternalPrivateKeyDecrypt(uint8_t *session_key, unsigned int uiKeyIndex,
                                  unsigned int uiAlgID, uint8_t *cipher_x,
                                  uint8_t *cipher_y, uint8_t *cipher_M,
                                  uint8_t *cipher_L, unsigned int cipher_L_len,
                                  unsigned char *pucDataOutput, unsigned int pucDataBufferLength,
                                  unsigned int *pucDataOutputLength) {
    if (!valid_session_key_access(session_key, uiKeyIndex,
                                  key_type_asymmetric)) {
        return Err_INVALID_SESSION;
    }
    if (uiAlgID != SGD_SM2) {
        return Err_INVALID_PARAM;
    }

    int ret_val = Err_OK;
    cc_enclave_result_t ret = CC_SUCCESS;

    const ByteArray *key;
    for (auto &dk: device_keys) {
        if (dk.key_id == uiKeyIndex) {
            key = &dk.key;
            break;
        }
    }

    ret_val = sm2_decrypt(cipher_x, cipher_y, cipher_M, cipher_L, cipher_L_len,
                          key->data(), pucDataOutput, pucDataOutputLength);
    if (ret_val != Err_OK) {
        PrintInfo(PRINT_WARNING, "sm2_decrypt failed, ret = %d", ret_val);
        return ret_val;
    }

    return ret_val;
}

int ECC_InternalPrivateKeySign(uint8_t *session_key, unsigned int uiKeyIndex,
                               unsigned int uiAlgID, uint8_t *pucData,
                               unsigned int uiDataLength, uint8_t *sign_r,
                               uint8_t *sign_s) {
    if (!valid_session_key_access(session_key, uiKeyIndex,
                                  key_type_asymmetric)) {
        return Err_INVALID_SESSION;
    }
    if (uiAlgID != SGD_SM2) {
        return Err_INVALID_PARAM;
    }

    int ret_val = Err_OK;
    cc_enclave_result_t ret = CC_SUCCESS;

    const ByteArray *key;
    for (auto &dk: device_keys) {
        if (dk.key_id == uiKeyIndex) {
            key = &dk.key;
            break;
        }
    }

    ret_val = sm2_sign(pucData, uiDataLength, key->data(), sign_r, sign_s);
    if (ret_val != Err_OK) {
        PrintInfo(PRINT_WARNING, "sm2_sign failed, ret = %d", ret_val);
        return ret_val;
    }

    return ret_val;
}

int ECC_ExternalPublicKeyVerify(uint8_t *session_key, unsigned int uiAlgID,
                                uint8_t *pucPublicKey, uint8_t *pucData,
                                unsigned int uiDataLength, uint8_t *sign_r,
                                uint8_t *sign_s) {
    if (!valid_session_key_access(session_key, UINT32_MAX, key_type_all)) {
        return Err_INVALID_SESSION;
    }
    if (uiAlgID != SGD_SM2) {
        return Err_INVALID_PARAM;
    }

    int ret_val = Err_OK;
    cc_enclave_result_t ret = CC_SUCCESS;

    ByteArray pub_key;
    pub_key.resize(32 + 32);
    memcpy(pub_key.data(), pucPublicKey, 32);
    memcpy((pub_key.data() + 32), (pucPublicKey + 32), 32);

    ret_val = sm2_verify(pucData, uiDataLength, pub_key.data(), sign_r, sign_s);
    if (ret_val != Err_OK) {
        PrintInfo(PRINT_WARNING, "sm2_verify failed, ret = %d", ret_val);
        return ret_val;
    }

    return ret_val;
}
////////////////////////////// 杂凑 ////////////////////////////////

static const EVP_MD *alg2md(uint32_t alg_id) {
    switch (alg_id) {
        case SGD_SM3:
            return EVP_sm3();
        case SGD_SM3_SM2:
            return EVP_sm3();
        case SGD_SHA1:
            return EVP_sha1();
        default:
            return EVP_sm3();
    }
}

static std::map<SessionKey, EVP_MD_CTX *> session_hash_ctx;

int hash_init(uint8_t *session_key, uint32_t alg_id) {
    if (!valid_session_key_access(session_key, UINT32_MAX, key_type_all)) {
        return Err_INVALID_SESSION;
    }

    EVP_MD_CTX *ctx;

    /* 创建并初始化EVP哈希上下文 */
    if (!(ctx = EVP_MD_CTX_new())) {
        PrintInfo(PRINT_WARNING, "EVP_MD_CTX_new failed");
        return Err_INTERNAL;
    }

    /* 设置算法 */
    if (1 != EVP_DigestInit_ex(ctx, EVP_sm3(), nullptr)) {
        PrintInfo(PRINT_WARNING, "EVP_DigestInit_ex failed");
        return Err_INTERNAL;
    }

    SessionKey sk;
    memcpy(sk.data(), session_key, sk.size());
    session_hash_ctx[sk] = ctx;

    return Err_OK;
}

int hash_update(uint8_t *session_key, uint8_t *data, size_t data_len) {
    if (!valid_session_key_access(session_key, UINT32_MAX, key_type_all)) {
        return Err_INVALID_SESSION;
    }

    SessionKey sk;
    memcpy(sk.data(), session_key, sk.size());
    auto it = session_hash_ctx.find(sk);
    if (it == session_hash_ctx.end()) {
        return Err_INVALID_SESSION;
    }

    EVP_MD_CTX *ctx = it->second;

    /* 执行哈希操作 */
    if (1 != EVP_DigestUpdate(ctx, data, data_len)) {
        PrintInfo(PRINT_WARNING, "EVP_DigestUpdate failed");
        return Err_INTERNAL;
    }

    return Err_OK;
}

int hash_final(uint8_t *session_key, uint8_t *hash, size_t buffer_len,
               unsigned int *hash_len) {
    if (!valid_session_key_access(session_key, UINT32_MAX, key_type_all)) {
        return Err_INVALID_SESSION;
    }

    SessionKey sk;
    memcpy(sk.data(), session_key, sk.size());
    auto it = session_hash_ctx.find(sk);
    if (it == session_hash_ctx.end()) {
        return Err_INVALID_SESSION;
    }

    EVP_MD_CTX *ctx = it->second;

    /* 获取哈希结果 */
    if (1 != EVP_DigestFinal_ex(ctx, hash, hash_len)) {
        PrintInfo(PRINT_WARNING, "EVP_DigestFinal_ex failed");
        return Err_INTERNAL;
    }

    /* 清除并释放EVP哈希上下文 */
    EVP_MD_CTX_free(ctx);
    return Err_OK;
}
