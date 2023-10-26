#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <catch2/catch_test_macros.hpp>

#include <random>
#include <string>

#include "secgear_kms.h"

const static char * ROOT_PASSWORD = "123123";
const static char * USER_PASSWORD = "123456";

class KMSSessionTestsFixture {
protected:
  void *device_handle = nullptr;
  void *session_handle = nullptr;

protected:
  KMSSessionTestsFixture() {
    std::string storage_path = random_storage_path();
    REQUIRE(SDF_InitDevice(storage_path.c_str(), (uint8_t *)ROOT_PASSWORD,
                           strlen(ROOT_PASSWORD)) == 0);
    REQUIRE(SDF_OpenDevice_ext(&device_handle, storage_path.c_str()) == 0);
    REQUIRE(device_handle != nullptr);

    for (int i = 0; i < 6; i++) {
      REQUIRE(SDF_CreatePrivateKeyAccessPassword(
                  device_handle, const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(ROOT_PASSWORD)),
                  strlen(ROOT_PASSWORD), i, const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(USER_PASSWORD)),
                  strlen(USER_PASSWORD)) == 0);
    }

    REQUIRE(SDF_OpenSession(device_handle, &session_handle) == 0);
    REQUIRE(session_handle != nullptr);
  }

  virtual ~KMSSessionTestsFixture() {
    REQUIRE(SDF_CloseSession(session_handle) == 0);
    REQUIRE(SDF_CloseDevice(device_handle) == 0);
  }

private:
  std::string random_storage_path() {
    std::random_device rd;
    std::mt19937_64 generator(rd());
    std::uniform_int_distribution<uint64_t> distribution(
        0, std::numeric_limits<uint64_t>::max());
    uint64_t random_number = distribution(generator);

    return "/tmp/secgear_kms_storage_" + std::to_string(random_number);
  }
};

TEST_CASE_METHOD(KMSSessionTestsFixture, "Get Device Info", "[Device]") {
  DeviceInfo device_info;
  REQUIRE(SDF_GetDeviceInfo(session_handle, &device_info) == 0);
}

TEST_CASE_METHOD(KMSSessionTestsFixture, "Generate Random", "[Device]") {
  unsigned char random[32];
  REQUIRE(SDF_GenerateRandom(session_handle, 32, random) == 0);

  // print random
  for (int i = 0; i < 32; i++) {
    printf("%02x", random[i]);
  }
}

TEST_CASE_METHOD(KMSSessionTestsFixture, "Get Private Key Access", "[Device]") {
  REQUIRE(SDF_GetPrivateKeyAccessRight(session_handle, 0,
                                       const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(USER_PASSWORD)),
                                       strlen(USER_PASSWORD)) == 0);
  REQUIRE(SDF_ReleasePrivateKeyAccessRight(session_handle, 0) == 0);
}

/**
 * Key 0 是对称密钥
 */
class KMSSessionWithKey0TestsFixture : public KMSSessionTestsFixture {
protected:
  KMSSessionWithKey0TestsFixture() : KMSSessionTestsFixture() {
    REQUIRE(SDF_GetPrivateKeyAccessRight(session_handle, 0,
                                         const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(USER_PASSWORD)),
                                         strlen(USER_PASSWORD)) == 0);
  }

  ~KMSSessionWithKey0TestsFixture() override {
    REQUIRE(SDF_ReleasePrivateKeyAccessRight(session_handle, 0) == 0);
  }

  unsigned int key_id = 0;
};

/**
 * Key 3 是非对称私钥
 */
class KMSSessionWithKey3TestsFixture : public KMSSessionTestsFixture {
protected:
  KMSSessionWithKey3TestsFixture() : KMSSessionTestsFixture() {
    REQUIRE(SDF_GetPrivateKeyAccessRight(session_handle, 3,
                                         const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(USER_PASSWORD)),
                                         strlen(USER_PASSWORD)) == 0);
  }

  ~KMSSessionWithKey3TestsFixture() override {
    REQUIRE(SDF_ReleasePrivateKeyAccessRight(session_handle, 3) == 0);
  }

  unsigned int key_id = 3;
};

TEST_CASE_METHOD(KMSSessionWithKey0TestsFixture,
                 "Symmetric key encryption and decryption", "[Symmetric]") {
  unsigned int uiAlgID = SGD_SM4_ECB;
  unsigned char pucIV[SDF_SM4_IV_LENGTH] = {0};
  unsigned char pucData[SDF_SM4_GROUP_LENGTH * 8] = "Hello, world!";
  unsigned int uiDataLength = sizeof(pucData);
  unsigned char pucEncData[SDF_SM4_GROUP_LENGTH * 8 + SDF_SM4_IV_LENGTH] = {0};
  unsigned int uiEncDataLength = 0;

  REQUIRE(SDF_Encrypt(session_handle, 0, uiAlgID, pucIV, pucData, uiDataLength,
                      pucEncData, &uiEncDataLength) == 0);

  unsigned char pucDecData[SDF_SM4_GROUP_LENGTH * 8] = {0};
  unsigned int uiDecDataLength = 0;
  REQUIRE(SDF_Decrypt(session_handle, 0, uiAlgID, pucIV, pucEncData,
                      uiEncDataLength, pucDecData, &uiDecDataLength) == 0);
  REQUIRE(uiDecDataLength == uiDataLength);
  REQUIRE(memcmp(pucData, pucDecData, uiDataLength) == 0);
}

TEST_CASE_METHOD(KMSSessionWithKey3TestsFixture, "Calculate Hash", "[Hash]") {
  unsigned int uiAlgID = SGD_SM3;
  unsigned char pucData[] = "Hello, world!";
  unsigned int uiDataLength = sizeof(pucData) - 1;
  unsigned char pucHash[SGD_MAX_MD_SIZE] = {0};
  unsigned int uiHashLength = 0;

  REQUIRE(SDF_HashInit(session_handle, uiAlgID, nullptr, nullptr, 0) == 0);
  REQUIRE(SDF_HashUpdate(session_handle, pucData, uiDataLength) == 0);
  REQUIRE(SDF_HashFinal(session_handle, pucHash, &uiHashLength) == 0);

  // calc hash with openssl
  unsigned char pucHash2[SGD_MAX_MD_SIZE] = {0};
  unsigned int uiHashLength2 = 0;
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  REQUIRE(md_ctx != nullptr);
  REQUIRE(EVP_DigestInit_ex(md_ctx, EVP_sm3(), nullptr) == 1);
  REQUIRE(EVP_DigestUpdate(md_ctx, pucData, uiDataLength) == 1);
  REQUIRE(EVP_DigestFinal_ex(md_ctx, pucHash2, &uiHashLength2) == 1);

  REQUIRE(uiHashLength2 == uiHashLength);
  REQUIRE(memcmp(pucHash, pucHash2, uiHashLength) == 0);
}

TEST_CASE_METHOD(KMSSessionWithKey3TestsFixture, "Export Public Key",
                 "[Asymmetric]") {
  ECCrefPublicKey public_key;
  REQUIRE(SDF_ExportEncPublicKey_ECC(session_handle, key_id, &public_key) == 0);
}

TEST_CASE_METHOD(KMSSessionWithKey3TestsFixture, "Sign and Verify",
                 "[Asymmetric]") {
  ECCrefPublicKey public_key;
  REQUIRE(SDF_ExportEncPublicKey_ECC(session_handle, key_id, &public_key) == 0);

  unsigned char data[] = "Hello, world!";
  unsigned int data_len = sizeof(data);

  ECCSignature signature;
  REQUIRE(SDF_InternalSign_ECC(session_handle, key_id, SGD_SM2, data, data_len,
                               &signature) == 0);

  REQUIRE(SDF_ExternalVerify_ECC(session_handle, SGD_SM2, &public_key, data,
                                 data_len, &signature) == 0);
}

TEST_CASE_METHOD(KMSSessionWithKey3TestsFixture, "Encrypt and Decrypt",
                 "[Asymmetric]") {
  ECCrefPublicKey public_key;
  REQUIRE(SDF_ExportEncPublicKey_ECC(session_handle, key_id, &public_key) == 0);

  unsigned char data[] = "Hello, world!";
  unsigned int data_len = sizeof(data);

  ECCCipher *cipher = (ECCCipher *)malloc(sizeof(ECCCipher) + data_len);
  REQUIRE(cipher != nullptr);
  REQUIRE(SDF_ExternalEncrypt_ECC(session_handle, SGD_SM2, &public_key, data,
                                  data_len, cipher) == 0);
  REQUIRE(cipher->L == data_len);

  unsigned char data2[1024] = {0};
  unsigned int data_len2 = 1024;
  REQUIRE(SDF_InternalDecrypt_ECC(session_handle, key_id, SGD_SM2, data2,
                                  &data_len2, cipher) == 0);
  REQUIRE(data_len2 == data_len);
  REQUIRE(memcmp(data, data2, data_len) == 0);

  free(cipher);
}
