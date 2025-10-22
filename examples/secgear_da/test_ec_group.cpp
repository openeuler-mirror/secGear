#include <iostream>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <cstring>
int main()
{
    OpenSSL_add_all_algorithms();
    int ret;
    EC_GROUP* ec_group = nullptr;
    EC_KEY* ec_key = nullptr;
    // 根据NID获取内置椭圆曲线
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    ret = EC_KEY_set_group(ec_key)
    
    if (!ec_key) {
        std::cerr << "Error: Failed to create ECC key pair.\n";
        return 1;
    }
    
    if (!EC_KEY_generate_key(ec_key)) {
        std::cerr << "Error: Failed to generate ECC key pair.\n";
        EC_KEY_free(ec_key);
        return 1;
    }
    
    const BIGNUM *priv_key = EC_KEY_get0_private_key(ec_key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
        
    PEM_write_bio_ECPrivateKey(pri, ec_key, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, ec_key);
          
    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    char *out_pri = new char[1024];
    char *out_pub = new char[1024];

    BIO_read(pri, out_pri, pri_len);
    BIO_read(pub, out_pub, pub_len);

    std::cout << out_pri << std::endl;
    std::cout << out_pub << std::endl;
    
    std::cout << "ECC key pair generated and saved as private_key.pem and public_key.pem.\n";
    EC_KEY_free(ec_key);
    EVP_cleanup();
    return 0;
}