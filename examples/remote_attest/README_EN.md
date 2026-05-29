# Quick Start

## Intel SGX

secGear does not support remote attestation on the SGX platform.

## Arm Trustzone

### Environment Setup

#### Setting Up the TEE Runtime Environment

[Setup Method](https://www.hikunpeng.com/document/detail/en/kunpengcctrustzone/fg-tz/kunpengtrustzone_04_0007.html)

#### Applying for TA Developer Certificates

In this sample, you need to apply for two developer certificates, one for the target TA and the other for the QTA (the UUID of the QTA is fixed to e08f7eca-e875-440e-9ab0-5f381136c600), and upload the obtained configuration file to the development environment. 
[Applying for a TA Developer Certificate in a Debugging Environment](https://www.hikunpeng.com/document/detail/en/kunpengcctrustzone/fg-tz/kunpengtrustzone_04_0009.html)

#### Verifying the Deployment of Third-Party Dependencies on the Server

- Downloading the code

QCA lib: itrustee_sdk/test/CA/libqca
QTA: itrustee_sdk/test/TA/qta

```shell
git clone https://gitee.com/openeuler/itrustee_sdk.git
git clone https://gitee.com/openeuler/libboundscheck.git
cp -rf libboundscheck/ itrustee_sdk/thirdparty/open_source/

```

- Modifying, compiling, and deploying libqca

```shell
vim itrustee_sdk/test/CA/libqca/src/ra_operate_api.c
// Search for **TEEC_OpenSession** and add the following content above **TEEC_OpenSession**.
context.ta_path = (uint8_t *)"/data/e08f7eca-e875-440e-9ab0-5f381136c600.sec";
cd itrustee_sdk/test/CA/libqca   # Replace the path with the actual one.
make
cp output/libqca.so /usr/lib64 && ldconfig

```

- Modifying, compiling, and deploying QTA

```shell
vim itrustee_sdk/test/TA/qta/src/tee_qta.c
// In the **TA_CreateEntryPoint** function, add the following content below the comment **/* TA auth CA */**:
// Add the CA program that is allowed to call the QTA.
ret = addcaller_ca_exec("/vendor/bin/secgear_ra_demo", "root");
if (ret != TEE_SUCCESS)
    return ret;

// Download the third-party dependency cJSON.
wget https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz
tar xvf v1.7.15.tar.gz 
mv cJSON-1.7.15/ itrustee_sdk/test/TA/qta/src/cJSON

// Configure the QTA developer certificate.
// Save the private key and configuration file corresponding to the QTA developer certificate to the following directory:
itrustee_sdk/build/signtools/signed_config/config
itrustee_sdk/build/signtools/TA_cert/private_key.pem
// Modify the fields in itrustee_sdk/test/TA/qta/manifest.txt based on the config.xml file used for applying for the QTA developer certificate.

pip3 install pycryptodomex           # Install the dependency of the iTrustee SDK TA signature tool.
cd itrustee_sdk/test/TA/qta    # Replace the path with the actual one.
make
cp e08f7eca-e875-440e-9ab0-5f381136c600.sec /data
```

#### Deploying the Third-Party Dependency Library by the Verifier

```shell
// Deploy libcjson.so.
wget https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz
tar xvf v1.7.15.tar.gz 
cd cJSON-1.7.15/
make && make install

// Deploy libteeverifier.so.
git clone https://gitee.com/openeuler/kunpengsecl.git
cd attestation/tee/tverlib/miracl
make
cd attestation/tee/tverlib/verifier
make
cp libteeverifier.so /usr/lib64/

// Install Huawei IT Product CA.pem.
// Use a Windows browser to download the file from https://download.huawei.com/dl/download.do?actionFlag=download&nid=PKI1000000040&partNo=3001&mid=SUP_PKI file using a Windows browser.
// Upload it to the secGear/examples/remote_attest/build/ directory.
// In actual application development, the certificate must be uploaded to the directory where the verify binary is executed. For example, if the verify_test file is located in the /usr/bin/ directory but you intend to run verify_test from the /home directory, the certificate must be uploaded to the /home directory.
```

### Compiling and Running the secGear Sample

```shell
// Installs the required build dependencies from the openEuler 22.03 LTS SP2 repository.
sudo yum install -y cmake ocaml-dune itrustee_sdk-devel secGear-devel

// Clone the secGear repository.
git clone https://gitee.com/openeuler/secGear.git

// Configure the target TA developer certificate.
// Modify the fields in secGear/examples/remote_attest/enclave/manifest.txt based on the config.xml file corresponding to the target TA developer certificate.   
// Modify the encryptKey, signKey, and configPath paths in the secGear/examples/remote_attest/enclaveconfig_cloud.ini file.   
// Uncomment the following lines in secGear/examples/remote_attest/enclave/CMakeLists.txt to enable signature.
    add_custom_command(TARGET ${PREFIX}
 POST_BUILD
 COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${PREFIX}.so -c ${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt -m ${CMAKE_CURRENT_SOURCE_DIR}/config_cloud.ini -o ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT})

    install(FILES ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT}
       DESTINATION /data
       PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE  WORLD_READ  WORLD_EXECUTE)

// Build example remote attest.
cd secGear/examples/remote_attest
mkdir build&& cd build && cmake -DENCLAVE=GP .. && make && sudo make install

// Configure basevalue.txt.
// Edit basevalue.txt to overwrite taid, img_hash, and mem_hash. The img_hash and mem_hash come from /opt/itrustee_sdk/build/signtools/hash_uuid.txt.

// Run the demo.
/vendor/bin/secgear_ra_demo
```
