# Secure Channel Sample

This sample consists of three parts: client, server host, and server enclave. It provides two client implementations, demonstrating both single-thread and multi-thread scenarios.

## Directory Structure

```sh
├── client                     // Single-thread client
│   ├── client.c
│   └── CMakeLists.txt
├── client_with_recv_thread   // Multi-thread client: main thread and independent message receiving thread
│   ├── client.c
│   └── CMakeLists.txt
├── CMakeLists.txt
├── enclave                   // Server TA   
│   ├── CMakeLists.txt
│   ├── config_cloud.ini
│   ├── enclave.c
│   ├── Enclave.config.xml
│   ├── Enclave.lds
│   └── manifest.txt
├── host                    // Server CA
│   ├── CMakeLists.txt
│   └── server.c
├── sc_demo.edl             // API between the CA and TA
└── usr_msg.h               // Message sending hook function implemented by the user based on the service network connection and hook function prototype
```

## Quick Start

### Intel SGX

```sh
// install build require
sudo yum install -y cmake ocaml-dune linux-sgx-driver sgxsdk libsgx-launch libsgx-urts intel-sgx-ssl secGear-devel

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// build example secure channel
cd secGear/examples/secure_channel
source /opt/intel/sgxsdk/environment
mkdir debug && cd debug && cmake .. && make && sudo make install

// start server
./bin/sc_server

// start client
./bin/sc_client
```

Note: When running this sample, ensure that the OpenSSL version in the system is later than or equal to that in intel-sgx-ssl; otherwise, the sample may not run properly.

### Arm TrustZone

#### Environment Setup

See [remote_attest](https://gitee.com/houmingyong/secGear/tree/master/examples/remote_attest#%E7%8E%AF%E5%A2%83%E5%87%86%E5%A4%87).
There are two differences from the remote attestation environment setup:

1. Copy **/vendor/bin/sc_server** to the QTA source code.
2. Upload **Huawei IT Product CA.pem** to the **secGear/examples/secure_channel/build/** directory.

#### Compiling and Running the secGear Sample

```sh
// install build require depends openEuler 23.03 repo
sudo yum install -y cmake ocaml-dune itrustee_sdk-devel secGear-devel

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// Configure the TA developer certificate.
cd secGear/examples/secure_channel
// Copy the manifest.txt file corresponding to the TA developer certificate to the enclave directory of the sample.
cp -rf {manifest.txt}  enclave/
// Add the path of the TA developer certificate to the config_cloud.ini file.
vim enclave/config_cloud.ini 
Modify the encryptKey, signKey, and configPath paths.

// Enable the signing TA and uncomment the following three lines in the enclave/CMakeLists.txt file.
add_custom_command(TARGET ${PREFIX}
    POST_BUILD
    COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${PREFIX}.so -c ${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt -m ${CMAKE_CURRENT_SOURCE_DIR}/config_cloud.ini -o ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT})

// build example secure channel
cd secGear/examples/secure_channel
mkdir build && cd build && cmake -DENCLAVE=GP .. && make && sudo make install

// start server
/vendor/bin/sc_server

// config basevalue.txt
// edit basevalue.txt to overwrite taid img_hash mem_hash, the img_hash and mem_hash comes from /opt/itrustee_sdk/build/signtools/hash_uuid.txt

// start client 
/vendor/bin/sc_client
```

#### Precautions

- Network connection:
    A secure channel encapsulates only the key negotiation process and encryption and decryption APIs, but does not establish any network connection. Instead, the negotiation process reuses the network connection of the service. The client–server connection is established and maintained by the service. During secure channel initialization on both the client and server sides, a message-sending hook function and a network connection pointer are transferred. The buffer for receiving network messages at both ends needs to be large enough to accommodate the 12320-byte secure channel initialization message.
- Client initialization:
    When calling the cc_sec_chl_client_init API, the client needs to initialize the `basevalue` field of cc_sec_chl_ctx_t and pass the measurement baseline value file of the server TA. The file content is in the `taid img_hash mem_hash` format. Otherwise, remote attestation will fail during the secure channel initialization, causing a failure in secure channel negotiation. The measurement baseline value file of the server TA is automatically generated during TA compilation, named `hash_uuid.txt`.
