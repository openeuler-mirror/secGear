# Getting started with the tls_enclave example

In the scenario where a user already has a certificate and private on the host side, the tls_enclve provides an example how to protect the private key and how to estabilish a TLS connection with enclave in Linux SGX environment. 

1. Install dependency
- Install SGX SDK by [released version](https://01.org/intel-software-guard-extensions/downloads) or [linux-sgx](https://github.com/intel/linux-sgx) source code.
- Install [intel-sgx-ssl](http://gitee.com/src-openEuler/intel-sgx-ssl).
2. Build
```
cd secGear
source /opt/intel/sgxsdk/environment && source environment
mkdir debug && cd debug && cmake .. && make && sudo make install
```

3. Generate test key and certificate </br>
The certificate and key used by the TLS server needs to be generated, the following example generate signed certificate only for testing.
```
// generate RSA key
openssl genrsa -f4 -aes256 -out server.key 3072
// follow the screen instructions to enter the pass phrase for protecting private key, the pass phrase should meet certain complexity requirements.

// generate self-signed certificate
openssl req -new -x509 -days 365 -key server.key -out server.pem -sha256 -subj "/C=CN/ST=GD/L=SZ/O=test/OU=test/CN=test"
```

4. run example
```
// start secgear_tls
sudo debug/bin/secgear_tls 9090 server.pem server.key

// start tls_client
sudo debug/bin/tls_client 9090 server.pem
// follow the screen instructions to enter the pass phrase to usee the private key.
// After exectued successfully, the private key is deleted and only the key encrypted by enclave is saved.
```
5. Note</br>
If your intel-sgx-ssl is not install by default. You need input your installed path by cmake.

```
cmake -DSSL_PATH="sdk installed path" ..
```
