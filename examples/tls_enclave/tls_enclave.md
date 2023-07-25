#Getting started with the tls_enclave example

In the scenario where a user already has a certificate and private on the host side, the tls_enclve provides an example how to protect the private key and how to estabilish a TLS connection with enclave in Linux SGX environment. 

1. Install secGear and intel-sgx-ssl(http://gitee.com/src-openEuler/intel-sgx-ssl).
2. Enter the development directory ../secGear, source environment &&  mkdir debug && cd debug
&& cmake -DCMAKE_BUILD_TYPE=Debug -DCC_SGX=on -DSGXSDK="sgx_sdk path" -DENCLAVE_SSL="sgxssl path" ..
3. To run secgear_tls, the certificate and key used by the TLS server needs to be generated, the following example generate signed certificate only for testing.
(1) generate RSA key:
    openssl genrsa -f4 -aes256 -out server.key 3072
    follow the screen instructions to enter the pass phrase for protecting private key, the pass phrase should meet certain complexity requirements.
(2) generate self-signed certificate
    openssl req -new -x509 -days 365 -key server.key -out server.pem -sha256 -subj "/C=CN/ST=GD/L=SZ/O=test/OU=test/CN=test"
4. start secgear_tls, sudo debug/bin/secgear_tls 9090 server.pem server.key &
   start tls_client, sudo debug/bin/tls_client 9090 server.pem
   follow the screen instructions to enter the pass phrase to usee the private key. 
   After exectued successfully, the private key is deleted and only the key encrypted by enclave is saved.
