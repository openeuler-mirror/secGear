# Getting started with the sign_tool

The sign_tool.sh helps to sign the enclave.

## The sign_tool.sh

The sign_tool.sh uses the 'sgx_sign' tool in SGX SDK for signing the sgx enclave and the 'sign_tool.py' for signing the trustzone enclave.

The tool supports the following two modes:


- single-step method, it is only for the dubug mode.  

    For example:    

    `$ ./sign_tool.sh –d sign –x trustzone –i test.enclave -c manifest.txt –o signed.enclave `


- two-step method, it is used when the signature needs to be obtained from the signing organization or the private key is stored on another secure platform.  

    For example:  
    (1) generate the digest value.  
    `$ ./sign_tool.sh –d digest –x trustzone –i input -c manifest.txt –o digest.data `

    For trustzone, temporary files KeyInfo.enc, rawData.enc, and rawDataHash.bin are generated in the current directory. And for sgx, a temporary file signdata is generated in the current directory. The temporary file is required when generating the signed enclave in step 3 and is deleted after the signed enclave is generated.  

    (2) send the digest.data to the signing organization or platform and get the signature.  

    (3) use the signature to generate the signed enclave.  
    `$ ./sign_tool.sh –d sign –x trustzone –i input -c manifest.txt –p pub.pem –s signature –o signed.enclave `

## sign_tool.sh parameter

```
    -a <parameter>  API_LEVEL, indicates trustzone GP API version, defalut is 1.
    -c <file>       basic config file.
    -d <parameter>  sign tool command, sign/digest.
                    The sign command is used to generate a signed enclave.
                    The digest command is used to generate a digest value.
    -f <parameter>  OTRP_FLAG, indicates whether the OTRP standard protocol is supported, default is 0.
    -i <file>       enclave to be signed.
    -k <file>       private key required for single-step method, required when trustzone TA_TYPE is 2 or sgx.
    -m <file>       additional config for trustzone when TA_TYPE is 2.
    -o <file>       output parameters, the sign command outputs sigend enclave, the digest command outputs digest value.
    -p <file>       signing server public key certificate, required for two-step method.
    -s <file>       the signed digest value required for two-step method, this parameter is empty to indicate single-step method.
    -t <parameter>  trustzone TA_TYPE, default is 1.
    -x <parameter>  enclave type, sgx or trustzone.
    -h              printf help message.
```
**Note**: 
Using the `./sign_tool.sh -h` to get help information.
For trustzone, it will randomly generate a AES key and temporarily stored in the file in plaintext, please ensure security.
