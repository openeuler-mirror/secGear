# Getting started with the sign_tool

The sign_tool.sh helps to sign the enclave.

## The sign_tool.sh

The sign_tool.sh uses the 'sgx_sign' tool in SGX SDK for signing the sgx enclave and the 'signtool_v3.py' for signing the trustzone enclave. When signing the trustzone enclave, it is recommended that use the absolute path to specify the file parameters, if provide a relative path, is should be a path relative to 'signtool_v3.py'.

The tool supports the following two modes:


- single-step method, it is only for the dubug mode.  

    For example:    

    `$ ./sign_tool.sh –d sign –x trustzone –i test.enclave -c manifest.txt -m config_cloud.ini –o signed.enclave `


- two-step method, it is used when the signature needs to be obtained from the signing organization or the private key is stored on another secure platform.  

    For example:  
    (1) generate the signing material.  
    `$ ./sign_tool.sh –d digest –x trustzone –i input -c manifest.txt -m config_cloud.ini –o signing.data `

    For trustzone, temporary files KeyInfo.enc, rawData.enc, and rawDataHash.bin are generated in the current directory. And for sgx, a temporary file signdata is generated in the current directory. The temporary file is required when generating the signed enclave in step 3 and is deleted after the signed enclave is generated.  

    (2) send the signing.data to the signing organization or platform and get the signature.  
    For trustzone, use rsautl command to sign the signing material.
    
	`$ openssl rsautl -sign -inkey sign_key.pem -in signing.data -out signature `
	
	For sgx, use dgst command to sign the signing material.
    
	`$ openssl dgst -sha256 -sign sign_key.pem -keyform PEM -out signature signing.data `
    
	(3) use the signature to generate the signed enclave.  
    
	`$ ./sign_tool.sh –d sign –x trustzone –i input -c manifest.txt -m config_cloud.ini –s signature –o signed.enclave `

## sign_tool.sh parameter

```
    -c <file>       basic config file.
    -d <parameter>  sign tool command, sign/digest/dump.
                    The sign command is used to generate a signed enclave.
		            The digest command is used to generate signing material.
		            The dump command is used to generate metadata for sgx signed enclave.
	-i <file>       input parameter, which is enclave to be signed for digest/sign command, and signed enclave for
	                dump command.
	-k <file>       private key required for single-step method.
	-m <file>       additional config_cloud.ini for trustzone.
	-o <file>       output parameter, the sign command outputs signed enclave, the digest command outputs signing
	                material, the dump command outputs data containing the SIGStruct metadata for the SGX signed
	                enclave, which is submitted to Intel for whitelisting.
	-p <file>       signing server public key certificate, required for sgx two-step method.
	-s <file>       the signature value required for two-step method, this parameter is empty to indicate
	                single-step method.
	-x <parameter>  enclave type, sgx or trustzone.
	-h              print help message.
```
**Note**: 
Using the `./sign_tool.sh -h` to get help information.
For trustzone, it will randomly generate a AES key and temporarily stored in the file in plaintext, please ensure security.
