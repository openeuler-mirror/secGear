# Getting started with the codegen

The codegen helps to define these special functions through the `edl` files and assist user to using enclave.

## The codegen

The codegen is based on the 'edger8r' tool in SGX SDK.
- For example
```
$ codegen_arm64 --trustzone test.edl 
```
**Note**: using the `codegen --help` to get more details.

## EDL format
- For SGX(x86) 
```
    enclave {
        trusted {
            public void enclave_helloworld(
                    int idata,
                    [in, size=data_in_size]unsigned char* data_in,
                    size_t data_in_size,
                    [out, size=data_out_size]unsigned char** data_out,
                    size_t data_out_size,
                    [in, out]unsigned char** data_in_out);
        };

        untrusted {
            void host_helloworld();
        };
    };
```
- For trustzone(arm)
```
    enclave {
        trusted {
            public void enclave_helloworld(
                    int idata,
                    [in, size=data_in_size]unsigned char* data_in,
                    size_t data_in_size,
                    [out, size=data_out_size]unsigned char** data_out,
                    size_t data_out_size,
                    [in, out]unsigned char** data_in_out);
        };
    };
```
**Note**: so far, we don`t support ocall for trustzone.And we also don`t support usercheck for trustzone.
