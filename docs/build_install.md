Install secGear
 
openEuler x86

1. Refer to https://01.org/intel-software-guard-extensions/downloads download and install the 2.11 
   sgx  driver, sgx psw, sgx sdk. In the directory of sgx sdk, source environment(for use sgx-sign)
   
2. Refer to https://github.com/ocaml/opam/releases download and install the  opam-2.0.7-x86_64-linux.
   Run "./opam-2.0.7-x86_64-linux init"
   Copy the output of "./opam-2.0.7-x86_64-linux env" to ~/.bashrc, then run "source ~/.bashrc"
   Run "./opam-2.0.7-x86_64-linux install dune"
   
3. source environment && mkdir debug && cd debug 
   && cmake -DCMAKE_BUILD_TYPE=Debug -DCC_SGX=ON -DSGXSDK="sgx_sdk path" .. &&  make && sudo make install

4. To run example tls_enclave, refer to https://gitee.com/src-openeuler/intel-sgx-ssl 
   download and install intel-sgx-ssl firstly.
   source environment && mkdir debug && cd debug && cmake -DCMAKE_BUILD_TYPE=Debug -DCC_SGX=ON -DSGXSDK="sgx_sdk path"
   && -DENCLAVE_SSL="sgxssl path" .. &&  make && sudo make install
   
openEuler arm

1. The itrustee OS is not released. Therefore, no installation description is provided.
   How to install and configure the secGear on the platform where the itrustee OS is enabled will be provided
   after the itrustee OS is released.

2. Refer to https://github.com/ocaml/opam/releases download and install the  opam-2.0.7-arm64-linux.
   Run "./opam-2.0.7-arm64-linux init"
   Copy the output of "./opam-2.0.7-arm64-linux env" to ~/.bashrc, then run "source ~/.bashrc"
   Run ./opam-2.0.7-arm64-linux install dune

3. source environment && mkdir debug && cd debug
   && cmake -DCMAKE_BUILD_TYPE=Debug -DCC_GP=ON -DiTrusteeSDK="iTrustee sdk path" .. && make && sudo make install


