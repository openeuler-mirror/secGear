Install secGear
 
openEuler x86

1. Refer to https://01.org/intel-software-guard-extensions/downloads download and install the 2.11 
   sgx  driver, sgx psw, sgx sdx. In the directory of sgx sdk, source environment(for use sgx-sign)
   
2. Refer to https://github.com/ocaml/opam/releases download and install the  opam-2.0.7-x86_64-linux.
   Run "./opam-2.0.7-x86_64-linux init"
   Copy the output of "./opam-2.0.7-x86_64-linux env" to ~/.bashrc, then run "source ~/.bashrc"
   Run "./opam-2.0.7-x86_64-linux install dune"
   
3. source environment && mkdir debug && cd debug 
   && cmake -DCMAKE_BUILD_TYPE=Debug -DCC_SGX=ON -DSGXSDK="sgx_sdk path" .. &&  make && sudo make install

   
openEuler arm

1. Refer to xxx  download and install the iTrustee SDK

2. Refer to https://github.com/ocaml/opam/releases download and install the  opam-2.0.7-arm64-linux.
   Run "./opam-2.0.7-arm64-linux init"
   Copy the output of "./opam-2.0.7-arm64-linux env" to ~/.bashrc, then run "source ~/.bashrc"
   Run ./opam-2.0.7-arm64-linux install dune

3. source environment && mkdir debug && cd debug
   && cmake -DCMAKE_BUILD_TYPE=Debug -DCC_GP=ON -DiTrusteeSDK="iTrustee sdk path" .. && make && sudo make install


