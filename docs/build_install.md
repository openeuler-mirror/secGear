# Quick start
 
## Quick start with Intel SGX
Ensure your system have installed sgx driver, sgx sdk and sgx psw. You can install by [released version](https://01.org/intel-software-guard-extensions/downloads) or [linux-sgx](https://github.com/intel/linux-sgx) source code.
1. Clone the secGear repository:

```
git clone https://gitee.com/openeuler/secGear.git
```
2. Build secGear and examples

```
cd secGear
source /opt/intel/sgxsdk/environment && source environment
mkdir debug && cd debug && cmake ..&& make && sudo make install
```
3. Run Helloword

```
./examples/helloworld/host/secgear_helloworld
```
4. For more complex examples, see `examples` directory.

## Quick start with ARM TrustZone(Kunpeng itrustee)
Now, itrustee TeeOS is only flashed on Kunpeng(such as Kunpeng 920).</br>
Ensure your system have installed ocaml-dune, if installed ignore this step.
Otherwise install refer to [ocaml-dune](https://github.com/ocaml/dune)

1. Clone the secGear repository:
```
git clone https://gitee.com/openeuler/secGear.git
```
2. Build secGear and examples
```
cd secGear
source environment
mkdir debug && cd debug && cmake -DENCLAVE=GP ..&& make && sudo make install
```
3. Run Helloword
```
/vendor/bin/secgear_helloworld
```
4. For more complex examples, see `examples` directory.

## Build with RSIC-V Penglai
refer to [riscv_tee.md](./riscv_tee.md)

## Note
The build cmd `cmake ..` used default sdk installed path and enclave ssl installed path(if necessary).
If you install them by customize, you need input your customize path by cmake such as：

```
// the following two cmd is same
cmake .. 
cmake -DSDK_PATH=/opt/intel/sgxsdk -DSSL_PATH=/opt/intel/sgxssl ..

// input your customize path
cmake -DSDK_PATH="sdk installed path" -DSSL_PATH="enclave ssl installed path" ..
```



