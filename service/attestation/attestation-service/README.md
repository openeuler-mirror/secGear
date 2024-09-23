# Attestation Service
The Attestation Service verifies hardware TEE evidence.
The first phase aims to support Kunpeng Trustzone, virtCCA and QingTian Enclave. In the future, it will support ARM CCA, Intel TDX, Hygon CSV etc.

# Quick Start
## Start Attestation Service
```
config yum repository, find here: https://repo.openeuler.org/
run service in current host like:
./as_startup.sh
or in docker and specified interface:port:
./as_startup.sh -t docker -l 127.0.0.1:8080
```
