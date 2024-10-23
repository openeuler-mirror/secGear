# Attestation Service
The Attestation Service verifies hardware TEE evidence.
The first phase aims to support Kunpeng Trustzone, virtCCA and QingTian Enclave. In the future, it will support ARM CCA, Intel TDX, Hygon CSV etc.

# Quick Start
## Start Attestation Service quickly
update repository source config
```
vim /etc/yum.repos.d/openEuler.repo
[everything]
name=everything
baseurl=https://repo.openeuler.org/openEuler-24.09/everything/aarch64/
enabled=1
gpgcheck=0

//run service in current host like this, initialize environment automatically
./as_startup.sh

//or in docker and specified ip:port
./as_startup.sh -t docker -l 127.0.0.1:8080
```
