# secGear Installation

## Arm Environment

### Environment Requirements

#### Hardware

| Item  | Version                                               |
| ------ | --------------------------------------------------- |
| Server| TaiShan 200 server (model 2280)                      |
| Mainboard  | Kunpeng board                                           |
| BMC    | 1711 board (model BC82SMMAB); firmware version: 3.01.12.49 or later|
| CPU    | Kunpeng 920 processor (model 7260, 5250, or 5220)              |
| Chassis  | No special requirements; an 8- or 12-drive chassis recommended                                |

> [!NOTE]NOTE   
> Ensure that the TrustZone feature kit has been preconfigured on the server. That is, the TEE OS, TEE OS boot key, BMC, BIOS, and license have been preconfigured on the server.
> For common servers, the TrustZone feature cannot be enabled only by upgrading the BMC, BIOS, and TEE OS firmware.
> By default, the TrustZone feature is disabled on the server. For details about how to enable the TrustZone feature on the server, see BIOS settings.

### Environment Preparation

For details, see [Environment Requirements](https://www.hikunpeng.com/document/detail/en/kunpengcctrustzone/fg-tz/kunpengtrustzone_20_0018.html) and [Procedure](https://www.hikunpeng.com/document/detail/en/kunpengcctrustzone/fg-tz/kunpengtrustzone_20_0019.html) on the Kunpeng official website.

### Installation

1. Configure the openEuler Yum repository. You can configure an online Yum repository (see the example below) or configure a local Yum repository by mounting an ISO file.

    ```shell
    vi /etc/yum.repo/openEuler.repo
    [osrepo]
    name=osrepo
    baseurl=http://repo.openeuler.org/openEuler-22.03-LTS/everything/aarch64/
    enabled=1
    gpgcheck=1
    gpgkey=http://repo.openeuler.org/openEuler-22.03-LTS/everything/aarch64/RPM-GPG-KEY-openEuler
    ```

2. Install secGear.

    ```shell
    #Install the compiler.
    yum install cmake ocaml-dune

    #Install secGear.
    yum install secGear-devel

    #Check whether the installations are successful. If the command output is as follows, the installations are successful.
    rpm -qa | grep -E 'secGear|itrustee|ocaml-dune'
    itrustee_sdk-xxx
    itrustee_sdk-devel-xxx
    secGear-xxx
    secGear-devel-xxx
    ocaml-dune-xxx
    ```

## x86 Environment

### Environment Requirements

#### Hardware

Processor that supports the Intel SGX feature

### Environment Preparation

Purchase a device that supports the Intel SGX feature and enable the SGX feature by referring to the BIOS setting manual of the device.

### Installation

1. Configure the openEuler Yum repository. You can configure an online Yum repository (see the example below) or configure a local Yum repository by mounting an ISO file.

    ```shell
    vi openEuler.repo
    [osrepo]
    name=osrepo
    baseurl=http://repo.openeuler.org/openEuler-22.03-LTS/everything/x86_64/
    enabled=1
    gpgcheck=1
    gpgkey=http://repo.openeuler.org/openEuler-22.03-LTS/everything/x86_64/RPM-GPG-KEY-openEuler
    ```

2. Install secGear.

    ```shell
    # Install the compiler.
    yum install cmake ocaml-dune

    # Install secGear.
    yum install secGear-devel

    # Check whether the installations are successful. If the command output is as follows, the installations are successful.
    rpm -qa | grep -E 'secGear|ocaml-dune|sgx'
    secGear-xxx
    secGear-devel-xxx
    ocaml-dune-xxx
    libsgx-epid-xxx
    libsgx-enclave-common-xxx
    libsgx-quote-ex-xxx
    libsgx-aesm-launch-plugin-xxx
    libsgx-uae-service-xxx
    libsgx-ae-le-xxx
    libsgx-urts-xxx
    sgxsdk-xxx
    sgx-aesm-service-xxx
    linux-sgx-driver-xxx
    libsgx-launch-xxx
    ```
