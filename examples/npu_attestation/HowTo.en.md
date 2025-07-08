# How to Perform Remote Attestation for NPU Firmware

## Basic Principles
For legacy NPU hardware that does not support device measurement (i.e., NPUs without a hardware root of trust (RoT)), you can verify the integrity of the NPU computing environment by measuring the NPU firmware—assuming local physical and side-channel attacks are out of scope.

Because NPUs lack persistent storage, their initialization process requires the host-side device driver to participate whenever the system is powered on or restarted. During this process, the device driver reads the NPU firmware files stored on the host and transfers them one by one to designated memory locations on the NPU, completing the firmware flashing and overwriting.

Based on this workflow, during system initialization and NPU driver loading, you can leverage the IMA feature to measure the firmware files accessed by the NPU driver. These measurement results can then be anchored to the host's RoT. By taking advantage of the tamper-resistant and unforgeable properties of the RoT, you can ensure the authenticity and reliability of the measurement results.

## Feature Dependencies
- Support for IMA (Integrity Measurement Architecture) measurement framework
- Host equipped with a hardware root of trust (RoT) (e.g., TPM, TPCM, etc.; vTPM not tested)
- NPU firmware files accessible and loadable by the host driver
- Support for remote attestation services (such as attestation-service) and related APIs
- Capability to manage and configure firmware reference values (Reference Value)

## Preparation
To enable NPU firmware measurement and attestation, you need to:
- Label NPU firmware files with custom SELinux file types
- Write custom IMA measurement policies
- Compile and run secGear remote attestation sample code

## Environment Setup
- **OS**: openEuler 22.03 LTS SP4
- **Ascend NPU Driver**: Download the appropriate driver version from the Ascend official website based on your NPU model
- **Kunpeng Confidential Computing BoostKit**: Install components such as tzdriver, itrustee_client, and securec as guided by the feature documentation
- **Kunpengsecl Security Library**: `yum install kunpengsecl-attester`
- **selinux-policy**: `yum install selinux-policy`

### Pre-checks
Before proceeding, ensure the following components are properly installed:
```bash
# Check SELinux status
getenforce

# Check if IMA is enabled
ls /sys/kernel/security/ima/

# Check if the NPU driver is loaded
lsmod | grep -i ascend

# Check if the firmware files exist
ls -la /usr/local/Ascend/driver/device/
```

## Procedure

### 1. Label NPU Firmware Files with SELinux File Types
This guide demonstrates how to label NPU firmware files using SELinux file type labels. For more advanced rules and configurations, refer to SELinux documentation and tailor them to your security requirements.

For detailed SELinux guidance, see [openEuler 22.03 SELinux Feature](https://docs.openeuler.org/zh/docs/22.03_LTS_SP4/docs/SecHarden/SELinux配置.html)

#### 1.1 Create a SELinux Policy Module

1. Create a working directory and policy file:
```bash
mkdir ascendfw && cd ascendfw
vim ascendfw/ascendfw.te
```

2. Define a new policy. Example content:
```
module ascendfw 1.0;
require { type unconfined_t; }
type ascendfw_t;
files_type(ascendfw_t)
```

3. Apply the policy to file contexts:
```bash
vim ascendfw.fc
```
Example file content:
```
/usr/local/Ascend/driver/device(/.*)?   gen_context(unconfined_u:object_r:ascendfw_t, s0)
```

4. Compile the module:
```bash
make -f /usr/share/selinux/policy/makefile
```
After successful compilation, the `ascendfw.pp` file will be generated.

5. Load the module:
```bash
semodule -i ascendfw.pp
```
Note: If you do not create an `ascendfw.fc` file, you must manually label the target files:
```bash
semanage fcontext -a -t ascendfw_t "/usr/local/Ascend/driver/device(/.*)?"
```

6. Verify the result:
Check for relevant records in the SELinux fcontext list:
```bash
semanage fcontext -l | grep ascendfw_t
```
Also, verify that the SELinux context label for the NPU firmware directory is as expected:
```bash
ls -lZ /usr/local/Ascend/driver/device
```

### 2. Create and Load an IMA Policy
openEuler 22.03 LTS SP4 enables IMA by default.

#### 2.1 Write the Policy File
Edit or create `/etc/ima/ima-policy` and add the following rules:
```
# PROC_SUPER_MAGIC = 0x9fa0
dont_measure fsmagic=0x9fa0
# SYSFS_MAGIC = 0x62656572
dont_measure fsmagic=0x62656572
# DEBUGFS_MAGIC = 0x64626720 
dont_measure fsmagic=0x64626720 
# TMPFS_MAGIC = 0x01021994
dont_measure fsmagic=0x1021994
# RAMFS_MAGIC
dont_measure fsmagic=0x858458f6 
# DEVPTS_SUPER_MAGIC=0x1cd1
dont_measure fsmagic=0x1cd1
# BINFMTFS_MAGIC=0x42494e4d
dont_measure fsmagic=0x42494e4d 
# SECURITYFS_MAGIC=0x73636673
dont_measure fsmagic=0x73636673
# SELINUX_MAGIC=0xf97cff8c
dont_measure fsmagic=0xf97cff8c 
# SMACK_MAGIC=0x43415d53
dont_measure fsmagic=0x43415d53 
# NSFS_MAGIC=0x6e736673
dont_measure fsmagic=0x6e736673 
# CGROUP_SUPER_MAGIC=0x27e0eb
dont_measure fsmagic=0x27e0eb 
# CGROUP2_SUPER_MAGIC=0x63677270
dont_measure fsmagic=0x63677270 
$ measure ascendfw_t files
measure func=FILE_CHECK obj_type=ascendfw_t
audit func=FILE_CHECK obj_type=ascendfw_t
```
(Note: In real deployment, it is recommended to measure the attestation-agent component to ensure the integrity of key components.)
For an introduction to IMA features and policy syntax, see [openEuler 22.03 LTS SP4 IMA Feature](https://docs.openeuler.org/zh/docs/22.03_LTS_SP4/docs/Administration/可信计算.html#内核完整性度量ima)

#### 2.2 Reboot the System to Apply the Policy
After rebooting, check the kernel boot log for IMA-related messages:
```bash
dmesg | grep -i ima
```
You should see that the IMA policy was updated before the NPU driver loaded.

To further verify the policy loaded by the IMA fs interface:
```bash
cat /sys/kernel/security/ima/policy
```

Check if the NPU driver loading generated measurement records:
```bash
cat /sys/kernel/security/ima/ascii_runtime_measurements
```

### 3. Compile the Sample TA Program
Use CMake to build `helloworld_ta`:
```bash
cd helloworld_ta
mkdir build
cd build
cmake -DENCLAVE=GP ..
make
make install
```
Run the sample program:
```bash
/vendor/bin/secgear_hellorld
```

### 4. Compile the secGear Remote Attestation Framework

#### 4.1 Build attestation-agent
For example, with TrustZone/iTrustee:
```bash
cd secgear/service/attestation/attestation-agent
cargo build --features itrustee-attester
```

#### 4.2 Build attestation-service
```bash
cd secgear/service/attestation/attestation-service
cargo build --features itrustee-verifier
```

#### 4.3 Deploy the Agent and Service
Refer to [secGear Remote Attestation Service Setup](https://gitee.com/openeuler/secGear/blob/master/service/attestation/README.md) to generate certificates, `aa-config`, and `as-config`, deploy them to the appropriate directories, and then run `attestation-agent` and `attestation-service`.

### 5. Register the Sample TA Baseline with the Attestation Service
After building `helloworld_ta`, a TA measurement baseline will be generated:
```bash
cat helloworld_ta/build/lib/hash_uuid.txt
```

Extract the `img_hash` and `mem_hash` fields, then use `curl` to register the baseline with the local attestation service:
```bash
curl -H "Content-Type:application/json" -X POST -d '{"refs":"{\"itrustee_uuid\":\"uuid img_hash mem_hash\"}"}'  http://127.0.0.1:8080/reference
```
Replace `uuid`, `img_hash`, and `mem_hash` with the actual values.

### 6. Deploy the IMA Measurement Baseline
In a secure environment, use `sha256sum` to calculate the hash of the NPU firmware files and write the values to the attestation service's baseline file:
```bash
# Calculate the hash of the NPU firmware files
sha256sum /usr/local/Ascend/driver/device/*.bin > /tmp/npu_firmware_hashes.txt

# Create the baseline file directory
mkdir -p /etc/attestation/attestation-service/verifier/itrustee/ima/

# Write the hash values to the baseline file
cp /tmp/npu_firmware_hashes.txt /etc/attestation/attestation-service/verifier/itrustee/ima/digest_list_file
```
Each line should contain the hash for one file.

### 7. Run the Sample
Use the `aa-test` program to initiate an attestation request for `helloworld_ta`, including the IMA measurement information for the NPU firmware:
```bash
cd secgear/service/attestation/attestation-agent
./target/debug/aa-test --ima
```

In the attestation service window, you should see the attestation report sent by `attestation-agent`, which includes IMA measurement information. The attestation service will verify the report against the baseline and return a token to `aa-test`.

## Troubleshooting

### Common Issues and Solutions

1. **SELinux policy loading failed**
   ```bash
   # Check policy syntax
   checkmodule -M -m -o ascendfw.mod ascendfw.te
   
   # Recompile
   semodule_package -o ascendfw.pp -m ascendfw.mod -f ascendfw.fc

   # If fcontext application failed
   # Check file attributes
   lsattr /usr/local/Ascend/driver/device/
   # If the output contains '----i-----', the file is immutable and needs to be temporarily relaxed
   chattr -i /usr/local/Ascend/driver/device/*
   # Reapply
   restorecon -v /usr/local/Ascend/driver/device/*
   # Restore attributes
   chattr +i /usr/local/Ascend/driver/device/*
   # Alternatively, set SELinux to permissive mode to log measurements without enforcement
   ```

2. **IMA policy not effective**
   ```bash
   # Check if IMA is enabled
   cat /proc/cmdline | grep ima
   
   # Reload IMA policy, refer to [loading customized IMA policies](https://wiki.gentoo.org/wiki/Integrity_Measurement_Architecture "How do I load a custom IMA policy?")
   cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
   ```

3. **NPU firmware file not measured**
   ```bash
   # Check file label
   ls -lZ /usr/local/Ascend/driver/device/
   
   # Manually trigger measurement
   cat /usr/local/Ascend/driver/device/*.bin > /dev/null
   ```

4. **Attestation service connection failed**
   ```bash
   # Check service status
   systemctl status attestation-service
   
   # Check port listening
   netstat -tlnp | grep 8080
   ```

5. **Baseline registration failed**
   ```bash
   # Check service logs
   journalctl -u attestation-service -f
   
   # Validate JSON format
   echo '{"refs":"{\"itrustee_uuid\":\"test_uuid test_hash test_hash\"}"}' | jq .
   ```

## Security Notes

1. **Baseline management**: Ensure baselines are generated and stored in a secure environment.
2. **Policy validation**: Regularly verify the effectiveness of SELinux and IMA policies.
3. **Log monitoring**: Monitor access and error logs for the attestation service.
4. **Certificate management**: Regularly update attestation service certificates and keys.
5. **Firmware verification**: Only use trusted NPU firmware sources; avoid unverified firmware.

## Related Links

- [secGear Project Home](https://gitee.com/openeuler/secGear)
- [openEuler 22.03 LTS SP4 Documentation](https://docs.openeuler.org/zh/docs/22.03_LTS_SP4/)
- [Kunpeng BoostKit 24.0.0 Confidential Computing TrustZone Suite Feature Guide 01](https://support.huawei.com/enterprise/zh/doc/EDOC1100433031?idPath=23710424|251364417|9856629|253662285)
- [IMA Kernel Documentation](https://sourceforge.net/p/linux-ima/wiki/Home/)
- [SELinux Official Documentation](https://selinuxproject.org/page/Main_Page) 