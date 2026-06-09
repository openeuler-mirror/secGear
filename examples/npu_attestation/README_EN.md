# How Do I Perform Remote Attestation on NPU Firmware?

## Basic Principles

For existing NPU hardware that does not support device measurement (i.e., NPU without a hardware root of trust), the integrity of the NPU computing environment can be verified by measuring the NPU firmware, provided that local physical attacks and side-channel attacks are not considered.

Since the NPU does not support persistent storage, the host-side device driver is required during the NPU initialization process when the system is powered on or restarted. With the operation of the device driver, the NPU firmware files stored on the host are sequentially read and transmitted to the designated memory locations on the NPU side to complete the firmware flashing and overwriting.

Based on this process, when the NPU driver is loaded during system initialization, the IMA feature can be used to measure the firmware files read by the NPU driver, and the measurement result can be extended to the hardware root of trust on the host side. Leveraging the tamper-proof and unforgeable characteristics of the hardware root of trust, the measurement results are protected, ensuring the authenticity and trustworthiness of the verification. When obtaining the measurement report, the attestation agent reads the IMA log, calculates the SHA-256 hash value, and transfers the hash value to the CPU-TEE. The hash value is then protected as part of the measurement report. During the verification of the measurement report, the authenticity and integrity of the report are verified, the integrity of the IMA log is ensured, and the IMA log is replayed for validation, thereby ensuring the authenticity and trustworthiness of the measurement results.

## Feature Dependency

- The integrity measurement architecture (IMA) measurement framework is supported.
- The host has a hardware root of trust (such as TPM and TPCM. vTPM is not tested).
- The NPU firmware file can be properly read and loaded by the host driver.
- The remote attestation service (such as attestation-service) and related APIs are supported.
- The firmware reference values can be managed and configured.

## Preparations

To measure and attest the NPU firmware, perform the following operations:

- Use a custom SELinux file type to label the NPU firmware file.
- Compile a custom IMA measurement policy.
- Compile and run the secGear remote attestation sample code.

## Environment Settings

- **OS**: openEuler 22.03 LTS SP4
- **Ascend NPU driver**: Download the driver of the required version from the Ascend official website based on the NPU type in use.
- **Kunpeng BoostKit for Confidential Computing**: Install components such as tzdriver, itrustee_client, and securec by referring to the feature guide.
- **Kunpengsecl security library**: `yum install kunpengsecl-attester`
- **selinux-policy**: `yum install selinux-policy`

### Pre-check

Before performing operations, ensure that the following components have been correctly installed:

```bash
# Check the SELinux status.
getenforce

# Check whether IMA is enabled.
ls /sys/kernel/security/ima/

# Check whether the NPU driver is loaded.
lsmod | grep -i ascend

# Check whether the firmware file exists.
ls -la /usr/local/Ascend/driver/device/
```

## Procedure

### 1. Using an SELinux File Type Label to Mark the NPU Firmware File

In this example, only the use of a file type label to mark the NPU firmware file is demonstrated. For more complex rules and settings, refer to the SELinux features and official documents according to your security requirements.

For details about how to use SELinux, see [openEuler 22.03 SELinux Features](https://docs.openeuler.org/en/docs/22.03_LTS_SP4/server/security/secharden/selinux_configuration.html).

#### 1.1 Compiling the SELinux Policy Module

1. Create a working directory and a policy file.

   ```bash
   mkdir ascendfw && cd ascendfw
   vim ascendfw/ascendfw.te
   ```

2. Define a new policy. The following is an example:

   ```bash
   policy_module(ascendfw, 1.0);
   require { 
      type unconfined_t;
      class file { read write };
   }

   type ascendfw_t;
   files_type(ascendfw_t)
   allow unconfined_t ascendfw_t:file { read write };
   ```

3. Apply it to the file context.

   ```bash
   vim ascendfw.fc
   ```

   A file content example is as follows:

   ```bash
   /usr/local/Ascend/driver/device(/.*)?   gen_context(unconfined_u:object_r:ascendfw_t, s0)
   ```
 
4. Compile the module.

   ```bash
   make -f /usr/share/selinux/policy/makefile
   ```

   After the compilation is successful, the ascendfw.pp file is generated.

5. Load the module.

   ```bash
   semodule -i ascendfw.pp
   ```

   Note: If the ascendfw.fc file is not compiled, you need to manually label the target file.

   ```bash
   semanage fcontext -a -t ascendfw_t "/usr/local/Ascend/driver/device(/.*)?"
   ```

6. Check the result.

   Finally, check whether the SELinux fcontext contains related records.

   ```bash
   semanage fcontext -l | grep ascendfw_t
   ```

   Check whether the SELinux context label of the NPU firmware file directory meets the expectation.

   ```bash
   ls -lZ /usr/local/Ascend/driver/device
   ```

### 2. Creating and Loading an IMA Policy

The IMA feature is enabled by default in openEuler 22.03 LTS SP4.

#### 2.1 Compiling a Policy File

Edit or create the /etc/ima/ima-policy file and add the following rules:

```bash
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

(Note: In actual deployment, it is recommended that the attestation-agent component be measured to ensure the integrity of key components.)
For details about the IMA feature and policy syntax, see [openEuler 22.03 LTS SP4 IMA Feature](https://docs.openeuler.org/en/docs/22.03_LTS_SP4/server/security/trusted_computing/trusted_computing.html).

#### 2.2 Restarting the System for the Configuration to Take Effect

After the system restarts, the kernel boot log displays information related to the IMA feature.

```bash
dmesg | grep -i ima
```

You can see that the IMA policy has been updated before the NPU driver is loaded.

Check the policy content of the ima fs interface.

```bash
cat /sys/kernel/security/ima/policy
```

Check whether a measurement record is generated during NPU driver loading.

```bash
cat /sys/kernel/security/ima/ascii_runtime_measurements
```

### 3. Compiling a Sample TA Program

Use CMake to compile helloworld_ta.

```bash
cd helloworld_ta
mkdir build
cd build
cmake -DENCLAVE=GP ..
make
make install
```

Run the sample program.

```bash
/vendor/bin/secgear_hellorld
```

### 4. Compiling the secGear Remote Attestation Framework

#### 4.1 Compiling attestation-agent

The following uses trustzone/itrustee as an example:

```bash
cd secgear/service/attestation/attestation-agent
cargo build --features itrustee-attester
```

#### 4.2 Compiling attestation-service

```bash
cd secgear/service/attestation/attestation-service
cargo build --features itrustee-verifier
```

#### 4.3 Deploying the agent and service

Generate the certificate, aa-config, and as-config content based on [secGear Remote Attestation Service Settings](https://gitee.com/openeuler/secGear/blob/master/service/attestation/README.md), deploy them to the corresponding directories, and run attestation-agent and attestation-service.

### 5. Registering the Baseline Value of the Sample TA with the attestation-service

In the previous step, the TA measurement baseline is generated after helloworld_ta is compiled.

```bash
cat helloworld_ta/build/lib/hash_uuid.txt
```

We need the img_hash and mem_hash fields. Use curl to initiate baseline value registration with the locally running attestation-service.

```bash
curl -H "Content-Type:application/json" -X POST -d '{"refs":"{\"itrustee_uuid\":\"uuid img_hash mem_hash\"}"}'  http://127.0.0.1:8080/reference
```

Replace uuid, img_hash, and mem_hash in the command with the corresponding values or strings.

### 6. Deploying the IMA Measurement Baseline

In a secure environment, use sha256sum to calculate the measurement value of the NPU firmware file and write the value to the attestation service baseline file.

```bash
# Calculate the hash value of the NPU firmware file.
sha256sum /usr/local/Ascend/driver/device/* > /tmp/npu_firmware_hashes.txt

# Create a baseline file directory.
mkdir -p /etc/attestation/attestation-service/verifier/itrustee/ima/

# Write the hash value to the baseline file.
cp /tmp/npu_firmware_hashes.txt /etc/attestation/attestation-service/verifier/itrustee/ima/digest_list_file
```

Write the measurement value of each file in each line.

### 7. Sample Running

Use the aa-test program to initiate an attestation request to helloworld_ta, requiring the IMA measurement information of the NPU firmware.

```bash
cd secgear/service/attestation/attestation-agent
./target/debug/aa-test --ima
```

In the attestation service window, you can view the attestation report sent by attestation-agent, which contains the IMA measurement information. The attestation service verifies the report content based on the baseline value and returns a token to aa-test.

## Troubleshooting

### Common Issues and Solutions

1. **Failure to Load the Selinux Policy**

   ```bash
   # Check the policy syntax.
   checkmodule -M -m -o ascendfw.mod ascendfw.te
   
   # Recompile
   semodule_package -o ascendfw.pp -m ascendfw.mod -f ascendfw.fc

   # Failure to apply fcontext
   # Check the file attributes.
   lsattr /usr/local/Ascend/driver/device/
   # If the output contains '----i-----', the file is immutable. In this case, you need to temporarily relax the restrictions.
   chattr -i /usr/local/Ascend/driver/device/*
   # Reapply
   restorecon -v /usr/local/Ascend/driver/device/*
   # Restore the attributes.
   chattr +i /usr/local/Ascend/driver/device/*
   # You can also set SELinux to permissive mode, which only records file measurements and does not perform control.
   ```

2. IMA Policy Not Effective

   ```bash
   # Check whether IMA is enabled.
   cat /proc/cmdline | grep ima
   
   # Reload the IMA policy. For details, see [Loading a Custom IMA Policy](https://wiki.gentoo.org/wiki/Integrity_Measurement_Architecture "How do I load a custom IMA policy?").
   cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
   ```

3. **NPU Firmware File Not Measured**

   ```bash
   # Check the file label.
   ls -lZ /usr/local/Ascend/driver/device/
   
   # Manually trigger measurement.
   cat /usr/local/Ascend/driver/device/* > /dev/null
   ```

4. **Failure to Connect to the Attestation Service**

   Troubleshooting:
   (1) Check the run logs and startup parameters of the attestation service to ensure that the listening IP address and port of the service process match the accessed ones.

   ```bash
   # Check port listening.
   netstat -tlnp | grep 8080
   ```

   (2) Ensure that the network connection between the server and the attestation service is established. For example, verify connectivity by pinging the IP address.
   (3) Check the firewall rules on the server to determine whether the relevant ports are blocked. For example, use the iptables or firewall-cmd command.

5. **Baseline Value Registration Failure**

   Troubleshooting:
   (1) Check the run logs of the attestation service to determine whether the service process has sufficient permissions to read and write files in the **/etc/attestation** directory.
   (2) Check whether the format of the registration message is correct. For example:

   ```bash
   # Verify the JSON format.
   echo '{"refs":"{\"itrustee_uuid\":\"test_uuid test_hash test_hash\"}"}' | jq .
   ```

## Safety Precautions

1. **Baseline value management**: Ensures that baseline values are generated and stored in a secure environment.
2. **Policy verification**: Periodically verifies the validity of SELinux and IMA policies.
3. **Log monitoring**: Monitors the access logs and error logs of the attestation service.
4. **Certificate management**: Periodically updates the certificates and keys of the attestation service.
5. **Firmware verification**: Ensures that the NPU firmware source is trusted and avoids using unverified firmware.

## Related Links

- [secGear homepage](https://gitee.com/openeuler/secGear)
- [IMA kernel documentation](https://sourceforge.net/p/linux-ima/wiki/Home/)
- [SELinux official documentation](https://selinuxproject.org/page/Main_Page)
