# 如何对NPU固件进行远程证明

## 基本原理

针对不支持设备度量的存量NPU硬件（NPU无硬件可信根），在不考虑近端物理攻击和侧信道攻击的前提下，可以通过对NPU固件进行度量来实现对NPU计算环境的完整性校验。

由于NPU无持久化存储能力，在系统上电或重启时，NPU初始化过程需要主机侧设备驱动参与。在设备驱动的运作下，主机上存储的NPU固件文件被一一读取并传输至NPU侧指定内存位置，完成固件刷写和覆盖。

根据这一流程，可以在系统初始化流程中的NPU驱动加载时，利用IMA特性对NPU驱动读取的固件文件进行度量，并将结果扩展到主机侧硬件可信根中。进而利用硬件可信根的不可篡改和不可伪造特点对度量结果进行保护，确保结果验证的真实可信。在获取度量报告时，证明代理读取IMA日志并计算sha256 hash值，将hash值传入CPU-TEE并作为度量报告的一部分进行保护。在验证度量报告时，通过“验证度量报告真实性和完整性--确保IMA日志完整性--IMA日志回放验证”来确保度量结果真实可信。

## 特性依赖

- 支持IMA（Integrity Measurement Architecture）度量框架
- 主机侧具备硬件可信根（如TPM、TPCM等, vTPM未测试）
- NPU固件文件可被主机驱动正常读取和加载
- 支持远程证明服务（如attestation-service）和相关API
- 具备固件参考值（Reference Value）管理与配置能力

## 准备操作

为了实现对NPU固件的度量和证明，需要进行以下几方面工作：

- 使用自定义SELinux文件类型对NPU固件文件进行标记
- 编写自定义IMA度量策略
- 编译运行secGear远程证明样例代码

## 环境设置

- **OS**: openEuler 22.03 LTS SP4
- **Ascend NPU驱动**: 请根据Ascend官网和使用的NPU类型，下载对应版本的驱动程序
- **Kunpeng机密计算BoostKit**: 按照特性指导手册部署安装tzdriver、itrustee_client、securec等组件
- **Kunpengsecl安全库**: `yum install kunpengsecl-attester`
- **selinux-policy**: `yum install selinux-policy`

### 前置检查

在开始操作前，请确认以下组件已正确安装：

```bash
# 检查SELinux状态
getenforce

# 检查IMA是否启用
ls /sys/kernel/security/ima/

# 检查NPU驱动是否加载
lsmod | grep -i ascend

# 检查固件文件是否存在
ls -la /usr/local/Ascend/driver/device/
```

## 操作步骤

### 1. 使用SELinux文件类型标签标记NPU固件文件

在本样例中，仅展示如何利用文件类型标签标记NPU固件文件。更复杂的规则和设置，请根据自身安全需求参考SELinux特性和专业文档。

关于SELinux的详细使用指导，可参考[openEuler 22.03 SELinux特性](https://docs.openeuler.org/zh/docs/22.03_LTS_SP4/docs/SecHarden/SELinux配置.html "openEuler 22.03 SELinux特性")

#### 1.1 编写SELinux策略模块

1. 创建工作目录和策略文件

```bash
mkdir ascendfw && cd ascendfw
vim ascendfw/ascendfw.te
```

2. 定义一个新策略，内容样例：

```bash
policy_module(ascendfw, 1.0);
require { 
   type unconfined_t;
   class file { read write };
}

type ascendfw_t;
files_type(ascendfw_t)
allow unconfied_t ascendfw_t:file { read write };
```

3. 应用到文件上下文

```bash
vim ascendfw.fc
```

文件内容样例：

```bash
/usr/local/Ascend/driver/device(/.*)?   gen_context(unconfined_u:object_r:ascendfw_t, s0)
```
 
4. 编译该模块

```bash
make -f /usr/share/selinux/policy/makefile
```

编译成功后，生成ascendfw.pp文件

5. 加载该模块

```bash
semodule -i ascendfw.pp
```

注意：若没有编写ascendfw.fc文件，则需要手动为目标文件打上标签

```bash
semanage fcontext -a -t ascendfw_t "/usr/local/Ascend/driver/device(/.*)?"
```

6. 检查结果

最后，检查selinux fcontext内容是否有相关记录

```bash
semanage fcontext -l |grep ascendfw_t
```

同时检查NPU固件文件目录的SELinux上下文标签是否符合预期

```bash
ls -lZ /usr/local/Ascend/driver/device
```

### 2. 创建并加载IMA策略

openEuler 22.03 LTS SP4默认启用IMA特性

#### 2.1 编写策略文件

编辑或创建/etc/ima/ima-policy文件，写入如下规则：

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

(注意：在实际部署中，建议对attestation-agent组件进行度量，保证关键组件的完整性)
关于IMA特性和策略语法的介绍，请参考[openEuler 22.03 LTS SP4 IMA特性](https://docs.openeuler.org/zh/docs/22.03_LTS_SP4/docs/Administration/可信计算.html#内核完整性度量ima "openEuler 22.03 IMA特性使用说明")

#### 2.2 重启系统并生效

重启系统后，内核启动日志会打印IMA特性相关内容

```bash
dmesg|grep -i ima
```

可以看到IMA策略在NPU驱动加载前已更新完毕。

进一步查看ima fs接口policy内容：

```bash
cat /sys/kernel/security/ima/policy
```

确认NPU驱动加载是否产生了度量记录：

```bash
cat /sys/kernel/security/ima/ascii_runtime_measurements
```

### 3. 编译样例TA程序

使用cmake编译helloworld_ta：

```bash
cd helloworld_ta
mkdir build
cd build
cmake -DENCLAVE=GP ..
make
make install
```

运行样例程序

```bash
/vendor/bin/secgear_hellorld
```

### 4. 编译secGear远程证明框架

#### 4.1 编译attestation-agent

以trustzone/itrustee为例：

```bash
cd secgear/service/attestation/attestation-agent
cargo build --features itrustee-attester
```

#### 4.2 编译attestation-service

```bash
cd secgear/service/attestation/attestation-service
cargo build --features itrustee-verifier
```

#### 4.3 部署agent和服务

根据[secGear远程证明服务设置](https://gitee.com/openeuler/secGear/blob/master/service/attestation/README.md)生成证书、aa-config、as-config内容并部署到相应目录，然后运行attestation-agent和attestation-service。

### 5. 向证明服务注册样例TA基线值

在先前步骤中，编译helloworld_ta后会产生TA度量基线：

```bash
cat helloworld_ta/build/lib/hash_uuid.txt
```

我们需要其中的img_hash和mem_hash字段，使用curl向本地运行的证明服务发起基线值注册：

```bash
curl -H "Content-Type:application/json" -X POST -d '{"refs":"{\"itrustee_uuid\":\"uuid img_hash mem_hash\"}"}'  http://127.0.0.1:8080/reference
```

将命令中的uuid、img_hash、mem_hash替换为相应的值/字符串。

### 6. 部署IMA度量基线

在安全环境中，使用sha256sum对NPU固件文件计算度量值，并将该值写入证明服务基线文件：

```bash
# 计算NPU固件文件的哈希值
sha256sum /usr/local/Ascend/driver/device/*.bin > /tmp/npu_firmware_hashes.txt

# 创建基线文件目录
mkdir -p /etc/attestation/attestation-service/verifier/itrustee/ima/

# 将哈希值写入基线文件
cp /tmp/npu_firmware_hashes.txt /etc/attestation/attestation-service/verifier/itrustee/ima/digest_list_file
```

每行分别写入一个文件的度量值。

### 7. 运行样例

使用aa-test程序对helloworld_ta发起证明请求，要求附带NPU固件的IMA度量信息：

```bash
cd secgear/service/attestation/attestation-agent
./target/debug/aa-test --ima
```

在证明服务窗口，可看到attestation-agent发来的证明报告内容，其中包含了ima度量相关信息，证明服务通过基线值对报告内容进行校验，并向aa-test返回Token。

## 故障排除

### 常见问题及解决方案

1. **SELinux策略加载失败**

   ```bash
   # 检查策略语法
   checkmodule -M -m -o ascendfw.mod ascendfw.te
   
   # 重新编译
   semodule_package -o ascendfw.pp -m ascendfw.mod -f ascendfw.fc

   # fcontext应用失败
   # 检查文件属性
   lsattr /usr/local/Ascend/driver/device/
   # 如果输出者含有'----i-----'，说明文件不可变，需要临时放宽限制
   chattr -i /usr/local/Ascend/driver/device/*
   # 重新应用
   restorecon -v /usr/local/Ascend/driver/device/*
   # 恢复属性
   chattr +i /usr/local/Ascend/driver/device/*
   # 也可考虑将selinux设置为permissive模式，只记录对文件的度量，不进行管控
   ```

2. **IMA策略未生效**

   ```bash
   # 检查IMA是否启用
   cat /proc/cmdline | grep ima
   
   # 重新加载IMA策略, 参考[加载自定义IMA策略](https://wiki.gentoo.org/wiki/Integrity_Measurement_Architecture "How do I load a custom IMA policy?")
   cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
   ```

3. **NPU固件文件未被度量**

   ```bash
   # 检查文件标签
   ls -lZ /usr/local/Ascend/driver/device/
   
   # 手动触发度量
   cat /usr/local/Ascend/driver/device/*.bin > /dev/null
   ```

4. **证明服务连接失败**

   ```bash
   # 检查服务状态
   systemctl status attestation-service
   
   # 检查端口监听
   netstat -tlnp | grep 8080
   ```

5. **基线值注册失败**

   ```bash
   # 检查服务日志
   journalctl -u attestation-service -f
   
   # 验证JSON格式
   echo '{"refs":"{\"itrustee_uuid\":\"test_uuid test_hash test_hash\"}"}' | jq .
   ```

## 安全注意事项

1. **基线值管理**: 确保基线值在安全环境中生成和存储
2. **策略验证**: 定期验证SELinux和IMA策略的有效性
3. **日志监控**: 监控证明服务的访问日志和错误日志
4. **证书管理**: 定期更新证明服务的证书和密钥
5. **固件验证**: 确保NPU固件来源可信，避免使用未经验证的固件

## 相关链接

- [secGear项目主页](https://gitee.com/openeuler/secGear)
- [openEuler 22.03 LTS SP4文档](https://docs.openeuler.org/zh/docs/22.03_LTS_SP4/)
- [Kunpeng BoostKit 24.0.0 机密计算TrustZone套件 特性指南 01](https://support.huawei.com/enterprise/zh/doc/EDOC1100433031?idPath=23710424|251364417|9856629|253662285)
- [IMA内核文档](https://sourceforge.net/p/linux-ima/wiki/Home/)
- [SELinux官方文档](https://selinuxproject.org/page/Main_Page)