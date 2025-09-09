## 1. 硬件环境
鲲鹏 virtCCA

## 2. 操作系统
openEuler-24.03-LTS-SP2、openEuler-25.09

## 3. 依赖软件栈部署
注意：依赖的软件均需安装对应操作系统的版本

### 3.1. TEE软件栈

#### 3.1.1. 部署环境要求
参考鲲鹏官网[部署环境要求](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/tee/fg/kunpengtee_16_0014.html)。

#### 3.1.2. 升级固件
参考鲲鹏官网[升级固件](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/tee/fg/kunpengtee_16_0015.html)。

#### 3.1.3. 机密虚机软件栈安装
```shell
$ yum install -y qemu qemu-system-aarch64
```

## 3.2. 容器软件栈安装
```shell
$ yum install -y iSulad kuasar-cc
```

## 3.3. 远程证明服务
### 3.3.1. 安装secGear-as软件包
在远程证明服务端，安装secGear-as软件包
```shell
$ yum install secGear-as -y
```

### 3.3.2. 生成自签名证书和私钥
```shell
$ openssl genrsa -out private.pem 2048
$ openssl req -new -key private.pem -out server.csr
$ openssl x509 -req -in server.csr -out as_cert.pem -signkey private.pem -days 3650
$ mkdir -p /etc/attestation/attestation-service/token
$ cp private.pem /etc/attestation/attestation-service/token/
$ cp as_cert.pem /etc/attestation/attestation-service/token/
```

### 3.3.3. 生成attestation-service的配置文件
```shell
mkdir -p /etc/attestation/attestation-service/
vim /etc/attestation.bak/attestation-service/attestation-service.conf
{
        "token_cfg": {
                "key": "/etc/attestation/attestation-service/token/private.pem",
                "iss": "oeas",
                "nbf": 0,
                "valid_duration": 300,
                "alg": "PS256"
        }
}
```

### 下载Huawei根证书以验证virtCCA
下载地址：

[Root Cert](https://gitee.com/link?target=https%3A%2F%2Fdownload.huawei.com%2Fdl%2Fdownload.do%3FactionFlag%3Ddownload%26nid%3DPKI1000000002%26partNo%3D3001%26mid%3DSUP_PKI)

[Sub Cert](https://gitee.com/link?target=https%3A%2F%2Fdownload.huawei.com%2Fdl%2Fdownload.do%3FactionFlag%3Ddownload%26nid%3DPKI1000000040%26partNo%3D3001%26mid%3DSUP_PKI)

```shell
$ mkdir -p /etc/attestation/attestation-service/verifier/virtcca
$ cp 'Huawei Equipment Root CA.pem' /etc/attestation/attestation-service/verifier/virtcca/'Huawei Equipment Root CA.pem'
$ cp 'Huawei IT Product CA.pem' /etc/attestation/attestation-service/verifier/virtcca/'Huawei IT Product CA.pem'
```

### 3.1.4. 启动远程证明服务attestation-service
```shell
# 执行远程证明服务
# attestation-service默认启动只监听本地端口，所以要设置 -s 0.0.0.0:8080参数监听其他设备。通信使用http协议。
$ attestation-service -s 0.0.0.0:8080
```

## 4. 机密容器

### 4.1. 制作加密容器镜像

#### 4.1.1. 执行加密工具
```shell
# 获取加密工具
$ git clone https://gitee.com/openeuler/guest-components 
$ cd guest-components/attestation-agent/coco_keyprovider 
$ cargo build 
# 启动加密工具
$ ../target/debug/coco_keyprovider
```

#### 4.1.2. 在启动加密工具的机器中对目标镜像做加密
```shell
# 创建临时目录
# /tmp/input 存储未加密的镜像
$ mkdir /tmp/input

# /tmp/output 存储加密后的镜像
$ mkdir /tmp/output

# 从远端镜像源中拉取未加密的目标镜像到本地
$ yum install skopeo -y
$ skopeo copy docker://hub.oepkgs.net/library/busybox_aarch64:latest dir:/tmp/input

# 创建加密配置文件
# 此配置文件主要是用于encrypt-image.sh脚本中的skopeo执行时与coco_keyprovider进行通信。
$ vim /etc/ocicrypt.conf
{
        "key-providers": {
                "attestation-agent": {
                        "grpc": "localhost:50000"
                }
        }
}

# 注意：-k avvBQtRDLhyUzlho2RxBsi/TbKDh6GQ9zezaIq0CLFA= -i kbs:///a/b/c密钥和加密算法实际上并没有对镜像做加密，实际上只做了基础的加密。
$ export OCICRYPT_KEYPROVIDER_CONFIG=/etc/ocicrypt.conf
$ ./encrypt-image.sh -k avvBQtRDLhyUzlho2RxBsi/TbKDh6GQ9zezaIq0CLFA= -i kbs:///a/b/c -s dir:/tmp/input -d dir:/tmp/output

# coco_keyprovider加密工具预期会输出如下内容
*************Received optsdata: {"symkey":"+yBv0yDEdOF1muNKXdqlUfJ2QFjJy93z5h2IJTu0lhA=","digest":"sha256:366ffb9a685d03ad8728c8e457dc9072115c2f6b840cd9d113cd7332c82851ed","cipheroptions":{"nonce":"hYRcgzsWOkYU+85ghRC5sQ=="}}
```

#### 4.1.3. 查看镜像加密结果
```shell
$ skopeo inspect dir:/tmp/output

# 预期输出的MIMEType字段中包含encrypted
{
    "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
    ...
}
```

#### 4.1.4. 对coco_keyprovider的输出内容进行base64编码
```shell
$ echo '{"symkey":"+yBv0yDEdOF1muNKXdqlUfJ2QFjJy93z5h2IJTu0lhA=","digest":"sha256:366ffb9a685d03ad8728c8e457dc9072115c2f6b840cd9d113cd7332c82851ed","cipheroptions":{"nonce":"hYRcgzsWOkYU+85ghRC5sQ=="}}' | base64 

# 预期输出如下的编码
eyJzeW1rZXkiOiIreUJ2MHlERWRPRjFtdU5LWGRxbFVmSjJRRmpKeTkzejVoMklKVHUwbGhBPSIs ImRpZ2VzdCI6InNoYTI1NjozNjZmZmI5YTY4NWQwM2FkODcyOGM4ZTQ1N2RjOTA3MjExNWMyZjZi ODQwY2Q5ZDExM2NkNzMzMmM4Mjg1MWVkIiwiY2lwaGVyb3B0aW9ucyI6eyJub25jZSI6ImhZUmNn enNXT2tZVSs4NWdoUkM1c1E9PSJ9fQo=
```

#### 4.1.5. 上传容器镜像密钥到attestation-service
将上述的编码内容整理成一行，保存到attestation-service服务端的`/etc/attestation/attestation-service/resource/storage/oeas/busybox-encrypted`文件中（oeas/busybox-encrypted可以是自定义路径）
```shell
$ mkdir -p /etc/attestation/attestation-service/resource/storage/oeas/
$ vi /etc/attestation/attestation-service/resource/storage/oeas/busybox-encrypted
{"content":"eyJzeW1rZXkiOiIreUJ2MHlERWRPRjFtdU5LWGRxbFVmSjJRRmpKeTkzejVoMklKVHUwbGhBPSIsImRpZ2VzdCI6InNoYTI1NjozNjZmZmI5YTY4NWQwM2FkODcyOGM4ZTQ1N2RjOTA3MjExNWMyZjZiODQwY2Q5ZDExM2NkNzMzMmM4Mjg1MWVkIiwiY2lwaGVyb3B0aW9ucyI6eyJub25jZSI6ImhZUmNnenNXT2tZVSs4NWdoUkM1c1E9PSJ9fQo=","policy":[]}
```

#### 4.1.6. 计算存储路径oeas/busybox-encrypted的base64编码
```shell
$ printf oeas/busybox-encrypted | base64
b2Vhcy9idXN5Ym94LWVuY3J5cHRlZA==
```

#### 4.1.7. 修改要加密镜像的manifest

修改/tmp/output/manifest.json配置文件，删除"annotations"字段中的"org.opencontainers.image.enc.keys.provider.attestation-agent"注解。
补充"org.opencontainers.image.enc.keys.provider.secgear": "b2Vhcy9idXN5Ym94LWVuY3J5cHRlZA=="注解（注解值为自定义路径oeas/busybox-encrypted的base64编码）。

```shell
$ vi /tmp/output/manifest.json
{...,"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip+encrypted","digest":"sha256:cc547a5acf740ecdfe9650f4a81d0b573d1a86942e33f95867eb84b8f2e31824","size":1833302,"annotations":{"org.opencontainers.image.enc.keys.provider.secgear": "b2Vhcy9idXN5Ym94LWVuY3J5cHRlZA==","org.opencontainers.image.enc.pubopts":"eyJjaXBoZXIiOiJBRVNfMjU2X0NUUl9ITUFDX1NIQTI1NiIsImhtYWMiOiJFZUh2RjZIbldYSVNFdk1XTmNTUEN3M0JUMmtjUjdZaFZ4RkpLNUROWUtnPSIsImNpcGhlcm9wdGlvbnMiOnt9fQ=="}}]}
```

### 4.2. 上传加密镜像到镜像仓库
```shell
$ skopeo copy /tmp/output docker://hub.oepkgs.net/isulad/busybox-encrypted:latest
```

### 4.3. 配置机密容器
参考：[isulad+kuasar机密容器部署指南](https://gitee.com/openeuler/docs-centralized/blob/master/docs/zh/docs/Container/isulad+kuasar-confidential-containers-deployment-guide.md)

#### 4.3.1. cni插件安装
```shell
$ wget https://github.com/containernetworking/plugins/releases/download/v1.3.0/cni-plugins-linux-arm64-v1.3.0.tgz
$ mkdir -p /opt/cni/bin/
$ tar -zxvf cni-plugins-linux-arm64-v1.3.0.tgz -C /opt/cni/bin/
```

#### 4.3.2. 修改iSulad配置文件
```shell
$ vi /etc/isulad/daemon.json
{
    ... ...
    "network-plugin": "cni",
    "default-sandboxer": "cc",
    "enable-cri-v1": true,
    "cri-sandboxers": {
        "cc": {
            "name": "cc", 
            "image-type":"remote",
            "address": "/run/cc-vmm-sandboxer.sock"
        }
    },
    "cri-runtimes": {
        "cc": "io.containerd.cc.v1"
    }
    ... ...
}
```
cri-sandboxers 和 cri-runtimes指定启动sandbox运行时的相关配置。其他参数可以参考[安装与配置](https://gitee.com/openeuler/docs-centralized/blob/master/docs/zh/docs/Container/%E5%AE%89%E8%A3%85%E4%B8%8E%E9%85%8D%E7%BD%AE.md)文档。

#### 4.3.3. 将证书打包到机密沙箱镜像
- 将机密容器服务器上的证书和镜像仓服务器证书`domain.crt`都打包到机密沙箱镜像，以便后续沙箱中可以拉取远程镜像仓库中的镜像。
- 将`3.3.2`小节中生成attestation-service根证书`as_cert.pem`打包到机密沙箱镜像，以便后续沙箱中可以访问attestation-service。
```shell
$ ls /var/lib/kuasar/cc-rootfs.img
/var/lib/kuasar/cc-rootfs.img
$ mkdir cc-rootfs
$ mount /var/lib/kuasar/cc-rootfs.img ./cc-rootfs
$ cp -r /etc/pki/ca-trust ./cc-rootfs/etc/pki/ca-trust
$ cat domain.crt >> ./cc-rootfs/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
$ cat domain.crt >> ./cc-rootfs/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt

$ mkdir -p ./cc-rootfs/etc/attestation/attestation-agent
$ cp as_cert.pem ./cc-rootfs/etc/attestation/attestation-agent/as_cert.pem

$umount ./cc-rootfs
```
#### 4.3.4. 为远程证明和镜像解密服务配置参数

修改/var/lib/kuasar/cc-config.toml中的kernel_params参数，参考下表，以key=value的形式补充需要的参数。

当前task.aa_kbc_key_provider只支持`secgear`，task.aa_proto只支持`http`，默认为`http`。

|Key|Type|Description|
|---|---|---|
|task.aa_kbc_params|String|远程证明代理的IP和端口。|
|task.aa_kbc_key_provider|String|key provider类型，目前支持"secgear"类型。|
|task.aa_ser_url|String|远程证明密钥托管服务器地址。|
|task.aa_cert|String|远程证明根证书文件路径。|
|task.aa_proto|String|与远程证明服务器通信的协议类型。|
|task.https_proxy|String|拉取镜像时的https代理环境变量。|
|task.no_proxy|String|拉取镜像时不使用代理地址的环境变量。|
|task.enable_signature_verification|bool|安全验证开关控制。|
|task.image_policy|String|`Policy.json`路径。|
|task.image_registry_auth|String|鉴权文件路径。|
|task.simple_signing_sigstore_config|String|用于简单签名的Sigstore配置文件。|

```shell
$ vi /var/lib/kuasar/cc-config.toml
... ...
kernel_params = "task.aa_kbc_params=127.0.0.1:8088 task.aa_kbc_key_provider=secgear task.aa_ser_url=xx.xx.xx.xx:8080: task.aa_cert=/etc/attestation/attestation-agent/as_cert.pem task.aa_proto=http ... ..."

$ systemctl restart cc-kuasar-vmm.service
```

#### 4.3.5. 增加cni配置文件
```shell
vi /etc/cni/net.d/mynet.conf 
{
  "cniVersion":"1.0.0",
  "name":"bridge-network",
  "type":"bridge",
  "bridge":"cni0",
  "isGateway":true,
  "ipMasq":true,
  "ipam":{
    "type":"host-local",
    "subnet":"10.244.0.0/16",
    "routes":[
      {"dst":"0.0.0.0/0"}
    ]
  }
}
```

#### 4.3.6. 增加pod配置文件
```shell
vi pod.json
{
        "annotations": {
        "cri.sandbox.network.setup.v2": "true"
        },
        "hostname": "testhostname",
        "log_directory": "/tmp",
        "linux": {
                "cgroup_parent": "/sys/fs/cgroup",
                "security_context": {
                        "namespace_options": {
                                "network": 0,
                                "pid": 0,
                                "ipc": 0
                        },
                "run_as_user": {
                        "value": 1003
                },
                "readonly_rootfs": true,
                "privileged": false
                }
        },
        "metadata": {
                "attempt": 1,
                "name": "liuxuPod",
                "namespace": "default",
                "uid": "2dishd83djaidwnduwk28baaa"
        }
}
```

#### 4.3.7. 增加container配置文件

image字段指定远程镜像仓库中加密镜像的地址。

```shell
vi local_container.json
{
    "metadata": {
        "name": "test-busybox"
    },
    "image": {
        "image": "hub.oepkgs.net/isulad/busybox-encrypted:latest"
    },
    "command": [
        "top"
    ],
    "log_path":"console.log",
    "linux": {
        "security_context": {
            "capabilities": {},
            "namespace_options": {
                "network": 0,
                "pid": 1
            }
        }
    }
}
```

### 4.4. 启动机密容器

```shell
# 重新启动iSulad和kuasar进程
$ systemctl restart cc-kuasar-vmm.service
$ systemctl restart isulad.service

# 启动机密容器
$ crictl runp --runtime cc pod.json 
8d69fee1179c4b0626230c315f48daf5ae75fcd36f080c4547724cc9aa590db9
$ crictl create 8d local_container.json pod.json
5d62561324a8f16781d2ea07008f07c33ae441e79bbebd9ae506c50f925b58c5
$ crictl start 5d
5d

# 查看机密容器启用详情
$ crictl ps -a
CONTAINER           IMAGE               CREATED             STATE               NAME                ATTEMPT             POD ID              POD
5d62561324a8f       [Encrypted]         3 hours ago         Running             test-busybox        0                   0aad103b627d7       unknown
```

当不再需要容器时，可以分别使用`crictl rm ${container id}` 删除容器，使用`crictl rmp ${sandbox id}`删除沙箱。
