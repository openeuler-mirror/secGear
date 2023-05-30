# Quick Start
## Intel SGX
secGear尚未支持SGX平台远程证明

## Arm Trustzone
### 环境准备
#### TEE运行环境搭建
[搭建方法](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/fg-tz/kunpengtrustzone_04_0007.html)
#### 申请TA开发者证书
本样例需要申请两个开发者证书，一个给目标TA用，一个给QTA用（QTA的uuid固定为e08f7eca-e875-440e-9ab0-5f381136c600）,并将申请到的config文件上传到开发环境  
[调测环境TA应用开发者证书申请方法](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/fg-tz/kunpengtrustzone_04_0009.html)

#### 证明服务端部署第三方依赖
- 下载代码   
QCA lib：itrustee_sdk/test/CA/libqca    
QTA：itrustee_sdk/test/TA/qta
```
git clone https://gitee.com/openeuler/itrustee_sdk.git
git clone https://gitee.com/openeuler/libboundscheck.git
cp -rf libboundscheck/ itrustee_sdk/thirdparty/open_source/
```
- 修改编译部署libqca

```
vim itrustee_sdk/test/CA/libqca/src/ra_operate_api.c
// 查找TEEC_OpenSession，并在TEEC_OpenSession上一行增加如下内容
context.ta_path = (uint8_t *)"/data/e08f7eca-e875-440e-9ab0-5f381136c600.sec";
cd itrustee_sdk/test/CA/libqca   #请根据实际路径予以替换
make
cp output/libqca.so /usr/lib64 && ldconfig
```
- 修改编译部署QTA

```
vim itrustee_sdk/test/TA/qta/src/tee_qta.c
// 并在TA_CreateEntryPoint函数中/* TA auth CA */注释下添加如下内容
// 添加允许调用QTA的CA程序，
ret = addcaller_ca_exec("/vendor/bin/secgear_ra_demo", "root");
if (ret != TEE_SUCCESS)
    return ret;

// 下载第三方依赖cJSON
wget https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz
tar xvf v1.7.15.tar.gz 
mv cJSON-1.7.15/ itrustee_sdk/test/TA/qta/src/cJSON

// 配置QTA开发者证书
// 将QTA开发者证书对应的私钥、config文件放到如下目录下
itrustee_sdk/build/signtools/signed_config/config
itrustee_sdk/build/signtools/TA_cert/private_key.pem
// 根据QTA开发者证书申请是的config.xml，修改itrustee_sdk/test/TA/qta/manifest.txt中字段

pip3 install pycryptodomex           #安装iTrustee SDK TA签名工具依赖
cd itrustee_sdk/test/TA/qta    #根据实际路径予以替换
make
cp e08f7eca-e875-440e-9ab0-5f381136c600.sec /data
```

#### 验证者部署第三方依赖库

```
// deploy libteeverifier.so
git clone https://gitee.com/openeuler/kunpengsecl.git
cd attestation/tee/tverlib/verifier
make
cp libteeverifier.so /usr/lib64/

// deploy libcjson.so
wget https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz
tar xvf v1.7.15.tar.gz 
cd cJSON-1.7.15/
make && make install

// intall Huawei IT Product CA.pem
// windows浏览器下载https://download.huawei.com/dl/download.do?actionFlag=download&nid=PKI1000000040&partNo=3001&mid=SUP_PKI
// 上传到环境 secGear/examples/remote_attest/build/目录下
```


### 编译运行secGear样例

```
// intall build require depends openEuler 22.03 LTS SP2 repo
sudo yum install -y cmake ocaml-dune itrustee_sdk-devel secGear-devel

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// 配置目标TA开发者证书
// 根据目标TA开发者证书对应的config.xml修改secGear/examples/remote_attest/enclave/manifest.txt中字段    
// 修改secGear/examples/remote_attest/enclaveconfig_cloud.ini文件中encryptKey、signKey、configPath三个路径    
// 放开secGear/examples/remote_attest/enclave/CMakeLists.txt如下几行注释，开启签名
    add_custom_command(TARGET ${PREFIX}
   	    POST_BUILD
   	    COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${PREFIX}.so -c ${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt -m ${CMAKE_CURRENT_SOURCE_DIR}/config_cloud.ini -o ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT})

    install(FILES ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT}
       DESTINATION /data
       PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE  WORLD_READ  WORLD_EXECUTE)

// build example remote attest
cd secGear/examples/remote_attest
mkdir build&& cd build && cmake -DENCLAVE=GP .. && make && sudo make install

// config basevalue.txt
// edit basevalue.txt to overwrite taid img_hash mem_hash, the img_hash and mem_hash comes from /opt/itrustee_sdk/build/signtools/hash_uuid.txt

// run demo
/vendor/bin/secgear_ra_demo
```