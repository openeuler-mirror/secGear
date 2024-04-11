# 擎天远程证明报告验证Demo

## 场景说明

当用户访问部署在擎天enclave环境的安全应用/服务时，为了验证对端的合法性、建立信任关系，可以通过验证安全应用的远程证明报告来实现.

(擎天enclave远程证明报告的原理介绍：https://support.huaweicloud.com/usermanual-ecs/ecs_03_1411.html)

由于擎天enclave的证明报告只能通过enclave虚拟机向QTSM设备发起请求的方式获得，而enclave虚拟机又没有I/O通道。
因此，在实际的部署中，通常需要在父虚拟机中部署网络转发服务来中转远端用户和enclave虚拟机间的通信，即网络通信如下：

远端用户设备/应用 <--- 网络通信 --> 擎天父虚拟机 <--- vsocket ---> enclave虚拟机

在这个Demo中，简便起见，我们只实现了位于远端用户的验证方（verifier），其利用相关接口获得enclave虚拟机的证明报告、并进行验证。
在实际部署中，开发者应自行实现上述的完整网络通信。

## Demo流程
参考擎天enclave给出的验证方式（https://support.huaweicloud.com/usermanual-ecs/ecs_03_1412.html），
验证方verifier的简要工作流程如下：
1. 利用cc_get_ra_report方法获取enclave虚拟机的证明报告（CBOR编码）；
2. 利用qt_verify_report方法对证明报告进行解析和验证。

在验证之前，verifier应当取得以下数据/材料：
1. 擎天enclave根证书（https://qingtian-enclave.obs.myhuaweicloud.com/huawei_qingtian-enclaves_root-G1.zip），
   用于校验证明报告中的证书链；
2. enclave镜像的PCR值，该组数值应当由安全服务提供方/擎天enclave虚拟机镜像制作者发布并公开；
3. (可选)nonce值，verifier可指定（不超过512字节）并传递给enclave虚拟机，用于证明报告的新鲜性保证。

## 编译方法：
**请注意**： enclave目录会在secGear/build/eif下建立临时镜像打包目录。
请参考enclave/Dockerfile检查依赖项，如docker、libcbor，libqtsm等。

编译参照CMakeLists.txt进行。大致流程如下：
1. 使用secGear SDK 源码编译：

    1.1. 修改examples/CMakeLists.txt，通过add_directory引入该demo目录结构；

    1.2. 在build目录下执行cmake -DCC_QT=ON /path/to/secGear-SDK；

    1.3. 执行make进行编译。

2. 使用openEuler 中的secGear二进制包：

    1.1. 在demo目录下建立build文件夹；

    1.2. 在build目录下执行cmake -DCC_QT=ON /path/to/secGear-SDK；

    1.3. 执行make进行编译。

## 运行
执行 ``` verifier/secgear_qt_verifier /path/to/qingtian-enclave-root-cert.pem``` 执行demo。

## 注意事项
1. 在某些老旧的擎天平台上，证明报告中的证书链并非由擎天enclave根证书开始生成，
   用户需酌情考虑是否开启qt_ra_report_verify.c中相关宏定义；
2. 在某些测试平台上，证明报告中的PCR值可能没有正确生成/携带，用户需酌情考虑是否开启qt_ra_report_verify.c中相关宏定义；