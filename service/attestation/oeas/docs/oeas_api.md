# OEAS API
本文介绍OEAS服务提供的相关API接口及使用方法

> oeas-API-url(${oeas_url})：https://www.openeuler.org/api/v1/oeas

| API                                   | 描述                                                   |
| ------------------------------------- | ------------------------------------------------------ |
| [/challenge](#challenge)              | 发起挑战，建立会话                                     |
| [/attestation](#attestation)          | 远程证明（需要openeuler社区私人令牌）                  |
| [/resource/storage](resource/storage) | 基于远程证明token获取密钥（需要openeuler社区私人令牌） |

## challenge

向服务发起挑战，建立会话。获取challenge值并保存返回Cookie

### 请求参数

无

### 请求头

无

### 请求示例

```
curl -c cookie -X GET ${oeas_url}/challenge
```

### 返回内容

| 返回数据        | 数据来源 | 数据类型 | 描述               |
| --------------- | -------- | -------- | ------------------ |
| challenge       | 响应体   | 字符串   | oeas会话挑战值     |
| oeas-session-id | Cookie   | 字符串   | oeas会话session-id |



## attestation

远程证明（需要openeuler社区私人令牌）

### 请求参数

| 请求参数        | 数据类型 | 是否必选 | 描述                                                         |
| --------------- | -------- | -------- | ------------------------------------------------------------ |
| openeuler_token | 字符串   | 是       | 社区私人令牌                                                 |
| cookie          | 字符串   | 是       | challenge挑战接口返回的cookie                                |
| challenge       | 字符串   | 是       | challenge挑战接口返回的challenge                             |
| evi_base64      | 字符串   | 是       | Base64编码的TEE平台证据，使用secGear同一远程证明框架的Attestation Agent获取 |
| policy          | 字符串   | 否       | 可选参数，用于指定本次验证所使用的证明策略。支持使用多个策略，以英文逗号分隔 |

### 请求头

```
token: ${openeuler_token}
```

### 请求示例

```
curl -X GET --cookie ${cookie} \
    -H "token: ${openeuler_token}"  \
    -F "challenge=${challenge}"  \
    -F "evidence=${evi_base64}" \
    -F "policy_name=${policy}" \
    ${oeas_url}/attestation
```

### 返回内容

| 返回数据 | 数据来源 | 数据类型 | 描述                                           |
| -------- | -------- | -------- | ---------------------------------------------- |
| as_token | 响应体   | 字符串   | Attestation Token([说明文档](./oeas_token.md)) |



## resource/storage

基于远程证明token获取密钥（需要openeuler社区私人令牌）

### 请求参数

| 请求参数        | 数据类型 | 是否必选 | 描述                          |
| --------------- | -------- | -------- | ----------------------------- |
| openeuler_token | 字符串   | 是       | 社区私人令牌                  |
| resource_name   | 字符串   | 是       | 需要获取的资源名称（路径）    |
| as_token        | 字符串   | 是       | attestation接口返回的as_token |

### 请求头

```
token: ${openeuler_token}
Authorization: Bearer ${as_token}
```

### 请求示例

```
    curl -X GET -H "token: ${openeuler_token}" \
        -H "Authorization: Bearer ${as_token}" \
        "${oeas_url}/resource/storage?resource_name=${resource_name}"
```

### 返回内容

| 返回数据         | 数据来源 | 数据类型 | 描述     |
| ---------------- | -------- | -------- | -------- |
| resource_content | 响应体   | 字符串   | 资源内容 |

## 常见报错

## FAQ

### 如何获取私人令牌？

openEuler社区->个人中心->私人令牌->勾选`oeas-api`
