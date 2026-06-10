# 主动证明使用说明

## 1. 概述

本文说明如何启用 attestation-agent（AA）主动证明，并让 Relying Party（RP）通过 AA 的 `/active_token` 接口获取 Attestation Service（AS）签发的缓存 JWT token。

当前阶段支持两类运行平台：

| 平台 | `/active_token` 当前能力 |
|------|--------------------------|
| iTrustee | 返回指定 TA 或默认 TA 的缓存 AS JWT token |
| virtCCA | 返回缓存 AS JWT token，并实时生成绑定 RP nonce 的 CVM Token 和设备证书 |

基本流程：

1. AA 启动后按配置周期性向 AS 获取 challenge。
2. AA 调用本机 TEE 能力生成 evidence。
3. AA 将 evidence 提交给 AS 验证。
4. AS 校验证据、reference 和 policy 后签发 JWT。
5. AA 缓存 JWT，并通过 `/active_token` 对 RP 暴露。

## 2. 构建

### 2.1 构建 AS

```bash
cd secGear/service/attestation/attestation-service
cargo build
```

### 2.2 构建 AA

iTrustee：

```bash
cd secGear/service/attestation/attestation-agent
cargo build --features itrustee-attester
```

virtCCA：

```bash
cd secGear/service/attestation/attestation-agent
cargo build --features virtcca-attester
```

通常应按实际硬件平台选择对应 feature。`all-attester` 可用于同时编译两类 attester，但运行时仍由当前硬件和固件决定平台。

## 3. 通用 AA 配置

AA 配置文件默认路径：

```text
/etc/attestation/attestation-agent/attestation-agent.conf
```

通用字段：

| 字段 | 说明 |
|------|------|
| `svr_url` | AS 地址，AA 会访问 `<svr_url>/challenge` 和 `<svr_url>/attestation` |
| `token_cfg.cert` | AS JWT 公钥证书路径，用于本地 token 验证接口 |
| `token_cfg.iss` | AS JWT issuer，通常为 `oeas` |
| `enable_active_attestation` | 是否启用主动证明定时刷新 |
| `app_list[].uuid` | iTrustee 为 TA UUID；virtCCA 为 rim，推荐使用 `auto` |
| `app_list[].ima` | 是否采集并验证 IMA log |
| `app_list[].interval` | 主动证明刷新间隔，单位秒 |
| `app_list[].platform` | 必须与运行平台匹配，推荐显式填写 `itrustee` 或 `virtcca` |

如果环境中存在 HTTP 代理，建议对 AS 地址配置 `NO_PROXY`，避免 AA 访问 AS 时被代理拦截：

```bash
unset http_proxy
unset https_proxy
unset HTTP_PROXY
unset HTTPS_PROXY
export NO_PROXY=127.0.0.1,localhost,<AS_IP>
export no_proxy=127.0.0.1,localhost,<AS_IP>
```

## 4. iTrustee 使用方式

### 4.1 前置条件

iTrustee 侧需要满足：

- 当前主机支持 TrustZone/iTrustee。
- 内核模块中存在 `tzdriver`。
- AA 能链接 iTrustee attester 依赖库。
- AS 已启用 iTrustee verifier。
- AS 已注册对应 TA 的 iTrustee reference。
- 如启用 IMA，还需要注册 IMA reference。

检查平台探测条件：

```bash
grep '^tzdriver' /proc/modules
```

### 4.2 AA 配置

单 TA 示例：

```json
{
  "svr_url": "http://<AS_IP>:8080",
  "token_cfg": {
    "cert": "/etc/attestation/attestation-agent/as_cert.pem",
    "iss": "oeas"
  },
  "protocal": {
    "Http": {
      "protocal": "http"
    }
  },
  "enable_active_attestation": true,
  "app_list": [
    {
      "uuid": "<TA_UUID>",
      "ima": true,
      "interval": 30,
      "platform": "itrustee"
    }
  ]
}
```

多 TA 示例：

```json
{
  "svr_url": "http://<AS_IP>:8080",
  "token_cfg": {
    "cert": "/etc/attestation/attestation-agent/as_cert.pem",
    "iss": "oeas"
  },
  "protocal": {
    "Http": {
      "protocal": "http"
    }
  },
  "enable_active_attestation": true,
  "app_list": [
    {
      "uuid": "<TA_UUID_1>",
      "ima": true,
      "interval": 30,
      "platform": "itrustee"
    },
    {
      "uuid": "<TA_UUID_2>",
      "ima": false,
      "interval": 60,
      "platform": "itrustee"
    }
  ]
}
```

注意：

- iTrustee 平台必须显式配置 `platform: "itrustee"`。
- `uuid` 必须是具体 TA UUID，不支持 `auto`。
- 多个 `app_list` 项不能使用相同 UUID，否则 `/active_token?uuid=...` 会返回冲突错误。

### 4.3 AS reference

iTrustee verifier 会读取 TA 基线文件：

```text
/etc/attestation/attestation-service/verifier/itrustee/itrustee_<TA_UUID>
```

可以通过 AS `/reference` 接口注册，名称必须使用 `itrustee_<TA_UUID>`：

```bash
curl -H "Content-Type:application/json" \
  -X POST \
  -d '{"refs":"{\"itrustee_<TA_UUID>\":\"<TA_BASELINE>\"}"}' \
  http://<AS_IP>:8080/reference
```

`<TA_BASELINE>` 的内容必须与当前 iTrustee verifier `tee_verify_report` 所需基线格式一致，由 TA 构建和部署流程提供。

默认 iTrustee policy 为：

```text
/etc/attestation/attestation-service/policy/default_itrustee.rego
```

如 AS 部署目录中没有默认 policy，需要复制仓库中的默认文件：

```bash
sudo mkdir -p /etc/attestation/attestation-service/policy
sudo cp secGear/service/attestation/attestation-service/policy/src/opa/default_itrustee.rego \
  /etc/attestation/attestation-service/policy/
```

### 4.4 iTrustee IMA reference（可选）

如果 AA 配置中设置 `"ima": true`，AS 会验证 IMA log。

默认 reference 文件：

```text
/etc/attestation/attestation-service/verifier/itrustee/ima/digest_list_file
```

TA-specific reference 文件：

```text
/etc/attestation/attestation-service/verifier/itrustee/ima/<TA_UUID>/digest_list_file
```

也可以通过 `/reference` 注册，名称格式为：

```text
itrustee_ima_<TA_UUID>
```

## 5. virtCCA 使用方式

### 5.1 前置条件

CVM 内需要满足：

- 存在 virtCCA TSI 设备：`/dev/tsi`
- AA 能链接 `libvccaattestation.so`
- AA 能访问 AS 的 `/challenge` 和 `/attestation`
- AS 已配置 virtCCA 证书链、UEFI reference、rim reference 和默认 policy
- 如启用 IMA，还需要 IMA reference 文件

检查：

```bash
ls -l /dev/tsi
ldd ./target/debug/attestation-agent | grep vcca
```

### 5.2 AS 证书链

AS verifier 会读取以下固定路径：

```text
/etc/attestation/attestation-service/verifier/virtcca/Huawei Equipment Root CA.pem
/etc/attestation/attestation-service/verifier/virtcca/Huawei IT Product CA.pem
```

创建目录并放置证书：

```bash
sudo mkdir -p /etc/attestation/attestation-service/verifier/virtcca
sudo cp "Huawei Equipment Root CA.pem" \
  /etc/attestation/attestation-service/verifier/virtcca/
sudo cp "Huawei IT Product CA.pem" \
  /etc/attestation/attestation-service/verifier/virtcca/
```

### 5.3 默认 policy

AS 默认 virtCCA policy 路径：

```text
/etc/attestation/attestation-service/policy/default_vcca.rego
```

复制默认 policy：

```bash
sudo mkdir -p /etc/attestation/attestation-service/policy
sudo cp secGear/service/attestation/attestation-service/policy/src/opa/default_vcca.rego \
  /etc/attestation/attestation-service/policy/
```

默认 policy 会要求 `vcca.cvm.rim` 在 AS reference store 中存在。

### 5.4 UEFI reference

UEFI reference 文件路径：

```text
/etc/attestation/attestation-service/verifier/virtcca/uefi/digest_list_file
```

格式为一行一个允许的 UEFI event digest，纯 hex 字符串：

```text
<GRUB_IMAGE_DIGEST>
<GRUB_CFG_DIGEST>
<KERNEL_DIGEST>
<INITRAMFS_DIGEST>
```

初始化文件：

```bash
sudo mkdir -p /etc/attestation/attestation-service/verifier/virtcca/uefi
sudo touch /etc/attestation/attestation-service/verifier/virtcca/uefi/digest_list_file
sudo chmod 644 /etc/attestation/attestation-service/verifier/virtcca/uefi/digest_list_file
```

如果文件为空，AS 可以读取文件，但 UEFI 事件通常会校验为 `false`。用 `RUST_LOG=debug` 启动 AS 后，重新触发一次证明，日志中会出现类似内容：

```text
'kernel' : '<hex>' not found in UEFI reference set.
'initramfs' : '<hex>' not found in UEFI reference set.
'grub_cfg' : '<hex>' not found in UEFI reference set.
GRUB Image[0] ('<hex>') not found in UEFI reference set.
```

将这些 `<hex>` 逐行写入 `digest_list_file`，再重新触发证明。

日志中的 `RTMR[...]` 和 `UEFI_LOG_HASH[...]` 是聚合度量值，用于校验 UEFI log 和 CVM Token 是否一致，不是 `digest_list_file` 的内容。

### 5.5 rim reference

UEFI reference 只负责启动链事件白名单；默认 OPA policy 还要求 `vcca.cvm.rim` 已注册到 AS reference store。

AA 启动时会打印自动发现的 rim：

```text
Auto-discovered rim: 8b20beea9304b06459e7cd295145d643d8b93cd8f47c8ccabafc6979040dc7c0
```

将该 rim 注册到 AS：

```bash
curl -H "Content-Type:application/json" \
  -X POST \
  -d '{"refs":"{\"vcca.cvm.rim\":\"8b20beea9304b06459e7cd295145d643d8b93cd8f47c8ccabafc6979040dc7c0\"}"}' \
  http://<AS_IP>:8080/reference
```

注册成功后，后续 JWT 中应看到：

```json
"evaluation_reports": {
  "eval_result": true
}
```

如果未注册 rim reference，AS 仍可能返回 JWT，但 `eval_result` 会是 `false`。

### 5.6 virtCCA IMA reference（可选）

如果 AA 配置中设置 `"ima": true`，AS 会验证 IMA log。

默认 reference 文件：

```text
/etc/attestation/attestation-service/verifier/virtcca/ima/digest_list_file
```

app-specific reference 文件：

```text
/etc/attestation/attestation-service/verifier/virtcca/ima/<rim_hex>/digest_list_file
```

其中 `<rim_hex>` 是 CVM Token 中的 `vcca.cvm.rim`。

IMA reference 也可以通过 `/reference` 注册，名称格式为：

```text
virtcca_ima_<rim_hex>
```

### 5.7 AA 配置

推荐使用 rim 自动发现：

```json
{
  "svr_url": "http://<AS_IP>:8080",
  "token_cfg": {
    "cert": "/etc/attestation/attestation-agent/as_cert.pem",
    "iss": "oeas"
  },
  "protocal": {
    "Http": {
      "protocal": "http"
    }
  },
  "enable_active_attestation": true,
  "app_list": [
    {
      "uuid": "auto",
      "ima": false,
      "interval": 30,
      "platform": "virtcca",
      "rim_auto_discover": true
    }
  ]
}
```

如果不使用自动发现，也可以手动写入 rim：

```json
{
  "uuid": "<rim_hex>",
  "ima": false,
  "interval": 30,
  "platform": "virtcca",
  "rim_auto_discover": false
}
```

注意：

- virtCCA 上 `/active_token` 必须携带 `nonce`。
- `uuid=auto` 不能作为 `/active_token` query 参数。
- 如果请求中携带 `uuid=<rim_hex>`，该值必须等于配置文件中原始 `app_list[0].uuid`。
- 如果配置文件中 `uuid` 为 `auto`，则不要在 `/active_token` 请求中携带 `uuid`。

## 6. 启动

### 6.1 启动 AS

```bash
cd secGear/service/attestation/attestation-service
RUST_LOG=info ./target/debug/attestation-service -s <AS_IP>:8080
```

排查问题时可使用 debug 日志：

```bash
RUST_LOG=debug ./target/debug/attestation-service -s <AS_IP>:8080
```

### 6.2 启动 AA

```bash
cd secGear/service/attestation/attestation-agent
RUST_LOG=info ./target/debug/attestation-agent \
  --config /etc/attestation/attestation-agent/attestation-agent.conf
```

调试时：

```bash
RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/attestation-agent \
  --config /etc/attestation/attestation-agent/attestation-agent.conf
```

AA 默认监听：

```text
127.0.0.1:8081
```

如需让 RP 从其他机器访问：

```bash
./target/debug/attestation-agent \
  --config /etc/attestation/attestation-agent/attestation-agent.conf \
  --socketaddr 0.0.0.0:8081
```

生产部署应通过安全组、防火墙或 VPC ACL 限制只有目标 RP 可以访问 AA 端口。

## 7. 验证主动证明是否成功

### 7.1 查看当前 token 状态

```bash
curl -s http://127.0.0.1:8081/current_token | jq
```

成功示例：

```json
{
  "apps": [
    {
      "app_uuid": "<APP_UUID_OR_RIM>",
      "has_token": true,
      "failure_count": 0,
      "is_expired": false,
      "ttl_seconds": 200
    }
  ]
}
```

关键检查项：

- `has_token` 为 `true`
- `failure_count` 为 `0`
- `ttl_seconds` 大于 `0`

### 7.2 iTrustee 获取缓存 JWT

不指定 UUID 时，返回 `app_list` 中第一个 app 的缓存 token：

```bash
curl -s http://127.0.0.1:8081/active_token | jq
```

指定 TA UUID：

```bash
curl -s "http://127.0.0.1:8081/active_token?uuid=<TA_UUID>" | jq
```

成功返回：

```json
{
  "jwt_token": "<jwt>",
  "expires_at": 1780908087,
  "ttl_seconds": 239,
  "cvm_token": null,
  "dev_cert": null,
  "error": null,
  "failure_count": 0
}
```

当前阶段 iTrustee 不支持 `/active_token?nonce=...`，该请求会返回 `501 not_supported`。

### 7.3 virtCCA 获取 nonce 绑定 active token

virtCCA 必须携带 RP nonce：

```bash
NONCE=$(openssl rand -hex 32)
curl -s "http://127.0.0.1:8081/active_token?nonce=${NONCE}" | jq
```

如果配置使用具体 rim，也可以携带 uuid 做配置一致性检查：

```bash
NONCE=$(openssl rand -hex 32)
curl -s "http://127.0.0.1:8081/active_token?uuid=<configured_rim>&nonce=${NONCE}" | jq
```

成功返回：

```json
{
  "jwt_token": "<cached jwt>",
  "expires_at": 1780908087,
  "ttl_seconds": 239,
  "cvm_token": "<standard base64 encoded CVM Token>",
  "dev_cert": "<standard base64 encoded device certificate>",
  "error": null,
  "failure_count": 0
}
```

`cvm_token` 和 `dev_cert` 使用标准 base64 编码，可能包含 `+`、`/`、`=`。

`expires_at` 来自缓存 AS JWT 的 `exp` 字段，是 Unix epoch 秒的绝对时间。AA 缓存的 JWT 未刷新时，多次调用 `/active_token` 可能返回相同的 `expires_at`，这是预期行为。RP 判断 token 是否有效时，应在验证 JWT 签名后检查 JWT 内的 `nbf` 和 `exp`；响应 JSON 中的 `expires_at` 只是便于调用方读取的冗余字段。virtCCA nonce 模式的新鲜度来自实时 `cvm_token` 中 challenge 绑定 RP nonce，不要求 `expires_at` 每次变化。

### 7.4 检查 JWT 评估结果

解码 JWT payload：

```bash
TOKEN=$(curl -s "http://127.0.0.1:8081/active_token?uuid=<TA_UUID>" | jq -r '.jwt_token')
TOKEN="$TOKEN" python3 - <<'PY'
import base64
import json
import os

token = os.environ["TOKEN"]
payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
PY
```

virtCCA 可改用：

```bash
NONCE=$(openssl rand -hex 32)
TOKEN=$(curl -s "http://127.0.0.1:8081/active_token?nonce=${NONCE}" | jq -r '.jwt_token')
```

重点检查：

```json
"evaluation_reports": {
  "eval_result": true
}
```

如果 `eval_result` 为 `false`，常见原因是 reference 缺失或不匹配。

## 8. `/active_token` 接口行为

请求方法：

```text
GET /active_token
GET /active_token?uuid=<uuid>
GET /active_token?nonce=<hex_encoded_nonce>
GET /active_token?uuid=<uuid>&nonce=<hex_encoded_nonce>
```

行为矩阵：

| 当前平台 | 请求 | 行为 |
|----------|------|------|
| iTrustee | `/active_token` | 返回 `app_list[0]` 的缓存 JWT |
| iTrustee | `/active_token?uuid=<TA_UUID>` | 返回指定 TA 的缓存 JWT |
| iTrustee | `/active_token?nonce=...` | 返回 `501 not_supported` |
| virtCCA | `/active_token` | 返回 `400 missing_nonce` |
| virtCCA | `/active_token?nonce=<nonce>` | 返回缓存 JWT、实时 CVM Token、设备证书 |
| virtCCA | `/active_token?uuid=<rim>&nonce=<nonce>` | 先校验 `uuid` 与配置文件原始 `uuid` 一致，再返回 active token |

错误状态码：

| HTTP 状态码 | `error` | 含义 |
|-------------|---------|------|
| 400 | `invalid_nonce` | `nonce` 不是合法 hex 或长度不是 32 字节 |
| 400 | `invalid_uuid` | query 中 `uuid=auto` |
| 400 | `missing_nonce` | virtCCA 请求缺少 `nonce` |
| 400 | `platform_mismatch` | 选中的 app platform 与当前运行平台不匹配 |
| 404 | `app_not_found` | 未找到匹配 app |
| 409 | `ambiguous_app` | 多个 app 使用相同 UUID |
| 501 | `not_supported` | 当前阶段不支持该请求路径 |
| 503 | `no_token_available` | 尚无可用缓存 JWT |
| 503 | `tee_unavailable` | 当前 TEE 不可用或实时 token 生成失败 |

## 9. RP 验证建议

RP 最少应完成以下检查：

1. 使用 AS 公钥证书验证 JWT 签名。
2. 检查 JWT `iss`、`nbf`、`exp`，其中 `exp` 是 Unix epoch 秒的绝对过期时间。
3. 检查 `evaluation_reports.eval_result == true`。
4. 检查 JWT 中的平台标识和 app 标识符合预期。
5. virtCCA nonce 模式下，验证 `cvm_token` 中 challenge 前 32 字节等于 RP 发出的 nonce。
6. virtCCA nonce 模式下，验证 `cvm_token` 和 `dev_cert` 的证书链与签名。

当前阶段 virtCCA `/active_token?nonce=...` 用于证明“当前响应方能实时从本机 TSI 生成绑定 RP nonce 的 CVM Token”。如果攻击者可以实时访问其他 CVM 的 AA 端口，仍可能发生转发攻击。因此应配合网络隔离使用。

## 10. 常见问题

### 10.1 `Rim auto-discovery failed`

常见原因：

- `/dev/tsi` 不存在
- `libvccaattestation.so` 不可用
- AA 未使用 `virtcca-attester` feature 构建
- CVM Token 格式解析失败

### 10.2 AA 访问 AS 返回 504

如果日志中出现代理：

```text
proxy(...) intercepts 'http://<AS_IP>:8080/'
```

应清理代理环境变量或设置 `NO_PROXY`。

### 10.3 AS 返回 `No such file or directory`

virtCCA 优先检查：

```bash
ls -l \
  "/etc/attestation/attestation-service/verifier/virtcca/Huawei IT Product CA.pem" \
  "/etc/attestation/attestation-service/verifier/virtcca/Huawei Equipment Root CA.pem" \
  /etc/attestation/attestation-service/verifier/virtcca/uefi/digest_list_file
```

iTrustee 优先检查：

```bash
ls -l \
  /etc/attestation/attestation-service/verifier/itrustee/itrustee_<TA_UUID> \
  /etc/attestation/attestation-service/policy/default_itrustee.rego
```

### 10.4 `/active_token` 返回 `no_token_available`

说明 AA 尚未缓存有效 JWT。先检查：

```bash
curl -s http://127.0.0.1:8081/current_token | jq
```

需要等待主动证明刷新成功，或查看 AA 日志中的失败原因。

### 10.5 `/active_token` 返回 `platform_mismatch`

说明配置中的 `app_list[].platform` 与当前硬件平台不一致。iTrustee 必须配置为 `"itrustee"`，virtCCA 推荐配置为 `"virtcca"`。

### 10.6 `evaluation_reports.eval_result=false`

接口可能仍返回 JWT，但 RP 不应视为通过。按平台检查：

- iTrustee：`itrustee_<TA_UUID>` reference 是否存在且匹配；启用 IMA 时 IMA reference 是否匹配。
- virtCCA：`vcca.cvm.rim` reference 是否注册；UEFI `digest_list_file` 是否包含当前 CVM 的启动事件 digest；启用 IMA 时 IMA reference 是否匹配。

## 11. 安全边界和当前限制

1. virtCCA rim 是镜像级标识，同镜像 CVM 的 rim 相同。该限制是当前阶段可接受的部署约束。
2. `/active_token` 暴露面依赖网络隔离控制。不要把 AA 端口暴露给不受信实例。
3. `/active_token` 有基础限流，但不能替代网络访问控制。
4. iTrustee 当前只支持返回缓存 AS JWT，不支持 RP nonce 绑定 active token。
5. virtCCA 当前要求 `/active_token` 必须携带 nonce。
6. `eval_result=false` 的 JWT 不应被 RP 视为可信通过结果。
