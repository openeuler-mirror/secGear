# get_attestation

## 工具描述

> 脚本运行依赖本地 secGear Attestation Agent。请确认本地 Attestation Agent 是否正常运行

脚本能够自动获取 Attestation Token。如果参数传递了资源名称(-r)，还会输出相应的资源内容。

> 如果使用 itrustee，则需要使用传入 UUID(-u)

## 工具使用

```
Usage: ./get_attestation.sh [options]
获取Attestation Token前，请先使用 -c 参数更新 Attestation Agent 的配置文件和证书文件
脚本运行依赖本地secGear Attestation Agent。请确认本地Attestation Agent是否正常运行
Options:
  -t, --token <openeuler_token>   设置 openeuler 私人令牌
  -u, --uuid <uuid>               (可选)设置UUID，使用itrustee则必须传入UUID
  -r, --resource <resource_name>  (可选)设置资源名称 (未使用参数则不会进行资源查询)
  -p, --policy <policy>           (可选)设置策略 (默认使用OEAS策略)
  -c, --cert-update               (可选)更新Attestation Agent的配置文件和证书文件，更新完需手动重启AA
  -s, --as <oeas_url>             (可选)设置OEAS在线服务URL (默认: http://127.0.0.1:8081)
  -a, --aa <aa_url>               (可选)设置secGear Attestation Agent应用URL (默认: https://www.openeuler.org/api/v1/oeas)
  -h, --help                      显示此帮助信息并退出

```

> --policy 可以传递多个策略，传递 a、b、c、d 四种策略如：
>
> --policy “a,b,c,d”

## 示例

### 更新证书

> 更新证书后请手动重启 Attestation Agent

```
openeuler_token=xxxxxxxxxxxxxxxxx
./get_attestation.sh -t $openeuler_token -c
```

### 获取 AS Token

```
openeuler_token=xxxxxxxxxxxxxxxxx
./get_attestation.sh -t $openeuler_token
```

### 获取资源内容

```
openeuler_token=xxxxxxxxxxxxxxxxx
resource_name=resource_name
./get_attestation.sh -t $openeuler_token -r $resource_name
```
