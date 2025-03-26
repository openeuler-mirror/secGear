# get_attestation

## 工具描述

> 脚本运行依赖本地secGear Attestation Agent。请确认本地Attestation Agent是否正常运行

脚本能够自动获取OEAS的Attestation Token。如果参数传递了资源名称(-r)，还会输出相应的资源内容。

## 工具使用

```
Usage: ./get_attestation.sh [options]
脚本运行依赖本地secGear Attestation Agent。请确认本地Attestation Agent是否正常运行
Options:
  -t, --token <openeuler_token>   设置 openeuler 私人令牌
  -r, --resource <resource_name>  (可选)设置资源名称 (未使用参数则不会进行资源查询)
  -p, --policy <policy>           (可选)设置策略 (默认使用OEAS策略)
  -u, --url <aa_url>              (可选)设置OEAS在线服务URL (默认: http://127.0.0.1:8081)
  -a, --aa <oeas_url>             (可选)设置secGear Attestation Agent应用URL (默认: https://www.openeuler.org/api/v1/oeas)
  -h, --help                      显示此帮助信息并退出

```

## 示例

```
openeuler_token=xxxxxxxxxxxxxxxxx
resource_name=ab
./get_attestation.sh -t $openeuler_token -r $resource_name
```

