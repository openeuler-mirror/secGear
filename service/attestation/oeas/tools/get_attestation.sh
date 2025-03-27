#!/bin/bash

# 默认配置
oeas_url=https://www.openeuler.org/api/v1/oeas
aa_url=http://127.0.0.1:8081

# 初始化变量，默认值为空
policy=""
resource_name=""
openeuler_token=""

# 使用说明函数
usage() {
    echo "Usage: $0 [options]"
    echo "脚本运行依赖本地secGear Attestation Agent。请确认本地Attestation Agent是否正常运行"
    echo "Options:"
    echo "  -t, --token <openeuler_token>   设置 openeuler 私人令牌"
    echo "  -r, --resource <resource_name>  (可选)设置资源名称 (未使用参数则不会进行资源查询)"
    echo "  -p, --policy <policy>           (可选)设置策略 (默认使用OEAS策略)"
    echo "  -u, --url <aa_url>              (可选)设置OEAS在线服务URL (默认: $aa_url)"
    echo "  -a, --aa <oeas_url>             (可选)设置secGear Attestation Agent应用URL (默认: $oeas_url)"
    echo "  -h, --help                      显示此帮助信息并退出"
    exit 0
}

# 检查是否请求帮助
if [[ "$#" -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    usage
fi

# 解析命令行参数
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -r|--resource)
            resource_name="$2"
            shift 2
            ;;
        -p|--policy)
            policy="$2"
            shift 2
            ;;
        -t|--token)
            openeuler_token="$2"
            shift 2
            ;;
        -u|--url)
            aa_url="$2"
            shift 2
            ;;
        -a|--aa)
            oeas_url="$2"
            shift 2
            ;;
        *)
            echo "未知参数: $1"
            usage # 当遇到未知参数时显示使用帮助
            ;;
    esac
done

# 检查必要参数是否已设置
if [[ -z "$openeuler_token" ]]; then
    echo "错误：缺少必要的参数。请指定-token。请使用--help参数查看详情使用方式。"
    usage
fi

echo "获取oeas挑战值"
challenge=$(curl -c cookie -X GET ${oeas_url}/challenge | tr -d '"')
cookie=$(cat cookie | grep oeas-session-id | awk '{print $7}')

echo "获取aa evidence证明值"
evi_req=$(printf "{\"challenge\":\"%s\",\"uuid\":\"xxx\"}" ${challenge})
evi=$(curl -X GET -d ${evi_req} \
    -H "Content-Type: application/json" \
    ${aa_url}/evidence)
# echo $evi
evi_base64=$(echo $evi | base64 | tr -d '\n' | tr -d '=')

echo "获取oeas as_token"
cookie_op=$(printf "oeas-session-id=%s" $cookie)
as_token=$(curl -X GET --cookie ${cookie_op} \
    -H "token: ${openeuler_token}"  \
    -F "challenge=${challenge}"  \
    -F "evidence=${evi_base64}" \
    -F "policy_name=${policy}" \
    ${oeas_url}/attestation)
echo  "as_token:"
echo  "${as_token}"

# 检查必要参数是否已设置
if [[ -n "$resource_name" ]]; then
    echo "resource_content:"
    curl -X GET -H "token: ${openeuler_token}" \
        -H "Authorization: Bearer ${as_token}" \
        "${oeas_url}/resource/storage?resource_name=${resource_name}"
fi
