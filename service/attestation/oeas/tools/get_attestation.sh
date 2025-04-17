#!/bin/bash

# 默认配置
oeas_url=https://www.openeuler.org/api/v1/oeas
aa_url=http://127.0.0.1:8081
aa_conf_url=https://gitee.com/openeuler/secGear/raw/master/service/attestation/oeas/service/conf/attestation-agent.conf

# 初始化变量，默认值为空
policy=""
resource_name=""
openeuler_token=""
oeas_uuid=""
update_cert=false

# 使用说明函数
usage() {
    echo "Usage: $0 [options]"
    echo "获取Attestation Token前，请先使用 -c 参数更新 Attestation Agent 的配置文件和证书文件"
    echo "脚本运行依赖本地secGear Attestation Agent。请确认本地Attestation Agent是否正常运行"
    echo "Options:"
    echo "  -t, --token <openeuler_token>   设置 openeuler 私人令牌"
    echo "  -u, --uuid <uuid>               (可选)设置UUID，使用itrustee则必须传入UUID"
    echo "  -r, --resource <resource_name>  (可选)设置资源名称 (未使用参数则不会进行资源查询)"
    echo "  -p, --policy <policy>           (可选)设置策略 (默认使用OEAS策略)"
    echo "  -c, --cert-update               (可选)更新Attestation Agent的配置文件和证书文件，更新完需手动重启AA"
    echo "  -s, --as <oeas_url>             (可选)设置OEAS在线服务URL (默认: $aa_url)"
    echo "  -a, --aa <aa_url>               (可选)设置secGear Attestation Agent应用URL (默认: $oeas_url)"
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
        -t|--token)
            openeuler_token="$2"
            shift 2
            ;;
        -r|--resource)
            resource_name="$2"
            shift 2
            ;;
        -p|--policy)
            oeas_uuid="$2"
            shift 2
            ;;
        -u|--uuid)
            policy="$2"
            shift 2
            ;;
        -c|--cert-update)
            update_cert=true
            cert_url="${oeas_url}/cert"  # 同时更新 cert_url
            shift
            ;;
        -s|--as)
            oeas_url="$2"
            shift 2
            ;;
        -a|--aa)
            aa_url="$2"
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
    echo "错误：缺少必要的参数。请指定 -t/--token。请使用 --help 参数查看详情使用方式。"
    usage
fi

# 如果传入了 -c 参数，则更新配置文件和证书文件
if [[ "$update_cert" == true ]]; then
    mkdir -p /etc/attestation/attestation-agent/
    if [[ -n "$openeuler_token" && -n "$cert_url" ]]; then
        echo "正在更新 as_cert.pem 文件..."
        
        curl -L -k -X GET -H "token: ${openeuler_token}" \
        -o /etc/attestation/attestation-agent/as_cert.pem \
        ${oeas_url}/cert
        curl -L -k -X GET ${aa_conf_url} \
        -o /etc/attestation/attestation-agent/attestation-agent.conf
        
        if [[ $? -eq 0 ]]; then
            echo "配置文件和证书更新成功！"
            echo "请重新启动 Attestation Agent 服务。"
            exit 1
        else
            echo "证书更新失败，请检查网络连接或 token 是否有效。"
            exit 1
        fi
    else
        echo "错误：缺少必要的参数（token 或 cert_url）。"
        exit 1
    fi
fi

echo "获取oeas挑战值"
challenge=$(curl -L -k -c cookie -X GET ${oeas_url}/challenge | tr -d '"')
cookie=$(cat cookie | grep oeas-session-id | awk '{print $7}')

echo "获取aa evidence证明值"
evi_req=$(printf "{\"challenge\":\"%s\",\"uuid\":\"${oeas_uuid}\"}" ${challenge})
evi=$(curl -L -k -X GET -d ${evi_req} \
    -H "Content-Type: application/json" \
    ${aa_url}/evidence)
# echo $evi
evi_base64=$(echo $evi | base64 | tr -d '\n' | tr -d '=')

echo "获取oeas as_token"
cookie_op=$(printf "oeas-session-id=%s" $cookie)
as_token=$(curl -L -k -X GET --cookie ${cookie_op} \
    -H "Expect: " \
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
    curl -L -k -X GET -H "token: ${openeuler_token}" \
        -H "Authorization: Bearer ${as_token}" \
        "${oeas_url}/resource/storage?resource_name=${resource_name}"
fi
echo
echo
