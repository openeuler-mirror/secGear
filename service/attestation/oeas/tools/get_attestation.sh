#!/bin/bash

# 默认配置
oeas_url=""
oeas_default_url=https://www.openeuler.org/api/v1/oeas
aa_url=http://127.0.0.1:8081

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
    echo "  -s, --as <oeas_url>             (可选)设置OEAS在线服务URL (默认: $oeas_default_url)"
    echo "  -a, --aa <aa_url>               (可选)设置secGear Attestation Agent应用URL (默认: $aa_url)"
    echo "  -h, --help                      显示此帮助信息并退出"
    exit 0
}


# 检查必要参数是否已设置
check_required_params() {
    if [[ -z "$openeuler_token" ]]; then
        echo "错误：缺少必要的参数。请指定 -t/--token。请使用 --help 参数查看详情使用方式。"
        usage
    fi
}


# 设置Attestation Agent的配置文件
set_aa_conf() {
    echo "正在更新 attestation-agent.conf 文件..."

    # 定义配置文件路径
    local conf_file="/etc/attestation/attestation-agent/attestation-agent.conf"

    # 检测 oeas_url 是 http 还是 https
    if [[ "$oeas_url" == https://* ]]; then
        local protocol="https"
    elif [[ "$oeas_url" == http://* ]]; then
        local protocol="http"
    else
        echo "错误：oeas_url 格式不正确，必须以 http:// 或 https:// 开头。"
        return 1
    fi

    # 创建临时文件以构建配置内容
    local temp_file=$(mktemp)

    cat <<EOF > "$temp_file"
{
    "svr_url": "$oeas_url",
    "token_cfg": {
        "cert": "/etc/attestation/attestation-agent/as_cert.pem",
        "iss": "oeas"
    },
    "protocal": {
        "Http": {
            "protocal":"$protocol"
        }
    }
}
EOF

    # 将临时文件移动到目标配置文件路径
    if mv "$temp_file" "$conf_file"; then
        echo "成功更新 $conf_file 文件。"
    else
        echo "错误：无法更新 $conf_file 文件，请检查权限。"
        rm -f "$temp_file"
        return 1
    fi
}

update_certificates_and_config() {
    mkdir -p /etc/attestation/attestation-agent/

    echo "正在更新 as_cert.pem 文件..."

    # 使用 curl 下载证书，并捕获 HTTP 状态码
    http_status=$(curl -L -k -X GET -H "token: ${openeuler_token}" \
                  -o /etc/attestation/attestation-agent/as_cert.pem \
                  -w "%{http_code}" \
                  "${oeas_url}/cert")

    # 检查 HTTP 状态码是否为 200
    if [[ "$http_status" -ne 200 ]]; then
        echo "证书更新失败，HTTP 状态码：$http_status，请检查网络连接或 token 是否有效。"
        exit 1
    fi

    set_aa_conf

    echo "配置文件和证书更新成功！"
    echo "请重新启动 Attestation Agent 服务。"
    exit 0
}

# 获取 OEAS 挑战值
get_challenge() {
    echo "获取 oeas 挑战值..."
    challenge=$(curl -L -k -c cookie -X GET "${oeas_url}/challenge" | tr -d '"')
    cookie=$(cat cookie | grep oeas-session-id | awk '{print $7}')
    if [[ -z "$challenge" || -z "$cookie" ]]; then
        echo "无法获取挑战值或会话ID，请检查 OEAS 服务是否可用。"
        exit 1
    fi
}

# 获取 AA Evidence 证明值
get_evidence() {
    echo "获取 AA Evidence 证明值..."
    evi_req=$(printf "{\"challenge\":\"%s\",\"uuid\":\"${oeas_uuid}\"}" "${challenge}")
    evi=$(curl -L -k -X GET -d "${evi_req}" \
          -H "Content-Type: application/json" \
          "${aa_url}/evidence")
    evi_base64=$(echo "$evi" | base64 | tr -d '\n' | tr -d '=')
    if [[ -z "$evi_base64" ]]; then
        echo "无法获取 Evidence，请检查 Attestation Agent 服务是否可用。"
        exit 1
    fi
}

# 获取 OEAS AS Token
get_as_token() {
    echo "获取 oeas as_token..."
    cookie_op=$(printf "oeas-session-id=%s" "$cookie")
    as_token=$(curl -L -k -X GET --cookie "${cookie_op}" \
               -H "Expect: " \
               -H "token: ${openeuler_token}"  \
               -F "challenge=${challenge}"  \
               -F "evidence=${evi_base64}" \
               -F "policy_name=${policy}" \
               "${oeas_url}/attestation")
    if [[ -z "$as_token" ]]; then
        echo "无法获取 AS Token，请检查 OEAS 服务或输入参数是否正确。"
        exit 1
    fi
    echo "as_token: ${as_token}"
}

# 查询资源内容
query_resource_content() {
    if [[ -n "$resource_name" ]]; then
        echo "查询资源内容..."
        resource_content=$(curl -L -k -X GET -H "token: ${openeuler_token}" \
                           -H "Authorization: Bearer ${as_token}" \
                           "${oeas_url}/resource/storage?resource_name=${resource_name}")
        echo "resource_content: ${resource_content}"
    fi
}

# 主函数
main() {
    # 检查是否请求帮助
    if [[ "$#" -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        usage
    fi

    # 解析命令行参数
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -t|--token) openeuler_token="$2"; shift 2 ;;
            -r|--resource) resource_name="$2"; shift 2 ;;
            -p|--policy) policy="$2"; shift 2 ;;
            -u|--uuid) oeas_uuid="$2"; shift 2 ;;
            -c|--cert-update) update_cert=true; shift ;;
            -s|--as) oeas_url="$2"; shift 2 ;;
            -a|--aa) aa_url="$2"; shift 2 ;;
            *) echo "未知参数: $1"; usage ;;
        esac
    done

    if [[ -z "$oeas_url" ]]; then
        oeas_url=$oeas_default_url
    fi 

    # 检查必要参数
    check_required_params

    # 如果传入了 -c 参数，则更新配置文件和证书文件
    if [[ "$update_cert" == true ]]; then
        update_certificates_and_config
    fi

    # 获取挑战值
    get_challenge

    # 获取 Evidence 证明值
    get_evidence

    # 获取 AS Token
    get_as_token

    # 查询资源内容（如果有资源名称）
    query_resource_content
}

# 执行主函数
main "$@"