#!/usr/bin/bash
set -e

private_path="/etc/attestation/attestation-service/token/private.pem"
cert_path="/etc/attestation/attestation-service/token/as_cert.pem"
csr_path="/etc/attestation/attestation-service/token/server.csr"
conf_path="/etc/attestation/conf/oeas.toml"

# 挂载文件存放路径
set_path="/vault/secrets"
private_set_path="${set_path}/private.pem"
cert_set_path="${set_path}/as_cert.pem"
conf_set_path="${set_path}/oeas.toml"

# 如果启动时使用http，可将supervisord-https.conf改为supervisord.conf
supervisord_conf_path="/etc/attestation/conf/supervisord-https.conf"

# 文件复制
yes | cp -r /opt/attestation/* /etc/attestation/
if [[ -e $private_path ]];then
    chmod 600 $private_path
fi
if [[ -e $cert_path ]];then
    chmod 644 $cert_path
fi

# 检查配置文件
if [ -e $conf_set_path ]; then
    echo "Copying oeas.toml..."
    yes | cp -r $conf_set_path $conf_path
fi

# 检查证书文件
if [ -e $private_set_path ] && [ -e $cert_set_path ]; then
    echo "Copying cert..."
    yes | cp -r $private_set_path $private_path
    yes | cp -r $cert_set_path $cert_path
    
    supervisord -c $supervisord_conf_path &
else
    echo "Generate cert..."
    openssl genrsa -out $private_path 2048
    openssl req -new -key $private_path -out $csr_path \
        -subj "/C=CN/ST=Zhejiang/L=Hangzhou/O=openEuler/CN=oeas"
    openssl x509 -req -in $csr_path -out $cert_path -signkey $private_path -days 3650

    supervisord -c $supervisord_conf_path &
fi

# 获取 supervisord 的 PID
SUPERVISOR_PID=$!

# 等待 supervisord 启动完成
sleep 5

# 清理敏感文件
echo "Cleaning up sensitive files..."
rm -rf $set_path/*
rm -rf $private_path
chmod 644 $cert_path

# 等待 supervisord 主进程结束
if [ -n "$SUPERVISOR_PID" ]; then
    echo "Waiting for supervisord"
    wait $SUPERVISOR_PID
else
    echo "Error: SUPERVISOR_PID is empty!"
    exit 1
fi