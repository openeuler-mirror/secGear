#!/usr/bin/bash
set -e

# 文件复制
yes | cp -r /opt/attestation/* /etc/attestation/

# 检查配置文件
if [ -e "/vault/secrets/oeas.toml" ]; then
    echo "Copying oeas.toml..."
    yes | cp -r /vault/secrets/oeas.toml /etc/attestation/conf/oeas.toml
fi

# 检查证书文件
if [ -e "/vault/secrets/private.pem" ] && [ -e "/vault/secrets/as_cert.pem" ]; then
    echo "Copying cert..."
    yes | cp -r /vault/secrets/private.pem /etc/attestation/attestation-service/token/private.pem
    yes | cp -r /vault/secrets/as_cert.pem /etc/attestation/attestation-service/token/as_cert.pem
    supervisord -c /etc/attestation/conf/supervisord-https.conf &
else
    echo "Generate cert..."
    cd /etc/attestation/attestation-service/token
    openssl genrsa -out private.pem 2048
    openssl req -new -key private.pem -out server.csr \
        -subj "/C=CN/ST=Zhejiang/L=Hangzhou/O=openEuler/CN=oeas"
    openssl x509 -req -in server.csr -out as_cert.pem -signkey private.pem -days 3650
    supervisord -c /etc/attestation/conf/supervisord-https.conf &
fi

# 获取 supervisord 的 PID
SUPERVISOR_PID=$!

# 等待 supervisord 启动完成
sleep 5

# 清理敏感文件
#echo "Cleaning up sensitive files..."
#rm -rf /vault/secrets/*
#rm -rf /etc/attestation/attestation-service/token/private.pem

# 等待 supervisord 主进程结束
if [ -n "$SUPERVISOR_PID" ]; then
    echo "Waiting for supervisord"
    wait $SUPERVISOR_PID
else
    echo "Error: SUPERVISOR_PID is empty!"
    exit 1
fi