FROM rust as attestation-service-builder
WORKDIR /app
COPY --from=data . .

RUN cd attestation-service/ && \
    sed -i 's/^default\s*=\s*\[.*\]/default = []/' verifier/Cargo.toml && \
    cargo build --release

# 第二阶段：运行时
# 镜像地址：https://repo.openeuler.org/openEuler-22.03-LTS-SP4/docker_img
FROM openeuler/openeuler:22.03-lts-sp4

WORKDIR /opt/oeas/

RUN yum install -y python3-pip supervisor && \
    pip3 config set global.index-url https://mirrors.huaweicloud.com/repository/pypi/simple && \
    pip3 install pyjwt requests flask && \
    dnf clean all && \
    rm -rf /var/cache/yum/* && \
    rm -rf /root/.cache/pip/*

# 复制构建产物
COPY --from=attestation-service-builder /app/attestation-service/target/release/attestation-service ./
COPY ./oeas_authentication.py ./
COPY ./supervisord.conf ./

# 创建日志目录并设置权限（在RUN指令中添加）
RUN groupadd -g 1000 oeas && \
    useradd -m -u 1000 -g 1000 oeas && \
    mkdir -p /opt/oeas/logs && \
    mkdir -p /etc/attestation && \
    chown -R oeas:oeas /opt/oeas && \
    chown -R oeas:oeas /etc/attestation && \
    chmod 755 /opt/oeas && \
    chmod +x /opt/oeas/attestation-service

# 最终切换用户
USER oeas

CMD ["supervisord", "-c", "/opt/oeas/supervisord.conf"]
