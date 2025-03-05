FROM rust as attestation-service-builder
WORKDIR /app
COPY --from=data . .

# 国内构建慢可取消注释此处COPY
# COPY ./config attestation-service/.cargo/

RUN cd attestation-service/ && \
    sed -i 's/^default\s*=\s*\[.*\]/default = []/' verifier/Cargo.toml && \
    cargo build --release

# 第二阶段：运行时
# 镜像地址：https://repo.openeuler.org/openEuler-22.03-LTS-SP4/docker_img/x86_64/
FROM openeuler-22.03-lts-sp4


WORKDIR /opt/oeas/

# 复制构建产物
COPY --from=attestation-service-builder /app/attestation-service/target/release/attestation-service ./
COPY ./AuthenticationModule.py ./
COPY ./supervisord.conf ./

RUN echo -e "[openEuler-everything]\nname=openEuler-everything\nbaseurl=http://repo.huaweicloud.com/openeuler/openEuler-22.03-LTS-SP4/everything/aarch64/\nenabled=1\ngpgcheck=0\ngpgkey=http://repo.huaweicloud.com/openeuler/openEuler-22.03-LTS-SP4/everything/aarch64/RPM-GPG-KEY-openEuler\n\n[openEuler-EPOL]\nname=openEuler-epol\nbaseurl=http://repo.huaweicloud.com/openeuler/openEuler-22.03-LTS-SP4/EPOL/main/aarch64/\nenabled=1\ngpgcheck=0\n\n[openEuler-update]\nname=openEuler-update\nbaseurl=http://repo.huaweicloud.com/openeuler/openEuler-22.03-LTS-SP4/update/aarch64/\nenabled=1\ngpgcheck=0" > /etc/yum.repos.d/openEuler.repo && \
    yum install -y python3-pip supervisor && \
    pip3 config set global.index-url https://mirrors.huaweicloud.com/repository/pypi/simple && \
    pip3 install pyjwt requests flask && \
    dnf clean all && \
    rm -rf /var/cache/yum/* && \
    rm -rf /root/.cache/pip/*

# 创建日志目录并设置权限（在RUN指令中添加）
RUN useradd -m oeas && \
    mkdir -p /opt/oeas/logs && \
    chown -R oeas:oeas /opt/oeas && \
    chmod 755 /opt/oeas && \
    chmod +x /opt/oeas/attestation-service

# 最终切换用户
USER oeas

CMD ["supervisord", "-c", "/opt/oeas/supervisord.conf"]
