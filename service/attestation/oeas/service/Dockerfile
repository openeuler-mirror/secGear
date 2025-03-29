ARG VERSION
ARG SECGEAR_REPO_URL
FROM openeuler/openeuler:${VERSION}

ARG SECGEAR_REPO_URL
WORKDIR /etc/attestation

RUN dnf install -y python3-pip supervisor 'dnf-command(config-manager)' openssl shadow && \
    dnf config-manager --add-repo ${SECGEAR_REPO_URL} && \
    dnf install -y secGear-as virtCCA_sdk virtCCA_sdk-devel itrustee_sdk itrustee_sdk-devel rust cargo rust-packaging kunpengsecl-attester && \
    pip3 config set global.index-url https://mirrors.huaweicloud.com/repository/pypi/simple && \
    pip3 install pyjwt requests flask && \
    dnf clean all && \
    cp /etc/yum.repos.d/openEuler.repo ./ && \
    rm -rf /etc/yum.repos.d/* && \
    mv openEuler.repo /etc/yum.repos.d/openEuler.repo && \
    rm -rf /var/cache/yum/* && \
    rm -rf /root/.cache/pip/*

COPY ./oeas_authentication.py ./
COPY ./supervisord.conf ./
COPY ./Huawei* /etc/attestation/attestation-service/verifier/virtcca/

RUN mkdir -p /etc/attestation/attestation-service/token && \
    cd /etc/attestation/attestation-service/token && \
    openssl genrsa -out private.pem 2048 && \
    openssl req -new -key private.pem -out server.csr \
    -subj "/C=CN/ST=Zhejiang/L=Hangzhou/O=openEuler/CN=oeas" && \
    openssl x509 -req -in server.csr -out as_cert.pem -signkey private.pem -days 3650

RUN groupadd -g 1000 oeas && \
    useradd -m -u 1000 -g 1000 oeas && \
    mkdir -p /etc/attestation/logs && \
    chown -R oeas:oeas /etc/attestation && \
    chmod 755 /etc/attestation

# 最终切换用户
USER oeas
WORKDIR /etc/attestation

CMD ["supervisord", "-c", "/etc/attestation/supervisord.conf"]