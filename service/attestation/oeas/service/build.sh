#!/usr/bin/bash
set -e

VERSION="22.03-lts-sp4"
VERSION_UPPER=$(echo "$VERSION" | tr '[:lower:]' '[:upper:]')
RELEASE="openEuler-${VERSION_UPPER}"
CONTAINER_NAME="oeas"

ARCH=$(uname -m)
DATA_DIR=$(readlink -f "$(dirname "$(dirname "$PWD")")")

DOCKER_TAR="openEuler-docker.${ARCH}.tar.xz"
OPENEULER_DOCKER_URL="https://repo.openeuler.org/${RELEASE}/docker_img/${ARCH}"
IMAGE_NAME="openeuler-${VERSION}"

echo "正在获取镜像 openeuler 镜像"
if [ -z "$(docker images -q "$IMAGE_NAME")" ]; then
  echo "下载镜像文件: ${OPENEULER_DOCKER_URL}/${DOCKER_TAR}"
  wget "${OPENEULER_DOCKER_URL}/${DOCKER_TAR}"
  docker load -i "${DOCKER_TAR}"
fi
docker tag "$IMAGE_NAME" "openeuler/openeuler:${VERSION}"
echo "openeuler 镜像加载完成，正在拉取 rust 镜像"

if [ -z "$(docker images -q "rust")" ]; then
  docker pull rust
fi
echo "rust 镜像拉取成功，开始构建 ${CONTAINER_NAME} 镜像"

DOCKER_BUILDKIT=1 docker build --build-context data="$DATA_DIR" -t "$CONTAINER_NAME" .
echo "${CONTAINER_NAME} 镜像构建完成，正在启动容器"

mkdir -p /etc/attestation /var/log/attestation
chmod -R 777 /etc/attestation /var/log/attestation
docker run -itd --name "$CONTAINER_NAME" -p 80:5000 -p 127.0.0.1:8080:8080  -v /etc/attestation:/etc/attestation -v /var/log/attestation:/opt/oeas/logs "$CONTAINER_NAME"
echo "容器启动成功"

echo "等待服务启动..."
for i in {1..10}; do
  if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:5000/challenge" | grep -q "200"; then
    echo "服务启动成功"
    break
  else
    echo "尝试第 $i 次，等待服务启动..."
    sleep 5
  fi
done