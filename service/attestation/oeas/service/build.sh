#!/usr/bin/bash
set -e

RELEASE="openEuler-22.03-LTS-SP4"
CONTAINER_NAME="oeas"

ARCH=$(uname -m)
DATA_DIR=$(readlink -f "$(dirname "$(dirname "$PWD")")")

DOCKER_TAR="openEuler-docker.aarch64.tar.xz"
OPENEULER_DOCKER_URL="https://repo.openeuler.org/${RELEASE}/docker_img/${ARCH}/"
IMAGE_NAME=$(echo "$RELEASE" | tr '[:upper:]' '[:lower:]')

echo "正在获取镜像 openeuler 镜像"
if [ -z "$(docker images -q "$IMAGE_NAME")" ]; then
  echo "下载镜像文件: ${OPENEULER_DOCKER_URL}/${DOCKER_TAR}"
  wget "${OPENEULER_DOCKER_URL}/${DOCKER_TAR}"
  docker load -i "${DOCKER_TAR}"
fi
echo "openeuler 镜像加载完成，正在拉取 rust 镜像"


if [ -z "$(docker images -q "rust")" ]; then
# 国内镜像源
# docker pull docker.1panelproxy.com/library/rust
# docker tag docker.1panelproxy.com/library/rust rust
  docker pull rust
fi
echo "rust 镜像拉取成功，开始构建 ${CONTAINER_NAME} 镜像"

docker build --build-context data="$DATA_DIR" -t "$CONTAINER_NAME" .
echo "${CONTAINER_NAME} 镜像构建完成，正在启动容器"

docker run -itd --name "$CONTAINER_NAME" -p 80:5000 -p 127.0.0.1:8080:8080 "$CONTAINER_NAME"
echo "容器启动成功"

echo "等待服务启动..."
for i in {1..10}; do
  if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/challenge" | grep -q "200"; then
    echo "服务启动成功"
    break
  else
    echo "尝试第 $i 次，等待服务启动..."
    sleep 5
  fi
done