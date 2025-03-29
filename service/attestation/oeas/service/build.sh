#!/usr/bin/bash
set -e

# secgear rpm包仓库
SECGEAR_REPO_URL="http://121.36.84.172/dailybuild/EBS-openEuler-25.03/openeuler-2025-03-29-09-24-45/everything/aarch64/"

VERSION="24.03-lts"
VERSION_UPPER=$(echo "$VERSION" | tr '[:lower:]' '[:upper:]')
RELEASE="openEuler-${VERSION_UPPER}"

ARCH=$(uname -m)
OPENEULER_DOCKER_URL="https://repo.openeuler.org/${RELEASE}/docker_img/${ARCH}"
DOCKER_TAR="openEuler-docker.${ARCH}.tar.xz"
IMAGE_NAME="openeuler-${VERSION}"
CONTAINER_NAME="oeas"

echo "正在获取镜像 openeuler 镜像"
if [ -z "$(docker images -q "openeuler/openeuler:${VERSION}")" ]; then
  echo "下载镜像文件: ${OPENEULER_DOCKER_URL}/${DOCKER_TAR}"
  curl -O "${OPENEULER_DOCKER_URL}/${DOCKER_TAR}"
  docker load -i "${DOCKER_TAR}"
fi
docker tag "$IMAGE_NAME" "openeuler/openeuler:${VERSION}"
echo "openeuler 镜像加载完成，正在构建镜像"

DOCKER_BUILDKIT=1 docker build --build-arg VERSION=${VERSION} \
    --build-arg SECGEAR_REPO_URL=${SECGEAR_REPO_URL} -t "$CONTAINER_NAME" .
echo "${CONTAINER_NAME} 镜像构建完成，正在启动容器"

docker volume create attestation_volume
docker run -itd --name "$CONTAINER_NAME" -p 80:5000 -p 8080:8080  \
    -v attestation_volume:/etc/attestation:rw "$CONTAINER_NAME"
echo "容器启动成功"

echo "等待服务启动..."
for i in {1..10}; do
  if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/oeas-api/challenge" | grep -q "200"; then
    echo "服务启动成功"
    break
  else
    echo "尝试第 $i 次，等待服务启动..."
    sleep 5
  fi
done