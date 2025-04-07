#!/usr/bin/bash
set -e

VERSION="24.09"
VERSION_UPPER=$(echo "$VERSION" | tr '[:lower:]' '[:upper:]')
RELEASE="openEuler-${VERSION_UPPER}"

ARCH=$(uname -m)
OPENEULER_DOCKER_URL="https://repo.openeuler.org/${RELEASE}/docker_img/${ARCH}"
DOCKER_TAR="openEuler-docker.${ARCH}.tar.xz"
IMAGE_NAME="openeuler-${VERSION}"
CONTAINER_NAME="oeas"

DATA_DIR=$(readlink -f "$(dirname "$(dirname "$PWD")")")
SECGEAR_REPO_URL="http://121.36.84.172/dailybuild/EBS-openEuler-25.03/rc6_openeuler-2025-03-26-10-07-43/everything/${ARCH}/"

echo "正在获取镜像 openeuler 镜像"
# 检查本地是否已有镜像
if [ -z "$(docker images -q "openeuler/openeuler:${VERSION}")" ]; then
  echo "本地未找到镜像，开始下载镜像文件: ${OPENEULER_DOCKER_URL}/${DOCKER_TAR}"
  
  # 尝试下载镜像文件
  if ! curl -O "${OPENEULER_DOCKER_URL}/${DOCKER_TAR}"; then
    echo "下载镜像文件失败，尝试使用 docker pull 拉取镜像..."
    
    # 尝试使用 docker pull 拉取镜像
    if ! docker pull "$IMAGE_NAME"; then
      echo "ERROR: 下载和拉取镜像均失败，请检查网络或镜像名称是否正确。"
      exit 1
    fi
  else
    # 如果下载成功，加载镜像
    echo "镜像文件下载成功，开始加载镜像..."
    if ! docker load -i "${DOCKER_TAR}"; then
      echo "ERROR: 加载镜像失败，请检查文件是否完整。"
      exit 1
    fi
    
    # 给镜像打标签
    docker tag "$IMAGE_NAME" "openeuler/openeuler:${VERSION}"
  fi
else
  echo "本地已存在镜像: openeuler/openeuler:${VERSION}"
fi

echo "openeuler 镜像加载完成，正在构建镜像"

DOCKER_BUILDKIT=1 docker build --build-arg BASE_IMAGE=openeuler/openeuler:${VERSION} \
    -f Dockerfile_${ARCH} \
    --build-arg SECGEAR_REPO_URL=${SECGEAR_REPO_URL} \
    --build-context data="$DATA_DIR" \
    -t "$CONTAINER_NAME" .

echo "${CONTAINER_NAME} 镜像构建完成，正在启动容器"
if docker ps -a --filter "name=oeas" | grep -q "oeas"; then
    docker rm -f oeas
fi
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