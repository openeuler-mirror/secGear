#!/usr/bin/env bash
# Copyright (c) 2026 secGear contributors.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
# See the Mulan PSL v2 for more details.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR="${PROJECT_ROOT}/templates/basic"
BUILD_DIR="${TEMPLATE_DIR}/build"

echo "[1/4] enter template directory"
cd "${TEMPLATE_DIR}"

echo "[2/4] regenerate proxy code"
codegen --sgx \
  --search-path /usr/include/secGear \
  --search-path /opt/intel/sgxsdk/include \
  --search-path . \
  --trusted-dir enclave \
  --untrusted-dir host \
  starterkit.edl

echo "[3/4] configure cmake"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake ..

echo "[4/4] build targets"
make -j2

echo
echo "Build finished."
echo "Host binary: ${BUILD_DIR}/secgear_starterkit_host"
echo "Signed enclave: ${BUILD_DIR}/enclave.signed.so"

ARCH="$(uname -m)"
if [ "${ARCH}" != "x86_64" ]; then
    echo "secgear-starterkit SGX smoke tests require x86_64. Skip on ${ARCH}."
    exit 0
fi
