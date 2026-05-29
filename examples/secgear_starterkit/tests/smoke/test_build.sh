#!/usr/bin/env bash
# Copyright (c) 2026 secGear contributors.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
# See the Mulan PSL v2 for more details.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_SCRIPT="${PROJECT_ROOT}/scripts/build.sh"
BUILD_DIR="${PROJECT_ROOT}/templates/basic/build"

echo "[1/3] run build script"
"${BUILD_SCRIPT}"

echo "[2/3] verify build outputs"
test -x "${BUILD_DIR}/secgear_starterkit_host"
test -f "${BUILD_DIR}/enclave/libenclave.so"
test -f "${BUILD_DIR}/enclave.signed.so"

echo "[3/3] smoke build test passed"

ARCH="$(uname -m)"
if [ "${ARCH}" != "x86_64" ]; then
    echo "secgear-starterkit SGX smoke tests require x86_64. Skip on ${ARCH}."
    exit 0
fi
