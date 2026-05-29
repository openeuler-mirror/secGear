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
GENERATED_ROOT="${PROJECT_ROOT}/generated"
PROJECT_NAME="ci_demo_app"
TARGET_DIR="${GENERATED_ROOT}/${PROJECT_NAME}"

echo "[1/4] clean old generated project"
rm -rf "${TARGET_DIR}"

echo "[2/4] generate new project"
cd "${PROJECT_ROOT}"
./scripts/init.sh "${PROJECT_NAME}"

echo "[3/4] build generated project"
cd "${TARGET_DIR}"
mkdir -p build
cd build
cmake ..
make -j2

echo "[4/4] verify outputs"
test -x "${TARGET_DIR}/build/secgear_${PROJECT_NAME}_host"
test -f "${TARGET_DIR}/build/enclave/libenclave.so"
test -f "${TARGET_DIR}/build/enclave.signed.so"

echo "generated project smoke test passed"

ARCH="$(uname -m)"
if [ "${ARCH}" != "x86_64" ]; then
    echo "secgear-starterkit SGX smoke tests require x86_64. Skip on ${ARCH}."
    exit 0
fi
