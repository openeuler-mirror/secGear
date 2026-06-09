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
EXAMPLE_DIR="${PROJECT_ROOT}/examples/seal_data"
BUILD_DIR="${EXAMPLE_DIR}/build"

echo "[1/3] regenerate proxy code"
cd "${EXAMPLE_DIR}"
codegen --sgx \
  --search-path /usr/include/secGear \
  --search-path /opt/intel/sgxsdk/include \
  --search-path . \
  --trusted-dir enclave \
  --untrusted-dir host \
  seal_data.edl

echo "[2/3] configure and build"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake ..
make -j2

echo "[3/3] verify outputs"
test -x "${BUILD_DIR}/secgear_seal_data_host"
test -f "${BUILD_DIR}/enclave/libenclave.so"
test -f "${BUILD_DIR}/enclave.signed.so"

echo "seal_data smoke build test passed"

ARCH="$(uname -m)"
if [ "${ARCH}" != "x86_64" ]; then
    echo "secgear-starterkit SGX smoke tests require x86_64. Skip on ${ARCH}."
    exit 0
fi
