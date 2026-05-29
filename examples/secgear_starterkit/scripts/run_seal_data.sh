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
BUILD_DIR="${PROJECT_ROOT}/examples/seal_data/build"
HOST_BIN="${BUILD_DIR}/secgear_seal_data_host"

echo "[1/3] check build outputs"
if [[ ! -x "${HOST_BIN}" ]]; then
  echo "Host binary not found: ${HOST_BIN}"
  echo "Please build examples/seal_data first."
  exit 1
fi

if [[ ! -f "${BUILD_DIR}/enclave.signed.so" ]]; then
  echo "Signed enclave not found: ${BUILD_DIR}/enclave.signed.so"
  echo "Please build examples/seal_data first."
  exit 1
fi

echo "[2/3] check SGX runtime environment"
if [[ ! -e /dev/sgx_enclave && ! -e /dev/sgx_provision && ! -e /dev/isgx ]]; then
  echo "No SGX device found on this machine."
  echo "Runtime validation requires SGX-enabled hardware."
  exit 2
fi

echo "[3/3] run seal_data example"
cd "${BUILD_DIR}"
LD_LIBRARY_PATH=/usr/lib64:/opt/intel/sgxsdk/lib64 ./secgear_seal_data_host

ARCH="$(uname -m)"
if [ "${ARCH}" != "x86_64" ]; then
    echo "secgear-starterkit SGX smoke tests require x86_64. Skip on ${ARCH}."
    exit 0
fi
