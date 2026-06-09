#!/usr/bin/env bash
# Copyright (c) 2026 secGear contributors.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
# See the Mulan PSL v2 for more details.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <project_name>"
  exit 1
fi

PROJECT_NAME="$1"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR="${PROJECT_ROOT}/templates/basic"
OUTPUT_ROOT="${PROJECT_ROOT}/generated"
TARGET_DIR="${OUTPUT_ROOT}/${PROJECT_NAME}"

mkdir -p "${OUTPUT_ROOT}"

if [[ -e "${TARGET_DIR}" ]]; then
  echo "Target already exists: ${TARGET_DIR}"
  exit 1
fi

echo "[1/6] copy template"
cp -r "${TEMPLATE_DIR}" "${TARGET_DIR}"

echo "[2/6] remove build directory"
rm -rf "${TARGET_DIR}/build"

echo "[3/6] rename edl and generated proxy files"
mv "${TARGET_DIR}/starterkit.edl" "${TARGET_DIR}/${PROJECT_NAME}.edl"
mv "${TARGET_DIR}/host/starterkit_u.c" "${TARGET_DIR}/host/${PROJECT_NAME}_u.c"
mv "${TARGET_DIR}/host/starterkit_u.h" "${TARGET_DIR}/host/${PROJECT_NAME}_u.h"
mv "${TARGET_DIR}/enclave/starterkit_t.c" "${TARGET_DIR}/enclave/${PROJECT_NAME}_t.c"
mv "${TARGET_DIR}/enclave/starterkit_t.h" "${TARGET_DIR}/enclave/${PROJECT_NAME}_t.h"

echo "[4/6] replace template identifiers"
find "${TARGET_DIR}" -type f \
  \( -name '*.c' -o -name '*.h' -o -name '*.txt' -o -name '*.edl' -o -name 'CMakeLists.txt' -o -name '*.xml' -o -name '*.lds' \) \
  -exec sed -i "s/starterkit/${PROJECT_NAME}/g" {} +

echo "[5/6] regenerate proxy code"
cd "${TARGET_DIR}"
codegen --sgx \
  --search-path /usr/include/secGear \
  --search-path /opt/intel/sgxsdk/include \
  --search-path . \
  --trusted-dir enclave \
  --untrusted-dir host \
  "${PROJECT_NAME}.edl"

echo "[6/6] done"
echo "Generated project: ${TARGET_DIR}"
echo "Build it with:"
echo "  cd ${TARGET_DIR}"
echo "  mkdir -p build && cd build"
echo "  cmake .. && make -j2"
