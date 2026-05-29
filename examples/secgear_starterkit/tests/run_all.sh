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

echo "[1/3] run basic template smoke test"
"${PROJECT_ROOT}/tests/smoke/test_build.sh"

echo
echo "[2/3] run seal_data smoke test"
"${PROJECT_ROOT}/tests/smoke/test_seal_data_build.sh"

echo
echo "[3/3] run generated project smoke test"
"${PROJECT_ROOT}/tests/smoke/test_init_generated_project.sh"

echo
echo "All smoke tests passed."

ARCH="$(uname -m)"
if [ "${ARCH}" != "x86_64" ]; then
    echo "secgear-starterkit SGX smoke tests require x86_64. Skip on ${ARCH}."
    exit 0
fi
