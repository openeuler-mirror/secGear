# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

include(ExternalProject)

project(CodeGen C)

find_program(DUNE dune)

if(NOT DUNE) 
	message(FATAL_ERROR "Please check your dune installation")
endif()

set(code codegen)

ExternalProject_Add(codegen
		SOURCE_DIR ${LOCAL_ROOT_PATH}/tools/codegener
		CONFIGURE_COMMAND ""
		BUILD_COMMAND  dune build
		BUILD_IN_SOURCE	TRUE
		INSTALL_COMMAND mv ${CMAKE_CURRENT_SOURCE_DIR}/_build/default/main.exe ${LOCAL_ROOT_PATH}/bin/${code}
)
