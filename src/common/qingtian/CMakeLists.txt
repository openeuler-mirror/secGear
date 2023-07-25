# Copyright (c) IPADS@SJTU 2021. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#set(CMAKE_C_FLAGS "${COMMON_C_FLAGS} -fPIC")
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")

#add_library(${target_lib} SHARED ${SOURCE_FILES})

#target_include_directories(${target_lib} PRIVATE
#    ${LOCAL_ROOT_PATH}/inc/common/qingtian )

#install(TARGETS  ${target_lib}
#        ARCHIVE
#        DESTINATION ${LIBRARY_INSTALL}
#        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)