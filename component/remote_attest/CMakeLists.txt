# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

ADD_SUBDIRECTORY(ra_report)

file(GLOB RA_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/sg_report_st.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/ra_report/sg_ra_report.h)

install(FILES ${RA_HEADERS}
        DESTINATION /usr/include/secGear
        PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
