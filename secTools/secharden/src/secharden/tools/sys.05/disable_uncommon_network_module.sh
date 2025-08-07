#!/bin/bash
## #######################################################################################
#
# Copyright (c) KylinSoft Co., Ltd. 2024. All rights reserved.
# SecureGuardian is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# Description: Security Baseline Check Script for 1.1.14
#
# #######################################################################################

config_path="/etc/modprobe.d/disable_uncommon_network_module.conf"

function setup_conf() {
    conf=$1
    if [ ! -e ${config_path} ]; then
        touch ${config_path}
        echo "Created configuration file: ${config_path}"
    fi

    if ! grep -q "${conf}" "${config_path}"; then
        echo "${conf}" >> "${config_path}"
        echo "Added configuration: ${conf} to ${config_path}"
    else
        echo "Configuration: ${conf} already exists in ${config_path}"
    fi
}

setup_conf "install sctp /bin/true"
setup_conf "install tipc /bin/true"