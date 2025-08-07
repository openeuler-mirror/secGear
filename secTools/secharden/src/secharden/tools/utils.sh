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

# Function to set sysctl configuration
# Arguments:
#   $1: Configuration option (e.g., "net.ipv4.ip_forward")
#   $2: Value to set for the configuration option (e.g., "0")
function set_sysctl() {
    local conf=$1
    local value=$2
    local sysctl_conf_path="/etc/sysctl.conf"

    if grep -q "^${conf}" ${sysctl_conf_path} > /dev/null; then
        sed -i "s/^${conf}.*/${conf} = ${value}/" ${sysctl_conf_path}
        echo "Updated ${conf} to ${value} in ${sysctl_conf_path}"
    else
        echo "${conf} = ${value}" >> ${sysctl_conf_path}
        echo "Added ${conf} with value ${value} to ${sysctl_conf_path}"
    fi

    sysctl -p ${sysctl_conf_path} --quiet
}

# Function to set SSH configuration
# Arguments:
#   $1: Configuration option (e.g., "PermitRootLogin")
#   $2: Value to set for the configuration option (e.g., "no")
# Returns:
#   0 on success, 1 on failure
function set_ssh() {
    local conf=$1
    local value=$2
    local sshd_conf_path="/etc/ssh/sshd_config"

    if grep -q "^${conf}\s*" "${sshd_conf_path}"; then
        sed -i "s/^${conf}.*/${conf} ${value}/" ${sshd_conf_path}
        echo "Updated ${conf} to ${value} in ${sshd_conf_path}"
    else
        echo "${conf} ${value}" >> "${sshd_conf_path}"
        echo "Added ${conf} with value ${value} to ${sshd_conf_path}"
    fi
}