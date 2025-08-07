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

function minimal() {
    path=$1
    perm=$2
    if [ ! -e "$path" ]; then
        return 0
    fi

    real_perm=$(stat -c '%04a' "${path}")
    if [ "${perm}" != ${real_perm} ]; then
        echo "Change ${path} file permission to ${perm}"
        chmod ${path} ${perm}
    fi
}

minimal "/etc/passwd" 0644
minimal "/etc/group" 0644
minimal "/etc/shadow" 0000
minimal "/etc/gshadow" 0000
minimal "/etc/passwd" 0644
minimal "/etc/shadow" 0000
minimal "/etc/group" 0644
minimal "/etc/gshadow" 0000
minimal "/etc/ssh/sshd_config" 0600
minimal "/etc/sudoers" 0440