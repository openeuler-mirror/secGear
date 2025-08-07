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

GRUB_CFG="/boot/efi/EFI/openEuler/grub.cfg"

if ! grep -q 'module.sig_enforce' /proc/cmdline; then
    if [ ! -f "${GRUB_CFG}" ]; then
        echo "Cannot find ${GRUB_CFG}."
        exit 1
    fi

    sed -i '/linuxefi/s/$/ module.sig_enforce/' "${GRUB_CFG}"
    echo "added module.sig_enforce to ${GRUB_CFG}."
    echo "Please reboot the system to apply the changes."
else
    echo "module.sig_enforce is already enabled."
fi