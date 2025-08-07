#!/bin/sh
#######################################################################################
#
# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
# security-tool licensed under the Mulan PSL v1.
# You can use this software according to the terms and conditions of the Mulan PSL v1.
# You may obtain a copy of Mulan PSL v1 at:
#     http://license.coscl.org.cn/MulanPSL
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v1 for more details.
# Description: Configure dim.
#
#######################################################################################

#=============================================================================
# Function Name: fn_dim_tool_main
# Description  : dim tool main function
# Returns      : 0 on success, otherwise on fail
#=============================================================================
function fn_dim_tool_main()
{
    # operator must be root
    if [ `id -u` -ne 0 ]; then
        echo "You must be logged in as root."
        exit 1
    fi

    # init kernel baseline
    echo "Initializing DIM kernel baseline..."
    mkdir -p /etc/dim/digest_list

    if [ ! -f /boot/vmlinuz-$(uname -r) ]; then
        echo "Kernel image /boot/vmlinuz-$(uname -r) does not exist." >&2
        echo "You have to measure your kernel manually." >&2
        return 1
    fi

    dim_gen_baseline -k "$(uname -r)" -o /etc/dim/digest_list/kernel.hash /boot/vmlinuz-$(uname -r)

    if [ ! -f /etc/dim/policy ]; then
        echo "Creating DIM policy at /etc/dim/policy."
        echo "measure obj=KERNEL_TEXT" > /etc/dim/policy
    fi

    # add dim kernel measurement to policy
    if ! grep -q "measure obj=KERNEL_TEXT" /etc/dim/policy; then
        echo "" >> /etc/dim/policy
        echo "measure obj=KERNEL_TEXT" >> /etc/dim/policy
        echo "Added kernel measurement (measure obj=KERNEL_TEXT) to DIM policy."
    else
        echo "Kernel measurement already exists in DIM policy."
    fi

    # install dim kernel module
    echo "Installing dim kernel module..."
    if ! lsmod | grep -q dim_core; then
        if ! modprobe dim_core measure_interval=1; then
            echo "Failed to install dim_core module." >&2
            return 1
        fi
    fi

    if ! lsmod | grep -q dim_monitor; then
        if ! modprobe dim_monitor; then
            echo "Failed to install dim module." >&2
            return 1
        fi
    fi

    # initialize dim baseline
    echo 1 > /sys/kernel/security/dim/baseline_init

    local result="$(grep "$(uname -r)" /sys/kernel/security/dim/ascii_runtime_measurements | tail -n 1)"
    # result not empty
    if [ -z "$result" ]; then
        echo "Failed to initialize DIM baseline for kernel" >&2
        return 1
    else
        echo "DIM kernel baseline initialized:"
        echo "$result"
    fi
}

fn_dim_tool_main