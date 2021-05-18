#!/usr/bin/env python
# coding:utf-8
#----------------------------------------------------------------------------
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# iTrustee licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# Description: tools for generating a trusted application load image
# Author: Li mingjuan
# Create: 2020-10-27
#----------------------------------------------------------------------------

import struct
import os
import hashlib
import subprocess

HASH256 = 0
HASH512 = 1

def gen_hash(hash_type, in_file_path, out_file_path):
    in_file_size = os.path.getsize(in_file_path)
    # Initialize a SHA256 object from the Python hash library
    if int(hash_type) == HASH256:
        hash_op = hashlib.sha256()
    elif int(hash_type) == HASH512:
        hash_op = hashlib.sha512()
    # Set the input buffer and return the output digest
    with open(in_file_path, 'rb') as in_file:
        hash_op.update(in_file.read(in_file_size))

    #-----hash file used for ras sign---
    with open(out_file_path, 'wb') as hash_fp:
        # fixed hash prefix value
        hash_fp.write(struct.pack('B'*19, 0x30, 0x31, 0x30, 0x0d, 0x06, \
            0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, \
            0x05, 0x00, 0x04, 0x20))
        hash_fp.write(hash_op.digest())
    return

def gen_ta_signature(cfg, hash_file_path, out_file_path):
    cmd = "openssl rsautl -sign -inkey {} -in {} -out {}".\
            format(cfg.sign_key, hash_file_path, out_file_path)
    try:
        subprocess.check_output(cmd.split(), shell=False)
    except Exception:
        print("sign operation failed")
        raise RuntimeError
    return

